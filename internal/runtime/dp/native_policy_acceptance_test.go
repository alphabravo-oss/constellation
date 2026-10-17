//go:build integration

package dp

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
)

type nativeMatcherStep struct {
	Name    string          `json:"name"`
	Policy  *WorkloadPolicy `json:"policy,omitempty"`
	Command uint            `json:"command,omitempty"`
	ICMP    *bool           `json:"icmp,omitempty"`
	Lookup  map[string]any  `json:"lookup,omitempty"`
	Prefix  bool            `json:"prefix,omitempty"`
}

func TestNativeRuntimePolicyAcceptance(t *testing.T) {
	image := os.Getenv("CONSTELLATION_NATIVE_POLICY_IMAGE_ID")
	directory := os.Getenv("CONSTELLATION_NATIVE_POLICY_DIR")
	if image == "" || directory == "" {
		t.Skip("opt in with scripts/test-native-policy.sh; requires native C harness")
	}
	body := readNativePolicyFixtures(t, directory)
	var steps []nativeMatcherStep
	if err := json.Unmarshal(body, &steps); err != nil {
		t.Fatal(err)
	}
	input, assertions := nativeMatcherInput(t, steps)
	command := nativeMatcherCommand(t, image)
	command.Stdin = bytes.NewReader(input)
	output, err := command.CombinedOutput()
	t.Logf("actual native parser/matcher output:\n%s", output)
	if err != nil {
		t.Fatalf("native matcher failed: %v", err)
	}
	if actual := strings.Count(string(output), "PASS "); actual != assertions || actual < 34 {
		t.Fatalf("native assertion count=%d want=%d (at least 34)", actual, assertions)
	}
	negative := corruptNativeExpectation(t, input)
	command = nativeMatcherCommand(t, image)
	command.Stdin = bytes.NewReader(negative)
	if output, err := command.CombinedOutput(); err == nil || !bytes.Contains(output, []byte("native action=")) {
		t.Fatalf("native assertion failed to detect wrong expected action: err=%v output=%s", err, output)
	}
	command = nativeMatcherCommand(t, image)
	command.Stdin = bytes.NewReader(corruptNativePacketExpectation(t, input))
	if output, err := command.CombinedOutput(); err == nil || !bytes.Contains(output, []byte("native action=")) {
		t.Fatalf("full packet wrapper failed to detect wrong expected action: err=%v output=%s", err, output)
	}
	for _, rejected := range []string{"{not-json}\n", "{\"unknown_control\":{}}\n"} {
		command := nativeMatcherCommand(t, image)
		command.Stdin = strings.NewReader(rejected)
		if output, err := command.CombinedOutput(); err == nil {
			t.Fatalf("native harness accepted malformed/unknown command: %s", output)
		}
	}
}

func nativeMatcherCommand(t *testing.T, image string) *exec.Cmd {
	t.Helper()
	// Explicit local engine; no daemon/session credentials or host namespaces.
	command := exec.CommandContext(t.Context(), "/bin/bash", "../../../tests/native-policy/run.sh")
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if name == "DOCKER_HOST" || name == "DOCKER_CONTEXT" || name == "DOCKER_TLS" || name == "DOCKER_TLS_VERIFY" || name == "DOCKER_CERT_PATH" {
			continue
		}
		if name != "CONSTELLATION_NATIVE_POLICY_IMAGE_ID" {
			command.Env = append(command.Env, entry)
		}
	}
	command.Env = append(command.Env, "CONSTELLATION_NATIVE_POLICY_IMAGE_ID="+image)
	return command
}

func nativeMatcherInput(t *testing.T, steps []nativeMatcherStep) ([]byte, int) {
	t.Helper()
	server := newCaptureServer(t)
	client := newClientPointedAt(t, server)
	var input bytes.Buffer
	emit := func(command any) {
		t.Helper()
		if err := json.NewEncoder(&input).Encode(command); err != nil {
			t.Fatal(err)
		}
	}
	for _, mac := range []string{"02:00:00:00:00:01", "02:00:00:00:00:02"} {
		if err := client.AddMAC("test-only-eth0", mac, nil); err != nil {
			t.Fatal(err)
		}
		messages := server.drain(1)
		if len(messages) != 1 {
			t.Fatal("missing actual Go MAC encoder output")
		}
		input.Write(messages[0])
		input.WriteByte('\n')
	}
	assertions := 0
	for _, step := range steps {
		if step.Lookup != nil {
			emit(map[string]any{"case": step.Name, "lookup": step.Lookup})
			assertions++
			continue
		}
		if step.ICMP != nil {
			if err := (&Supervisor{client: client}).SetICMPPolicy(*step.ICMP); err != nil {
				t.Fatal(err)
			}
			messages := server.drain(1)
			if len(messages) != 1 {
				t.Fatal("missing actual Go ICMP encoder output")
			}
			input.Write(messages[0])
			input.WriteByte('\n')
			continue
		}
		for _, fragment := range nativeStepFragments(t, client, server, step) {
			input.Write(fragment)
			input.WriteByte('\n')
		}
	}
	// The real control parser rejects an empty MAC list; check its return rather
	// than treating every successfully decoded JSON document as successful apply.
	emit(map[string]any{"case": "native-parser-rejects-empty-MAC", "expect_ret": -1, "ctrl_cfg_policy": map[string]any{"cmd": CmdModify, "flag": MsgStart | MsgEnd, "mac": []string{}, "rules": []any{}}})
	return input.Bytes(), assertions
}

func captureNativePolicyFragments(t *testing.T, client *dpClient, server *captureServer, policy *WorkloadPolicy, command uint) [][]byte {
	t.Helper()
	result := make(chan error, 1)
	go func() { result <- client.pushPolicy(policy, command) }()
	var fragments [][]byte
	for count := 0; count < 10000; count++ {
		messages := server.drain(1)
		if len(messages) != 1 {
			t.Fatal("actual Go policy transfer did not finish")
		}
		if len(messages[0]) > maxPolicyMsgSize {
			t.Fatalf("native policy datagram exceeds safe payload: %d", len(messages[0]))
		}
		var parsed policyCfgReq
		if err := json.Unmarshal(messages[0], &parsed); err != nil {
			t.Fatal(err)
		}
		fragments = append(fragments, messages[0])
		if parsed.Cfg.Flag&MsgEnd != 0 {
			break
		}
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	return fragments
}

// A deliberately incorrect expectation must fail in the C process, proving the
// positive output is backed by actual comparisons rather than presence checks.
func corruptNativeExpectation(t *testing.T, input []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	changed := false
	for _, line := range bytes.Split(bytes.TrimSpace(input), []byte("\n")) {
		var command map[string]json.RawMessage
		if err := json.Unmarshal(line, &command); err != nil {
			t.Fatal(err)
		}
		if _, lookup := command["lookup"]; lookup && !changed {
			var query map[string]any
			if err := json.Unmarshal(command["lookup"], &query); err != nil {
				t.Fatal(err)
			}
			query["action"] = PolicyActionAllow
			raw, err := json.Marshal(query)
			if err != nil {
				t.Fatal(err)
			}
			command["lookup"] = raw
			changed = true
		}
		if err := json.NewEncoder(&output).Encode(command); err != nil {
			t.Fatal(err)
		}
	}
	if !changed {
		t.Fatal("no native expectation to invalidate")
	}
	return output.Bytes()
}

func nativeStepFragments(t *testing.T, client *dpClient, server *captureServer, step nativeMatcherStep) [][]byte {
	t.Helper()
	if step.Policy == nil {
		t.Fatal("missing native fixture policy")
	}
	fragments := captureNativePolicyFragments(t, client, server, step.Policy, step.Command)
	if step.Prefix {
		if len(fragments) < 2 {
			t.Fatal("prefix fixture must leave native staging incomplete")
		}
		fragments = fragments[:1]
	}
	return fragments
}

func readNativePolicyFixtures(t *testing.T, directory string) []byte {
	t.Helper()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	file, err := root.Open("policies.json")
	if err != nil {
		t.Fatal(errors.Join(err, root.Close()))
	}
	body, readErr := io.ReadAll(file)
	if err := errors.Join(readErr, file.Close(), root.Close()); err != nil {
		t.Fatal(err)
	}
	return body
}

// Prove the full packet wrapper is asserted independently of keyed matching.
func corruptNativePacketExpectation(t *testing.T, input []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	changed := false
	for _, line := range bytes.Split(bytes.TrimSpace(input), []byte("\n")) {
		var command map[string]any
		if err := json.Unmarshal(line, &command); err != nil {
			t.Fatal(err)
		}
		if query, ok := command["lookup"].(map[string]any); ok && query["packet"] == true && !changed {
			query["action"] = PolicyActionAllow
			changed = true
		}
		if err := json.NewEncoder(&output).Encode(command); err != nil {
			t.Fatal(err)
		}
	}
	if !changed {
		t.Fatal("no full packet query to invalidate")
	}
	return output.Bytes()
}
