//go:build integration && linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

type flannelPod struct {
	Name        string `json:"name"`
	Namespace   string `json:"namespace"`
	UID         string `json:"uid"`
	ContainerID string `json:"container_id"`
	PID         int    `json:"pid"`
	IP          string `json:"ip"`
	NetNS       string `json:"netns"`
	NodeNetNS   string `json:"-"`
}

type flannelIdentity struct {
	ClusterName   string       `json:"cluster_name"`
	Namespace     string       `json:"namespace"`
	NodeContainer string       `json:"node_container"`
	NodePIDNS     string       `json:"node_pidns"`
	NodeNetNS     string       `json:"node_netns"`
	HostPIDNS     string       `json:"host_pidns"`
	HostNetNS     string       `json:"host_netns"`
	RuntimeImage  string       `json:"runtime_image"`
	CNI           string       `json:"cni"`
	Pods          []flannelPod `json:"pods"`
}

var flannelNamePattern = regexp.MustCompile(`^flannel-policy-[0-9a-f]{12}$`)
var flannelContainerPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var flannelNamespacePattern = regexp.MustCompile(`^packet-proof-[0-9a-f]{12}$`)
var flannelNSPattern = regexp.MustCompile(`^(pid|net):\[[1-9][0-9]*\]$`)

func validateFlannelIdentity(identity flannelIdentity) error {
	if !flannelNamePattern.MatchString(identity.ClusterName) || !flannelNamespacePattern.MatchString(identity.Namespace) || identity.NodeContainer != identity.ClusterName+"-server-0" || identity.CNI != "flannel" {
		return errors.New("fixture does not identify a uniquely owned Flannel node")
	}
	if identity.RuntimeImage != "sha256:58a1dfe1ce01f77007243106143edceb3db0071cbcbd2765b2be267679a0ff8e" {
		return errors.New("unexpected qualified runtime image")
	}
	if !validFlannelNamespacePair(identity.NodePIDNS, identity.HostPIDNS, "pid") || !validFlannelNamespacePair(identity.NodeNetNS, identity.HostNetNS, "net") {
		return errors.New("test node must not share host PID or network namespace")
	}
	return validateFlannelPods(identity)
}

func validFlannelNamespacePair(node, host, kind string) bool {
	return node != host && flannelNSPattern.MatchString(node) && flannelNSPattern.MatchString(host) && strings.HasPrefix(node, kind+":") && strings.HasPrefix(host, kind+":")
}

func validateFlannelPods(identity flannelIdentity) error {
	if len(identity.Pods) != 3 {
		return errors.New("exactly two servers and one client required")
	}
	names, uids, pids, ips, namespaces := map[string]bool{}, map[string]bool{}, map[int]bool{}, map[string]bool{}, map[string]bool{}
	_, subnet, err := net.ParseCIDR("10.233.0.0/16")
	if err != nil {
		return err
	}
	for _, pod := range identity.Pods {
		if pod.Name != "server-a" && pod.Name != "server-b" && pod.Name != "client" {
			return errors.New("unexpected pod")
		}
		uid, err := uuid.Parse(pod.UID)
		if err != nil || uid == uuid.Nil || uid.String() != pod.UID || pod.Namespace != identity.Namespace || !flannelContainerPattern.MatchString(pod.ContainerID) || pod.PID <= 1 || pod.PID > math.MaxInt32 {
			return errors.New("invalid exact pod identity")
		}
		ip := net.ParseIP(pod.IP)
		if ip == nil || ip.To4() == nil || !subnet.Contains(ip) || !flannelNSPattern.MatchString(pod.NetNS) || !strings.HasPrefix(pod.NetNS, "net:") || pod.NetNS == identity.NodeNetNS || pod.NetNS == identity.HostNetNS {
			return errors.New("pod escaped isolated pod network")
		}
		if names[pod.Name] || uids[pod.UID] || pids[pod.PID] || ips[pod.IP] || namespaces[pod.NetNS] {
			return errors.New("duplicate fixture identity")
		}
		names[pod.Name], uids[pod.UID], pids[pod.PID], ips[pod.IP], namespaces[pod.NetNS] = true, true, true, true, true
	}
	return nil
}

func loadFlannelIdentity() (flannelIdentity, error) {
	var identity flannelIdentity
	root, err := os.OpenRoot("/evidence")
	if err != nil {
		return identity, err
	}
	body, readErr := root.ReadFile("identity.json")
	if err := errors.Join(readErr, root.Close()); err != nil {
		return identity, err
	}
	if len(body) > 16<<10 {
		return identity, errors.New("oversized fixture identity")
	}
	if err := json.Unmarshal(body, &identity); err != nil {
		return identity, err
	}
	if err := validateFlannelIdentity(identity); err != nil {
		return identity, err
	}
	for _, check := range []struct{ path, expected string }{{"/proc/self/ns/pid", identity.NodePIDNS}, {"/proc/self/ns/net", identity.NodeNetNS}} {
		actual, err := os.Readlink(check.path)
		if err != nil || actual != check.expected {
			return identity, errors.New("driver is not inside the owned node namespaces")
		}
	}
	for index := range identity.Pods {
		identity.Pods[index].NodeNetNS = identity.NodeNetNS
	}
	if err := captureFlannelSecurityLabels(identity.Pods); err != nil {
		return identity, err
	}
	return identity, checkFlannelPods(identity.Pods)
}

// This deliberate driver-only AppArmor exception never changes host profiles.
// Capture actual labels before inspecting pod namespace links or starting DP.
func captureFlannelSecurityLabels(pods []flannelPod) error {
	labels := make(map[string]string, len(pods)+1)
	for _, target := range append([]flannelPod{{Name: "driver", PID: os.Getpid()}}, pods...) {
		body, err := os.ReadFile("/proc/" + strconv.Itoa(target.PID) + "/attr/current")
		if err != nil {
			return fmt.Errorf("read %s AppArmor label: %w", target.Name, err)
		}
		labels[target.Name] = strings.TrimSpace(string(body))
	}
	body, err := json.MarshalIndent(labels, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile("/evidence/security-labels.json", append(body, '\n'), 0o600); err != nil {
		return err
	}
	return validateFlannelSecurityLabels(labels)
}

func validateFlannelSecurityLabels(labels map[string]string) error {
	if len(labels) != 4 {
		return errors.New("exact driver and three pod AppArmor labels required")
	}
	for _, name := range []string{"driver", "client", "server-a", "server-b"} {
		if labels[name] != "unconfined" {
			return fmt.Errorf("unexpected %s AppArmor label %q", name, labels[name])
		}
	}
	return nil
}

func checkFlannelPods(pods []flannelPod) error {
	for _, pod := range pods {
		root, err := os.OpenRoot("/proc/" + strconv.Itoa(pod.PID))
		if err != nil {
			return err
		}
		namespace, nsErr := flannelPodNamespace(root)
		cgroup, cgErr := root.ReadFile("cgroup")
		closeErr := root.Close()
		if err := errors.Join(nsErr, cgErr, closeErr); err != nil {
			return err
		}
		ownedUID := strings.Contains(string(cgroup), pod.UID) || strings.Contains(string(cgroup), strings.ReplaceAll(pod.UID, "-", "_"))
		if namespace != pod.NetNS || !ownedUID || !strings.Contains(string(cgroup), pod.ContainerID) {
			return errors.New("pod PID generation or container ownership changed")
		}
	}
	return nil
}

func flannelPodNamespace(root *os.Root) (string, error) {
	// Root.Readlink traverses ns using an O_RDONLY directory open, but proc's
	// non-owner ns directory is search-only (0511). Keep the pinned PID directory
	// and resolve this fixed literal with readlinkat, without adding DAC caps.
	directory, err := root.Open(".")
	if err != nil {
		return "", err
	}
	fd := directory.Fd()
	if fd > math.MaxInt {
		return "", errors.Join(errors.New("invalid proc directory descriptor"), directory.Close())
	}
	var buffer [128]byte
	n, readErr := unix.Readlinkat(int(fd), "ns/net", buffer[:])
	if err := errors.Join(readErr, directory.Close()); err != nil {
		return "", err
	}
	if n <= 0 || n >= len(buffer) {
		return "", errors.New("empty or truncated pod namespace link")
	}
	return string(buffer[:n]), nil
}

func flannelLister(identity flannelIdentity) dp.ContainerLister {
	return func(context.Context) ([]dp.RunningContainer, error) {
		if err := checkFlannelPods(identity.Pods); err != nil {
			return nil, err
		}
		var containers []dp.RunningContainer
		for _, pod := range identity.Pods {
			if pod.Name == "client" {
				continue
			}
			containers = append(containers, dp.RunningContainer{ID: pod.ContainerID, PodName: pod.Name, PodUID: pod.UID, PID: pod.PID, Namespace: pod.Namespace, Enforce: true})
		}
		return containers, nil
	}
}

func flannelPolicies(identity flannelIdentity) []runtimePolicyWire {
	var policies []runtimePolicyWire
	for _, pod := range identity.Pods {
		if pod.Name == "client" {
			continue
		}
		port := uint16(18080)
		wireID := int64(11)
		if pod.Name == "server-b" {
			port = 18081
			wireID = 22
		}
		policies = append(policies, runtimePolicyWire{ID: uuid.NewString(), DPPolicyID: wireID, Workload: pod.Namespace + "/pod/" + pod.Name, Namespace: pod.Namespace, BindingStatus: "resolved", PodBindings: []runtimePolicyPodBinding{{Namespace: pod.Namespace, PodName: pod.Name, PodUID: pod.UID}}, Mode: "monitor", Version: 1, DefAction: dp.PolicyActionDeny, ApplyDir: dp.ApplyDirIngress, Rules: []*dp.PolicyRule{{Ingress: true, Port: port, IPProto: dp.IPProtoTCP, Action: dp.PolicyActionAllow, Apps: []dp.PolicyApp{{App: 1001, Action: dp.PolicyActionAllow}}}}})
	}
	return policies
}

func flannelBundleServer(cluster string, payload *atomic.Pointer[runtimePolicyBundle], logger *slog.Logger) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/runtime/policies:bundle" || r.URL.Query().Get("protocol") != "2" || r.URL.Query().Get("cluster_id") != cluster || r.Header.Get("Authorization") != "Bearer isolated-fixture" {
			http.Error(w, "scope rejected", http.StatusBadRequest)
			return
		}
		if err := json.NewEncoder(w).Encode(payload.Load()); err != nil {
			logger.Error("fixture bundle response", "error", err)
		}
	}))
}

func fixtureFlannelIdentity() flannelIdentity {
	id := flannelIdentity{ClusterName: "flannel-policy-abcdef123456", Namespace: "packet-proof-abcdef123456", NodeContainer: "flannel-policy-abcdef123456-server-0", NodePIDNS: "pid:[100]", NodeNetNS: "net:[200]", HostPIDNS: "pid:[1]", HostNetNS: "net:[2]", CNI: "flannel", RuntimeImage: "sha256:58a1dfe1ce01f77007243106143edceb3db0071cbcbd2765b2be267679a0ff8e"}
	for index, name := range []string{"server-a", "server-b", "client"} {
		id.Pods = append(id.Pods, flannelPod{Name: name, Namespace: id.Namespace, UID: uuid.NewString(), ContainerID: strings.Repeat(strconv.Itoa(index+1), 64), PID: index + 10, IP: fmt.Sprintf("10.233.0.%d", index+10), NetNS: fmt.Sprintf("net:[%d]", index+300)})
	}
	return id
}

func TestFlannelFixtureRejectsScopeEscapeAndReusedIdentity(t *testing.T) {
	tests := map[string]func(*flannelIdentity){"existing cluster": func(id *flannelIdentity) { id.ClusterName = "constellation-convergence" }, "host PID": func(id *flannelIdentity) { id.NodePIDNS = id.HostPIDNS }, "host net": func(id *flannelIdentity) { id.NodeNetNS = id.HostNetNS }, "foreign IP": func(id *flannelIdentity) { id.Pods[0].IP = "10.42.0.1" }, "host pod": func(id *flannelIdentity) { id.Pods[0].NetNS = id.NodeNetNS }, "reused PID": func(id *flannelIdentity) { id.Pods[1].PID = id.Pods[0].PID }, "wrong image": func(id *flannelIdentity) { id.RuntimeImage = "latest" }, "missing UID": func(id *flannelIdentity) { id.Pods[0].UID = "" }}
	if err := validateFlannelIdentity(fixtureFlannelIdentity()); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			id := fixtureFlannelIdentity()
			mutate(&id)
			if err := validateFlannelIdentity(id); err == nil {
				t.Fatal("unsafe fixture accepted")
			}
		})
	}
}

func TestFlannelFixtureRejectsUnexpectedSecurityLabels(t *testing.T) {
	labels := map[string]string{"driver": "unconfined", "client": "unconfined", "server-a": "unconfined", "server-b": "unconfined"}
	if err := validateFlannelSecurityLabels(labels); err != nil {
		t.Fatal(err)
	}
	for name := range labels {
		labels[name] = "docker-default (enforce)"
		if err := validateFlannelSecurityLabels(labels); err == nil {
			t.Fatalf("unexpected %s profile accepted", name)
		}
		labels[name] = "unconfined"
	}
	delete(labels, "client")
	if err := validateFlannelSecurityLabels(labels); err == nil {
		t.Fatal("missing pod label accepted")
	}
}

func TestFlannelFixtureReadlinkSearchOnly(t *testing.T) {
	if path := os.Getenv("CONSTELLATION_FLANNEL_SEARCH_ONLY_TEST"); path != "" {
		assertFlannelSearchOnlyLink(t, path)
		return
	}
	directory, err := os.MkdirTemp("", "flannel-search-only-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Chmod(directory+"/ns", 0o700); err != nil {
			t.Error(err)
		}
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	for _, err := range []error{unix.Chmod(directory, 0o755), os.Mkdir(directory+"/ns", 0o700), os.Symlink("net:[12345]", directory+"/ns/net"), unix.Chmod(directory+"/ns", 0o111)} {
		if err != nil {
			t.Fatal(err)
		}
	}
	executable, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := executable.Close(); err != nil {
			t.Error(err)
		}
	})
	command := exec.CommandContext(t.Context(), "/proc/self/fd/3", "-test.run=^TestFlannelFixtureReadlinkSearchOnly$")
	command.ExtraFiles = []*os.File{executable}
	command.Env = append(os.Environ(), "CONSTELLATION_FLANNEL_SEARCH_ONLY_TEST="+directory)
	if os.Geteuid() == 0 {
		// The owned child has no capabilities and cannot borrow root's DAC bypass.
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("unprivileged search-only regression: %v\n%s", err, output)
	}
}

func TestFlannelFixturePoliciesRequireRealBindingsAndStampAppIDs(t *testing.T) {
	identity := fixtureFlannelIdentity()
	policies := flannelPolicies(identity)
	if err := validateRuntimePolicyBundle(&runtimePolicyBundle{ProtocolVersion: 2, ClusterID: "fixture", SourceComplete: true, Policies: policies}, "fixture"); err != nil {
		t.Fatal(err)
	}
	for _, policy := range policies {
		merged := buildMergedWorkloadPolicy([]runtimePolicyWire{policy}, []string{"02:00:00:00:00:01"})
		if len(merged.Rules) != 1 || len(merged.Rules[0].Apps) != 1 || int64(merged.Rules[0].Apps[0].RuleID) != policy.DPPolicyID {
			t.Fatal("fixture does not exercise nested native attribution")
		}
	}
}

func assertFlannelSearchOnlyLink(t *testing.T, path string) {
	t.Helper()
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, err := root.Readlink("ns/net"); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("expected traversal read denial, got %v", err)
	}
	got, err := flannelPodNamespace(root)
	if err != nil || got != "net:[12345]" {
		t.Fatalf("pinned literal readlink failed: %q, %v", got, err)
	}
}
