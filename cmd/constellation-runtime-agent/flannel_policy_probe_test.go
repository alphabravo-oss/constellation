//go:build integration && linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

type flannelEvents struct {
	mu   sync.Mutex
	rows []dp.Connection
}

func (events *flannelEvents) drain(stream <-chan dp.Event, done chan<- struct{}) {
	defer close(done)
	for event := range stream {
		if event.Conn != nil {
			events.mu.Lock()
			events.rows = append(events.rows, *event.Conn)
			events.mu.Unlock()
		}
	}
}
func (events *flannelEvents) matching(probe flannelProbe, clientIP, serverIP, mac string) []dp.Connection {
	events.mu.Lock()
	defer events.mu.Unlock()
	var matches []dp.Connection
	for index, row := range events.rows {
		if index < probe.EventCursor || int64(row.FirstSeenAt) < probe.StartedAt || probe.Application != 0 && row.Application != probe.Application {
			continue
		}
		if row.EPMAC.String() == mac && row.ClientIP.String() == clientIP && row.ServerIP.String() == serverIP && row.ServerPort == probe.Port && row.IPProto == dp.IPProtoTCP && row.PolicyAction == probe.Action && row.PolicyID == probe.PolicyID {
			matches = append(matches, row)
		}
	}
	return matches
}

func (events *flannelEvents) cursor() int {
	events.mu.Lock()
	defer events.mu.Unlock()
	return len(events.rows)
}

type flannelProbe struct {
	StartedAt     int64           `json:"started_at"`
	EventCursor   int             `json:"event_cursor"`
	Phase         string          `json:"phase"`
	Pod           string          `json:"pod"`
	Nonce         string          `json:"nonce"`
	Port          uint16          `json:"port"`
	SourcePort    uint16          `json:"source_port"`
	Allowed       bool            `json:"allowed"`
	Action        uint8           `json:"action"`
	Application   uint16          `json:"application"`
	PolicyID      uint32          `json:"policy_id"`
	RequireNative bool            `json:"require_native"`
	Before        uint64          `json:"queue_packets_before"`
	After         uint64          `json:"queue_packets_after"`
	Response      json.RawMessage `json:"response,omitempty"`
	Error         string          `json:"error,omitempty"`
	Native        []dp.Connection `json:"native"`
}

type flannelObservation struct {
	Nonce  string `json:"nonce"`
	Pod    string `json:"pod"`
	Port   uint16 `json:"port"`
	Remote string `json:"remote"`
}

func flannelCounter(ctx context.Context, pod flannelPod) (uint64, error) {
	output, err := flannelInPodNamespace(pod, func() ([]byte, error) {
		return exec.CommandContext(ctx, "iptables-save", "-t", "mangle", "-c").Output()
	})
	if err != nil {
		return 0, err
	}
	return parseFlannelCounter(string(output))
}
func parseFlannelCounter(output string) (uint64, error) {
	var count uint64
	for _, line := range strings.Split(output, "\n") {
		if !strings.Contains(line, "-j NFQUEUE") {
			continue
		}
		if !strings.Contains(line, "--queue-bypass") || (!strings.Contains(line, "-i eth0") && !strings.Contains(line, "-o eth0")) {
			return 0, errors.New("unexpected queue redirect")
		}
		left, _, ok := strings.Cut(strings.TrimPrefix(line, "["), ":")
		if !ok {
			return 0, errors.New("missing exact packet counter")
		}
		value, err := strconv.ParseUint(left, 10, 64)
		if err != nil {
			return 0, err
		}
		if ^uint64(0)-count < value {
			return 0, errors.New("packet counter overflow")
		}
		count += value
	}
	return count, nil
}

func flannelProbeOnce(ctx context.Context, client, pod flannelPod, probe *flannelProbe) error {
	if err := checkFlannelPods([]flannelPod{client, pod}); err != nil {
		return err
	}
	before, err := flannelCounter(ctx, pod)
	if err != nil {
		return err
	}
	probe.Before = before
	input, err := json.Marshal(struct {
		Target     string `json:"target"`
		Port       uint16 `json:"port"`
		SourcePort uint16 `json:"source_port"`
		Nonce      string `json:"nonce"`
	}{pod.IP, probe.Port, probe.SourcePort, probe.Nonce})
	if err != nil {
		return err
	}
	body, callErr := flannelInPodNamespace(client, func() ([]byte, error) {
		command := exec.CommandContext(ctx, "/usr/local/bin/flannel-policy-fixture", "-mode=probe")
		command.Stdin = bytes.NewReader(input)
		return command.Output()
	})
	after, err := flannelCounter(ctx, pod)
	if err != nil {
		return err
	}
	probe.After = after
	if err := flannelProbeOutcome(client, pod, probe, body, callErr); err != nil {
		return err
	}

	if probe.RequireNative && probe.After <= probe.Before {
		return errors.New("probe did not traverse native queue redirects")
	}
	return nil
}

func flannelProbeOutcome(client, pod flannelPod, probe *flannelProbe, body []byte, callErr error) error {
	if !probe.Allowed {
		if callErr == nil {
			return fmt.Errorf("protected probe %s reached server", probe.Nonce)
		}
		var exitError *exec.ExitError
		if !errors.As(callErr, &exitError) || exitError.ExitCode() != 1 {
			return fmt.Errorf("probe tool failed outside packet outcome: %w", callErr)
		}
		probe.Error = string(exitError.Stderr)
		return nil
	}
	if callErr != nil {
		return fmt.Errorf("required reachable probe %s: %w", probe.Nonce, callErr)
	}
	var observation flannelObservation
	if err := json.Unmarshal(body, &observation); err != nil {
		return err
	}
	remote, port, err := net.SplitHostPort(observation.Remote)
	if err != nil || remote != client.IP || port != strconv.Itoa(int(probe.SourcePort)) || observation.Nonce != probe.Nonce || observation.Pod != pod.Name || observation.Port != probe.Port {
		return errors.New("server did not observe exact client probe")
	}
	probe.Response = append([]byte(nil), body...)
	return nil
}

// A locked disposable OS thread enters only the validated namespace descriptor.
// Children inherit that namespace. Failed restoration retires the thread rather
// than making an escaped thread available to any other Go goroutine.
func flannelInPodNamespace(pod flannelPod, call func() ([]byte, error)) ([]byte, error) {
	if err := checkFlannelPods([]flannelPod{pod}); err != nil {
		return nil, err
	}
	type result struct {
		body []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		original, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			runtime.UnlockOSThread()
			done <- result{err: err}
			return
		}
		var current unix.Stat_t
		statErr := unix.Fstat(original, &current)
		if statErr != nil || "net:["+strconv.FormatUint(current.Ino, 10)+"]" != pod.NodeNetNS {
			_ = unix.Close(original)
			runtime.UnlockOSThread()
			done <- result{err: errors.New("driver thread is outside the owned node namespace")}
			return
		}
		target, err := flannelPodNamespaceFD(pod)
		if err != nil {
			_ = unix.Close(original)
			runtime.UnlockOSThread()
			done <- result{err: err}
			return
		}
		if err := unix.Setns(target, unix.CLONE_NEWNET); err != nil {
			_ = unix.Close(target)
			_ = unix.Close(original)
			runtime.UnlockOSThread()
			done <- result{err: err}
			return
		}
		body, callErr := call()
		restoreErr := unix.Setns(original, unix.CLONE_NEWNET)
		closeErr := errors.Join(unix.Close(target), unix.Close(original))
		if restoreErr == nil {
			runtime.UnlockOSThread()
		}
		done <- result{body, errors.Join(callErr, restoreErr, closeErr)}
	}()
	outcome := <-done
	return outcome.body, outcome.err
}

func flannelPodNamespaceFD(pod flannelPod) (int, error) {
	root, err := os.OpenRoot("/proc")
	if err != nil {
		return -1, err
	}
	directory, openErr := root.Open(strconv.Itoa(pod.PID))
	if err := errors.Join(openErr, root.Close()); err != nil {
		return -1, err
	}
	descriptor := directory.Fd()
	if descriptor > math.MaxInt {
		_ = directory.Close()
		return -1, errors.New("invalid process directory descriptor")
	}
	target, openErr := unix.Openat(int(descriptor), "ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err := errors.Join(openErr, directory.Close()); err != nil {
		if target >= 0 {
			_ = unix.Close(target)
		}
		return -1, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(target, &stat); err != nil {
		_ = unix.Close(target)
		return -1, err
	}
	if "net:["+strconv.FormatUint(stat.Ino, 10)+"]" != pod.NetNS {
		_ = unix.Close(target)
		return -1, errors.New("opened namespace generation changed")
	}
	return target, nil
}

func waitFlannelNative(ctx context.Context, events *flannelEvents, client, pod flannelPod, mac string, probe *flannelProbe) error {
	deadline := time.NewTimer(35 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		matches := events.matching(*probe, client.IP, pod.IP, mac)
		if len(matches) > 0 {
			probe.Native = matches
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("no matching actual native verdict for %s", probe.Nonce)
		case <-ticker.C:
		}
	}
}

func stopOwnedFlannelDP(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	pid, err := flannelOwnedChildPID()
	if err != nil {
		return err
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	root, err := os.OpenRoot("/proc/" + strconv.Itoa(pid))
	if err != nil {
		return err
	}
	path, pathErr := root.Readlink("exe")
	status, statusErr := root.ReadFile("status")
	if err := errors.Join(pathErr, statusErr, root.Close()); err != nil {
		return err
	}
	if path != "/usr/local/bin/dp" || !flannelOwnChildStatus(string(status), os.Getpid()) {
		return errors.New("refusing to signal anything except exact owned native child")
	}
	return unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
}
func flannelOwnedChildPID() (int, error) {
	root, err := os.OpenRoot("/proc")
	if err != nil {
		return 0, err
	}
	defer func() { _ = root.Close() }()
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return 0, err
	}
	var matched int
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 1 {
			continue
		}
		status, err := root.ReadFile(entry.Name() + "/status")
		if err != nil || !flannelOwnChildStatus(string(status), os.Getpid()) {
			continue
		}
		executable, err := root.Readlink(entry.Name() + "/exe")
		if err != nil || executable != "/usr/local/bin/dp" {
			continue
		}
		if matched != 0 {
			return 0, errors.New("multiple owned native children")
		}
		matched = pid
	}
	if matched == 0 {
		return 0, errors.New("no exact owned native child")
	}
	return matched, nil
}

func flannelOwnChildStatus(status string, parent int) bool {
	for _, line := range strings.Split(status, "\n") {
		if strings.HasPrefix(line, "PPid:") {
			value, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")))
			return err == nil && value == parent
		}
	}
	return false
}

func flannelQueueListener(pod flannelPod) (bool, error) {
	root, err := os.OpenRoot("/proc/" + strconv.Itoa(pod.PID))
	if err != nil {
		return false, err
	}
	body, readErr := root.ReadFile("net/netfilter/nfnetlink_queue")
	if err := errors.Join(readErr, root.Close()); err != nil {
		return false, err
	}
	return strings.TrimSpace(string(body)) != "", nil
}

func TestFlannelCounterRequiresRealQueueBypassAndRejectsOverflow(t *testing.T) {
	text := "[12:120] -A PREROUTING -i eth0 -j NFQUEUE --queue-num 4000 --queue-bypass\n[3:30] -A POSTROUTING -o eth0 -j NFQUEUE --queue-num 4000 --queue-bypass"
	if value, err := parseFlannelCounter(text); err != nil || value != 15 {
		t.Fatalf("counter=%d error=%v", value, err)
	}
	for _, invalid := range []string{strings.ReplaceAll(text, " --queue-bypass", ""), strings.ReplaceAll(text, "eth0", "other"), strings.Replace(text, "12:120", "-1:120", 1), strings.Replace(text, "12:120", "18446744073709551615:120", 1)} {
		if _, err := parseFlannelCounter(invalid); err == nil {
			t.Fatal("invalid queue evidence accepted")
		}
	}
}
func TestFlannelOwnedChildRejectsUnrelatedParent(t *testing.T) {
	if !flannelOwnChildStatus("Name:\tdp\nPPid:\t123\n", 123) || flannelOwnChildStatus("Name:\tdp\nPPid:\t123\n", 456) || flannelOwnChildStatus("Name:\tdp\n", 123) {
		t.Fatal("owned child guard lost parent identity")
	}
}

func TestFlannelNativeEvidenceRejectsDelayedEarlierAggregate(t *testing.T) {
	mac, err := net.ParseMAC("02:00:00:00:00:01")
	if err != nil {
		t.Fatal(err)
	}
	probe := flannelProbe{EventCursor: 1, StartedAt: 100, Port: 18080, SourcePort: 40001, Action: dp.PolicyActionAllow, PolicyID: 11}
	row := dp.Connection{EPMAC: mac, ClientIP: net.ParseIP("10.233.0.12"), ServerIP: net.ParseIP("10.233.0.10"), ServerPort: 18080, IPProto: dp.IPProtoTCP, PolicyAction: dp.PolicyActionAllow, PolicyID: 11, FirstSeenAt: 100}
	events := &flannelEvents{rows: []dp.Connection{row}}
	if len(events.matching(probe, "10.233.0.12", "10.233.0.10", mac.String())) != 0 {
		t.Fatal("pre-dispatch aggregate accepted")
	}
	old := row
	old.FirstSeenAt = 99
	events.rows = append(events.rows, old)
	if len(events.matching(probe, "10.233.0.12", "10.233.0.10", mac.String())) != 0 {
		t.Fatal("delayed earlier aggregate accepted")
	}
	wrong := row
	wrong.PolicyID = 22
	events.rows = append(events.rows, wrong)
	if len(events.matching(probe, "10.233.0.12", "10.233.0.10", mac.String())) != 0 {
		t.Fatal("another workload policy accepted")
	}
	events.rows = append(events.rows, row)
	if len(events.matching(probe, "10.233.0.12", "10.233.0.10", mac.String())) != 1 {
		t.Fatal("fresh native aggregate rejected")
	}
}
