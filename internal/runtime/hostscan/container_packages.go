package hostscan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ContainerPackages is package inventory collected from one running
// container's root filesystem. The runtime-agent uploads this as workload scan
// evidence; scanner workers perform vulnerability matching separately.
type ContainerPackages struct {
	Node          string    `json:"node"`
	ObservedAt    time.Time `json:"observed_at"`
	Runtime       string    `json:"runtime,omitempty"`
	Socket        string    `json:"socket,omitempty"`
	WorkloadID    string    `json:"workload_id,omitempty"`
	Namespace     string    `json:"namespace,omitempty"`
	PodName       string    `json:"pod_name,omitempty"`
	PodUID        string    `json:"pod_uid,omitempty"`
	ContainerID   string    `json:"container_id"`
	ContainerName string    `json:"container_name,omitempty"`
	ContainerPID  int       `json:"container_pid,omitempty"`
	Image         string    `json:"image,omitempty"`
	ImageRef      string    `json:"image_ref,omitempty"`
	Distro        string    `json:"distro,omitempty"`
	DistroVersion string    `json:"distro_version,omitempty"`
	Source        string    `json:"source,omitempty"`
	Count         int       `json:"count"`
	Items         []Package `json:"items"`
}

type ContainerPackagesOptions struct {
	HostRoot    string
	ProcRoot    string
	NodeName    string
	Container   Container
	ContainerID string
	WorkloadID  string
	CrictlBin   string
	Timeout     time.Duration
}

type crictlInspectResponse struct {
	Status crictlContainer `json:"status"`
	Info   map[string]any  `json:"info"`
}

// CollectContainerPackages resolves the container process through CRI, reads
// /proc/<pid>/root, and enumerates the package DB inside that container only.
func CollectContainerPackages(ctx context.Context, opts ContainerPackagesOptions) (ContainerPackages, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	bin := strings.TrimSpace(opts.CrictlBin)
	if bin == "" {
		bin = "crictl"
	}
	procRoot := strings.TrimSpace(opts.ProcRoot)
	if procRoot == "" {
		procRoot = "/proc"
	}

	container := opts.Container
	if container.ID == "" {
		container.ID = opts.ContainerID
	}
	out := ContainerPackages{
		Node:          opts.NodeName,
		ObservedAt:    time.Now().UTC(),
		WorkloadID:    strings.TrimSpace(opts.WorkloadID),
		Namespace:     strings.TrimSpace(container.PodNS),
		PodName:       strings.TrimSpace(container.PodName),
		PodUID:        strings.TrimSpace(container.PodUID),
		ContainerID:   strings.TrimSpace(container.ID),
		ContainerName: strings.TrimSpace(container.Name),
		Image:         strings.TrimSpace(container.Image),
		ImageRef:      strings.TrimSpace(container.ImageRef),
	}
	if out.Node == "" {
		if h, _ := os.Hostname(); h != "" {
			out.Node = h
		}
	}
	if out.ContainerID == "" {
		return out, errors.New("container id is required")
	}

	socket, runtime := resolveCRISocket(opts.HostRoot)
	out.Socket = socket
	out.Runtime = runtime
	if socket == "" {
		return out, errors.New("no CRI socket detected — runtime-agent can't inspect container")
	}

	inspect, err := inspectContainer(ctx, bin, socket, out.ContainerID, opts.Timeout)
	if err != nil {
		return out, err
	}
	mergeInspectContainer(&out, inspect)
	pid := containerPID(inspect.Info)
	if pid <= 0 {
		return out, errors.New("container pid unavailable from crictl inspect")
	}
	out.ContainerPID = pid

	root := filepath.Join(procRoot, strconv.Itoa(pid), "root")
	distro, distroVersion := readOSReleaseRoot(root)
	out.Distro = distro
	out.DistroVersion = distroVersion
	pkgs, err := collectPackagesAtRoot(root, out.Node, distro, distroVersion)
	if err != nil {
		return out, err
	}
	out.Source = pkgs.Source
	out.Count = pkgs.Count
	out.Items = pkgs.Items
	return out, nil
}

// RunningContainer is one running container paired with the host PID of its
// main process. The dp tap reconciler turns each into a per-container netns
// tap (/proc/<PID>/ns/net) so dp captures packets with the pod's real
// on-wire MAC instead of the host-side veth MAC.
type RunningContainer struct {
	ID        string
	Name      string
	PodName   string
	PodNS     string
	PodUID    string
	PID       int
	// PodLabels are the user labels on the container's pod sandbox (from
	// `crictl pods`), keyed by the pod UID. Used to opt a workload into DPI
	// (WAF/DLP) per NeuVector's per-group model. Empty if the sandbox lookup
	// failed — callers treat absence as "no opt-in".
	PodLabels map[string]string
}

// ListRunningContainersOptions controls ListRunningContainers.
type ListRunningContainersOptions struct {
	HostRoot  string
	CrictlBin string
	Timeout   time.Duration
}

// ListRunningContainers shells out to crictl (reusing the same CRI socket
// detection as the inventory collector), then `crictl inspect`s each running
// container to resolve its host PID. Containers that aren't running, or whose
// PID can't be resolved, are skipped. This is the container enumeration the
// ContainerTapProvider builds its tap list from.
//
// It reuses inspectContainer + containerPID — the exact PID-resolution path
// CollectContainerPackages already trusts.
func ListRunningContainers(ctx context.Context, opts ListRunningContainersOptions) ([]RunningContainer, error) {
	bin := strings.TrimSpace(opts.CrictlBin)
	if bin == "" {
		bin = "crictl"
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	socket, _ := resolveCRISocket(opts.HostRoot)
	if socket == "" {
		return nil, errors.New("no CRI socket detected — runtime-agent can't list containers")
	}

	listCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	listCmd := exec.CommandContext(listCtx, bin,
		"--runtime-endpoint", "unix://"+socket,
		"ps", "-o", "json", // running only (no -a)
	)
	raw, err := listCmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("crictl ps failed (exit=%d): %s", exitErr.ExitCode(), strings.TrimSpace(string(exitErr.Stderr)))
		}
		return nil, fmt.Errorf("crictl ps: %w", err)
	}
	var listed crictlListResponse
	if err := json.Unmarshal(raw, &listed); err != nil {
		return nil, fmt.Errorf("parse crictl ps json: %w", err)
	}

	out := make([]RunningContainer, 0, len(listed.Containers))
	for _, c := range listed.Containers {
		if c.State != "" && c.State != "CONTAINER_RUNNING" {
			continue
		}
		inspect, err := inspectContainer(ctx, bin, socket, c.ID, timeout)
		if err != nil {
			// One bad inspect shouldn't abort the whole list.
			continue
		}
		pid := containerPID(inspect.Info)
		if pid <= 0 {
			continue
		}
		out = append(out, RunningContainer{
			ID:      c.ID,
			Name:    c.Metadata.Name,
			PodName: c.Labels["io.kubernetes.pod.name"],
			PodNS:   c.Labels["io.kubernetes.pod.namespace"],
			PodUID:  c.Labels["io.kubernetes.pod.uid"],
			PID:     pid,
		})
	}
	// Best-effort: attach each container's pod-sandbox user labels (for DPI
	// opt-in). One `crictl pods` call; failure leaves PodLabels nil (no opt-in).
	if labels := listPodSandboxLabels(ctx, bin, socket, timeout); len(labels) > 0 {
		for i := range out {
			if l, ok := labels[out[i].PodUID]; ok {
				out[i].PodLabels = l
			}
		}
	}
	return out, nil
}

// crictlPodsResponse is the shape of `crictl pods -o json`.
type crictlPodsResponse struct {
	Items []struct {
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
		Labels map[string]string `json:"labels"`
	} `json:"items"`
}

// listPodSandboxLabels returns podUID -> user labels for every running sandbox.
// The io.kubernetes.* / CRI system labels are dropped; only user labels remain.
func listPodSandboxLabels(ctx context.Context, bin, socket string, timeout time.Duration) map[string]map[string]string {
	ctx2, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx2, bin,
		"--runtime-endpoint", "unix://"+socket,
		"pods", "-o", "json",
	)
	raw, err := cmd.Output()
	if err != nil {
		return nil
	}
	var parsed crictlPodsResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil
	}
	out := make(map[string]map[string]string, len(parsed.Items))
	for _, p := range parsed.Items {
		uid := strings.TrimSpace(p.Metadata.UID)
		if uid == "" {
			continue
		}
		user := make(map[string]string, len(p.Labels))
		for k, v := range p.Labels {
			if strings.HasPrefix(k, "io.kubernetes.") {
				continue // CRI/system label, not a user label
			}
			user[k] = v
		}
		out[uid] = user
	}
	return out
}

func inspectContainer(ctx context.Context, bin, socket, containerID string, timeout time.Duration) (crictlInspectResponse, error) {
	ctx2, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx2, bin,
		"--runtime-endpoint", "unix://"+socket,
		"inspect", "-o", "json", containerID,
	)
	raw, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return crictlInspectResponse{}, fmt.Errorf("crictl inspect failed (exit=%d): %s", exitErr.ExitCode(), strings.TrimSpace(string(exitErr.Stderr)))
		}
		return crictlInspectResponse{}, fmt.Errorf("crictl inspect: %w", err)
	}
	var parsed crictlInspectResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return crictlInspectResponse{}, fmt.Errorf("parse crictl inspect json: %w", err)
	}
	return parsed, nil
}

func mergeInspectContainer(out *ContainerPackages, inspect crictlInspectResponse) {
	st := inspect.Status
	if out.ContainerID == "" {
		out.ContainerID = strings.TrimSpace(st.ID)
	}
	if out.ContainerName == "" {
		out.ContainerName = strings.TrimSpace(st.Metadata.Name)
	}
	if out.Image == "" {
		out.Image = strings.TrimSpace(st.Image.Image)
	}
	if out.ImageRef == "" {
		out.ImageRef = strings.TrimSpace(st.ImageRef)
	}
	if out.Namespace == "" {
		out.Namespace = strings.TrimSpace(st.Labels["io.kubernetes.pod.namespace"])
	}
	if out.PodName == "" {
		out.PodName = strings.TrimSpace(st.Labels["io.kubernetes.pod.name"])
	}
	if out.PodUID == "" {
		out.PodUID = strings.TrimSpace(st.Labels["io.kubernetes.pod.uid"])
	}
}

func containerPID(info map[string]any) int {
	for _, key := range []string{"pid", "Pid", "PID"} {
		if pid := numericJSONValue(info[key]); pid > 0 {
			return pid
		}
	}
	if nested, ok := info["info"].(map[string]any); ok {
		if pid := containerPID(nested); pid > 0 {
			return pid
		}
	}
	if runtimeSpec, ok := info["runtimeSpec"].(map[string]any); ok {
		if process, ok := runtimeSpec["process"].(map[string]any); ok {
			if pid := numericJSONValue(process["pid"]); pid > 0 {
				return pid
			}
		}
	}
	return firstPIDRecursive(info)
}

func firstPIDRecursive(value any) int {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			if strings.EqualFold(key, "pid") {
				if pid := numericJSONValue(child); pid > 0 {
					return pid
				}
			}
		}
		for _, child := range v {
			if pid := firstPIDRecursive(child); pid > 0 {
				return pid
			}
		}
	case []any:
		for _, child := range v {
			if pid := firstPIDRecursive(child); pid > 0 {
				return pid
			}
		}
	}
	return 0
}

func numericJSONValue(value any) int {
	switch v := value.(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	case json.Number:
		n, _ := v.Int64()
		return int(n)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(v))
		return n
	default:
		return 0
	}
}

func readOSReleaseRoot(root string) (string, string) {
	for _, rel := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		kv, ok := readKeyValueFile(filepath.Join(root, rel))
		if !ok {
			continue
		}
		return strings.TrimSpace(kv["ID"]), strings.TrimSpace(kv["VERSION_ID"])
	}
	return "", ""
}

func collectPackagesAtRoot(root, node, distro, distroVersion string) (Packages, error) {
	distro = strings.ToLower(strings.TrimSpace(distro))
	distroVersion = strings.TrimSpace(distroVersion)
	p := Packages{
		Node:          node,
		ObservedAt:    time.Now().UTC(),
		Distro:        distro,
		DistroVersion: distroVersion,
	}

	debianFamily := distro == "" || distro == "debian" || distro == "ubuntu"
	if debianFamily {
		if items, err := readDpkg(filepath.Join(root, "/var/lib/dpkg/status")); err == nil && len(items) > 0 {
			p.Source = "dpkg"
			p.Items = items
			p.Count = len(items)
			return p, nil
		}
	}
	if distro == "" || apkFamily(distro) {
		if items, err := readApk(filepath.Join(root, "/lib/apk/db/installed")); err == nil && len(items) > 0 {
			p.Source = "apk"
			p.Items = items
			p.Count = len(items)
			return p, nil
		}
	}
	if distro == "" || rpmFamily(distro) || (!debianFamily && !apkFamily(distro)) {
		if items, err := readRpm(root); err == nil && len(items) > 0 {
			p.Source = "rpm"
			p.Items = items
			p.Count = len(items)
			return p, nil
		}
	}
	if hasRpmDB(root) {
		p.Source = "rpm"
		return p, errors.New("rpm package database found but could not be enumerated")
	}
	return p, errors.New("no supported package manager DB found in container root")
}
