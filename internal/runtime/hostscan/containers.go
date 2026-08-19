// Container inventory collector (Slice C). Shells out to `crictl ps`
// against the host's CRI socket and emits a normalized inventory.
//
// Why shell out? The full Go CRI client is k8s.io/cri-api + lots of
// transitive deps (kube-apimachinery, kube-runtime, …) that pull in
// ~150 packages just to round-trip a few protos. crictl is the upstream
// CLI shipped on every Kubernetes node, supports both containerd and
// cri-o, and emits stable JSON — it's the same approach the kubelet
// debug tools take.
//
// The CRI socket is detected by hostscan.collectCRI; this collector
// re-uses that detection so we don't hardcode socket paths.
package hostscan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Container is one row in a Containers snapshot.
type Container struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Image     string            `json:"image"`
	ImageRef  string            `json:"image_ref,omitempty"`  // resolved digest, if crictl returns one
	State     string            `json:"state"`                // CONTAINER_RUNNING / CONTAINER_EXITED / …
	PodName   string            `json:"pod_name,omitempty"`   // io.kubernetes.pod.name
	PodNS     string            `json:"pod_namespace,omitempty"`
	PodUID    string            `json:"pod_uid,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	CreatedAt int64             `json:"created_at,omitempty"` // unix nanoseconds (crictl shape)
}

// Containers is the wire shape POSTed by the agent.
type Containers struct {
	Node       string      `json:"node"`
	ObservedAt time.Time   `json:"observed_at"`
	Runtime    string      `json:"runtime,omitempty"` // containerd | crio | docker
	Socket     string      `json:"socket,omitempty"`  // path used
	Count      int         `json:"count"`
	Items      []Container `json:"items"`
}

// ContainersOptions controls collection.
type ContainersOptions struct {
	HostRoot string // bind-mount prefix; /run + /var/run are read from $ROOT
	NodeName string

	// CrictlBin overrides the crictl binary path (default looks up $PATH).
	CrictlBin string

	// Timeout caps the crictl invocation. Default 10s.
	Timeout time.Duration
}

// crictlListResponse is the subset of `crictl ps -o json` we care about.
// crictl actually returns CRI's runtime.v1.ListContainersResponse JSON
// shape; we model the fields we need and tolerate extras.
type crictlListResponse struct {
	Containers []crictlContainer `json:"containers"`
}

type crictlContainer struct {
	ID           string            `json:"id"`
	PodSandboxID string            `json:"podSandboxId"`
	Metadata     struct {
		Name    string `json:"name"`
		Attempt uint32 `json:"attempt"`
	} `json:"metadata"`
	Image struct {
		Image string `json:"image"`
	} `json:"image"`
	ImageRef    string            `json:"imageRef"`
	State       string            `json:"state"`
	CreatedAt   string            `json:"createdAt"` // crictl emits stringified int64 ns
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
}

// CollectContainers shells out to crictl, parses the result, and
// returns a normalized Containers snapshot. Best-effort: any error
// (crictl missing, socket unreachable, bad JSON) leaves the returned
// Containers with an empty Items slice and the error in err.
func CollectContainers(ctx context.Context, opts ContainersOptions) (Containers, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	bin := opts.CrictlBin
	if bin == "" {
		bin = "crictl"
	}

	c := Containers{
		Node:       opts.NodeName,
		ObservedAt: time.Now().UTC(),
	}
	if c.Node == "" {
		if h, _ := os.Hostname(); h != "" {
			c.Node = h
		}
	}

	socket, runtime := resolveCRISocket(opts.HostRoot)
	c.Socket = socket
	c.Runtime = runtime
	if socket == "" {
		return c, errors.New("no CRI socket detected — runtime-agent can't read container inventory")
	}

	ctx2, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	// `crictl --runtime-endpoint unix://<socket> ps -a -o json` returns
	// every container the runtime knows about, not just Running ones.
	// We pass -q false so labels/annotations are included.
	cmd := exec.CommandContext(ctx2, bin,
		"--runtime-endpoint", "unix://"+socket,
		"ps", "-a", "-o", "json",
	)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return c, fmt.Errorf("crictl ps failed (exit=%d): %s", exitErr.ExitCode(),
				strings.TrimSpace(string(exitErr.Stderr)))
		}
		return c, fmt.Errorf("crictl ps: %w", err)
	}

	var parsed crictlListResponse
	if err := json.Unmarshal(out, &parsed); err != nil {
		return c, fmt.Errorf("parse crictl json: %w", err)
	}

	for _, raw := range parsed.Containers {
		entry := Container{
			ID:       raw.ID,
			Name:     raw.Metadata.Name,
			Image:    raw.Image.Image,
			ImageRef: raw.ImageRef,
			State:    raw.State,
			Labels:   raw.Labels,
		}
		// crictl stamps the pod's namespace/name/uid as labels on every
		// container (the kubelet's standard label set).
		entry.PodName = raw.Labels["io.kubernetes.pod.name"]
		entry.PodNS = raw.Labels["io.kubernetes.pod.namespace"]
		entry.PodUID = raw.Labels["io.kubernetes.pod.uid"]
		// CreatedAt is stringified ns; tolerate empty.
		if raw.CreatedAt != "" {
			// Best-effort parse — crictl emits a stringified int64.
			var ns int64
			_, _ = fmt.Sscanf(raw.CreatedAt, "%d", &ns)
			entry.CreatedAt = ns
		}
		c.Items = append(c.Items, entry)
	}
	c.Count = len(c.Items)
	sort.Slice(c.Items, func(i, j int) bool {
		// Stable order: by namespace/podname/containername.
		a, b := c.Items[i], c.Items[j]
		if a.PodNS != b.PodNS {
			return a.PodNS < b.PodNS
		}
		if a.PodName != b.PodName {
			return a.PodName < b.PodName
		}
		return a.Name < b.Name
	})
	return c, nil
}

// resolveCRISocket walks the same candidate list as collectCRI and
// returns the first socket that exists. Returns ("", "") when none
// are mounted (or HostRoot is wrong).
func resolveCRISocket(hostRoot string) (path, runtime string) {
	for _, c := range candidateCRISockets {
		mounted := c.Path
		if hostRoot != "" {
			mounted = filepath.Join(hostRoot, c.Path)
		}
		st, err := os.Stat(mounted)
		if err != nil {
			continue
		}
		if st.Mode()&os.ModeSocket == 0 {
			continue
		}
		return mounted, c.Runtime
	}
	return "", ""
}
