// Image-name parsing + admission-log aggregation, ported from
// neuvector/controller/rest/admwebhook.go (parseReqImageName + aggrLogsCache).
package admission

import (
	"fmt"
	"strings"
	"sync"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
)

// AggregationWindow is the sliding window for deduplicating denial events
// (NeuVector ships 8 minutes; preserved here for parity).
const AggregationWindow = 8 * time.Minute

// defaultRegistries is the canonical list of registries treated as the docker default.
var defaultRegistries = map[string]struct{}{
	"https://docker.io/":           {},
	"https://index.docker.io/":     {},
	"https://registry-1.docker.io/": {},
}

// ImageRef is a parsed container image reference.
type ImageRef struct {
	Registry string // protocol-prefixed, trailing slash, lowercase
	Repo     string
	Tag      string
	Digest   string // present when image was @sha256:... pinned
	Raw      string
}

// ContainerImage is one container-from-podspec ref, including sidecars and inits.
type ContainerImage struct {
	Name       string // container name from the pod spec
	Role       string // "init" | "container" | "ephemeral"
	Image      ImageRef
}

// ParseReqImageName parses an image string in the same shape NeuVector's
// parseReqImageName does. The transcription preserves the original quirks:
//
//   - protocol prefix (http(s)://) is stripped + propagated to Registry
//   - bare "ubuntu" → docker.io + library/ubuntu + latest
//   - "docker.io/x" → docker.io + library/x
//   - host:port/path → registry "https://host:port/", repo "path"
//   - foo@sha256:... → digest pinned ref
func ParseReqImageName(image string) ImageRef {
	out := ImageRef{Raw: image}
	imgName := image
	protocol := "https://"
	if idx := strings.Index(imgName, "://"); idx != -1 {
		protocol = imgName[:idx+3]
		imgName = imgName[idx+3:]
	}

	foundRegistry := false
	ss := strings.Split(imgName, "/")
	if len(ss) > 1 {
		// see splitDockerDomain() in github.com/docker/distribution
		if strings.ContainsAny(ss[0], ".:") || ss[0] == "localhost" {
			foundRegistry = true
			imgName = strings.Join(ss[1:], "/")
		}
	}
	if !foundRegistry {
		out.Registry = "https://docker.io/"
		if len(ss) == 1 {
			imgName = "library/" + imgName
		}
	} else {
		if ss[0] == "docker.io" {
			out.Registry = "https://docker.io/"
			if len(ss) == 2 {
				imgName = "library/" + imgName
			}
		} else {
			out.Registry = protocol + strings.ToLower(ss[0]) + "/"
			if len(ss) == 2 {
				if _, ok := defaultRegistries[out.Registry]; ok {
					imgName = "library/" + imgName
				}
			}
		}
	}

	// digest? — split @sha256:... first.
	if idx := strings.Index(imgName, "@"); idx != -1 {
		out.Repo = imgName[:idx]
		out.Digest = imgName[idx+1:]
		// repo may still carry :tag before the @
		if colon := strings.Index(out.Repo, ":"); colon != -1 {
			out.Tag = out.Repo[colon+1:]
			out.Repo = out.Repo[:colon]
		}
		return out
	}
	if idx := strings.LastIndex(imgName, ":"); idx != -1 {
		out.Repo = imgName[:idx]
		out.Tag = imgName[idx+1:]
		return out
	}
	out.Repo = imgName
	out.Tag = "latest"
	return out
}

// ParseAdmissionContainers extracts every container, init container, and ephemeral
// container image ref from an AdmissionRequest's Pod object. Returns nil + error
// when the request isn't a Pod or fails to decode.
func ParseAdmissionContainers(req *admissionv1.AdmissionRequest) ([]ContainerImage, error) {
	if req == nil {
		return nil, fmt.Errorf("admission: nil request")
	}
	if req.Kind.Kind != "Pod" {
		return nil, nil
	}
	pod := &corev1.Pod{}
	if err := decodePod(req.Object.Raw, pod); err != nil {
		return nil, err
	}
	out := []ContainerImage{}
	for _, c := range pod.Spec.InitContainers {
		out = append(out, ContainerImage{Name: c.Name, Role: "init", Image: ParseReqImageName(c.Image)})
	}
	for _, c := range pod.Spec.Containers {
		out = append(out, ContainerImage{Name: c.Name, Role: "container", Image: ParseReqImageName(c.Image)})
	}
	for _, c := range pod.Spec.EphemeralContainers {
		out = append(out, ContainerImage{Name: c.Name, Role: "ephemeral", Image: ParseReqImageName(c.EphemeralContainerCommon.Image)})
	}
	return out, nil
}

// ----------------------------- aggregation cache ----------------------------

// AggregatedEntry is one folded admission denial.
type AggregatedEntry struct {
	OwnerUID    string
	ImageDigest string
	Image       string
	Occurrences int
	FirstAt     time.Time
	LastAt      time.Time
	Reason      string
	Decision    string // "denied" | "allowed"
}

// AggregationCache deduplicates identical admission events by (owner UID, image digest)
// over a sliding window (8 min default). NeuVector parity from admwebhook.go.
type AggregationCache struct {
	window time.Duration
	now    func() time.Time
	mu     sync.Mutex
	items  map[string]*AggregatedEntry
}

// NewAggregationCache constructs a cache with the given window. Pass 0 to use the
// NeuVector-parity default (8 minutes).
func NewAggregationCache(window time.Duration) *AggregationCache {
	if window <= 0 {
		window = AggregationWindow
	}
	return &AggregationCache{
		window: window,
		now:    time.Now,
		items:  map[string]*AggregatedEntry{},
	}
}

// SetClock injects a clock (tests).
func (c *AggregationCache) SetClock(now func() time.Time) { c.now = now }

// Observe records one denial. Returns the aggregated entry IF this observation crosses
// the window boundary (i.e., a flush is appropriate); otherwise returns nil and the
// caller should suppress the event. The intent matches NeuVector's emit-one-per-window
// behavior: the first event in a window opens it; subsequent events inside the window
// merge; once the window elapses, the next call returns the folded summary.
func (c *AggregationCache) Observe(ownerUID, imageDigest, image, reason, decision string) *AggregatedEntry {
	key := ownerUID + "." + imageDigest
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	existing, ok := c.items[key]
	if !ok {
		c.items[key] = &AggregatedEntry{
			OwnerUID: ownerUID, ImageDigest: imageDigest, Image: image,
			Occurrences: 1, FirstAt: now, LastAt: now, Reason: reason, Decision: decision,
		}
		return c.items[key] // open the window; emit once now
	}
	// inside the window — merge & suppress
	if now.Sub(existing.FirstAt) <= c.window {
		existing.Occurrences++
		existing.LastAt = now
		return nil
	}
	// window elapsed — flush the old entry and reopen with this observation.
	flushed := *existing
	c.items[key] = &AggregatedEntry{
		OwnerUID: ownerUID, ImageDigest: imageDigest, Image: image,
		Occurrences: 1, FirstAt: now, LastAt: now, Reason: reason, Decision: decision,
	}
	return &flushed
}

// Sweep drains any entry whose window has elapsed without further events. Callers
// typically run this on a 1-minute tick.
func (c *AggregationCache) Sweep() []AggregatedEntry {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	out := []AggregatedEntry{}
	for k, e := range c.items {
		if now.Sub(e.FirstAt) > c.window {
			out = append(out, *e)
			delete(c.items, k)
		}
	}
	return out
}

// decodePod is a tiny wrapper so the unit test can intercept the decode path.
var decodePod = func(raw []byte, out *corev1.Pod) error {
	return jsonUnmarshal(raw, out)
}
