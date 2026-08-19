// Package aiworkload is the heuristic detector that tags a workload as ai-workload=true
// when it looks like an AI/ML inference or training job. The detector is intentionally
// conservative — false positives clutter the dashboard, false negatives leave AI
// workloads outside the AI-specific runtime policies. We err toward false negatives.
//
// Signals (any one is sufficient unless flagged as weak):
//
//	strong  image base       — pytorch/* | tensorflow/* | huggingface/* | nvidia/*
//	strong  process name     — vllm | triton-inference-server | text-generation-inference
//	strong  resource request — nvidia.com/gpu | amd.com/gpu | inference.kserve.io/*
//	medium  label/annotation — ai-workload=true | mlops/=*
//	weak    image name infix — *-llm-* | *-embedding-* | *-inference-*
//
// Workloads with two weak signals + zero strong tag as ai-workload=true.
// Workloads with one strong signal tag as ai-workload=true.
package aiworkload

import (
	"strings"
)

// Workload is the input shape. Fields are populated by the operator from the K8s
// PodSpec + container runtime info.
type Workload struct {
	Namespace string
	Name      string
	Images    []string            // container images
	Processes []string            // observed process names (from agent)
	Resources map[string]string   // ResourceRequirements aggregated (limits + requests)
	Labels    map[string]string
	Annotations map[string]string
}

// Verdict is what the detector returns.
type Verdict struct {
	IsAI       bool     // true when classification fires
	Confidence float64  // 0..1
	Signals    []string // human-readable signal list (UI surfaces these as chips)
}

// Detect runs the heuristic and returns a Verdict.
func Detect(w Workload) Verdict {
	v := Verdict{}
	strong := 0
	weak := 0

	for _, img := range w.Images {
		l := strings.ToLower(img)
		if hasAnyPrefix(l, "pytorch/", "tensorflow/", "huggingface/", "nvidia/", "nvcr.io/nvidia/", "vllm/") {
			v.Signals = append(v.Signals, "image-base:"+pickBase(l))
			strong++
		}
		if containsAny(l, "llm", "embedding", "inference", "mlops", "stable-diffusion") {
			v.Signals = append(v.Signals, "image-name:"+pickBase(l))
			weak++
		}
	}
	for _, p := range w.Processes {
		l := strings.ToLower(p)
		if containsAny(l, "vllm", "triton-inference-server", "text-generation-inference",
			"ollama", "llamafile", "kserve", "torchserve", "ray::") {
			v.Signals = append(v.Signals, "process:"+p)
			strong++
		}
	}
	for k, val := range w.Resources {
		l := strings.ToLower(k)
		_ = val
		if l == "nvidia.com/gpu" || l == "amd.com/gpu" || strings.HasPrefix(l, "inference.kserve.io/") {
			v.Signals = append(v.Signals, "gpu-resource:"+k)
			strong++
		}
	}
	if v := w.Labels["ai-workload"]; v == "true" {
		strong++
	}
	if v := w.Annotations["mlops.k8s/managed-by"]; v != "" {
		strong++
	}

	v.IsAI = strong >= 1 || weak >= 2
	switch {
	case strong >= 2:
		v.Confidence = 1.0
	case strong == 1:
		v.Confidence = 0.85
	case weak >= 2:
		v.Confidence = 0.6
	}
	return v
}

func hasAnyPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func containsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func pickBase(image string) string {
	// strip registry prefix + tag suffix for the chip text.
	s := image
	if i := strings.LastIndex(s, "/"); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.Index(s, ":"); i > 0 {
		s = s[:i]
	}
	return s
}
