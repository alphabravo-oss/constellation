package aiworkload

import "testing"

func TestDetect_StrongImageBase(t *testing.T) {
	v := Detect(Workload{
		Namespace: "default", Name: "llama",
		Images: []string{"pytorch/pytorch:2.5.0-cuda12"},
	})
	if !v.IsAI || v.Confidence < 0.85 {
		t.Fatalf("expected AI verdict: %+v", v)
	}
}

func TestDetect_GPUResource(t *testing.T) {
	v := Detect(Workload{
		Namespace: "default", Name: "infer",
		Images:    []string{"ghcr.io/example/serve:1.0"},
		Resources: map[string]string{"nvidia.com/gpu": "1"},
	})
	if !v.IsAI {
		t.Fatalf("GPU resource should classify as AI: %+v", v)
	}
}

func TestDetect_TwoWeakSignals(t *testing.T) {
	v := Detect(Workload{
		Images: []string{"ghcr.io/example/text-llm-server:latest", "ghcr.io/example/embedding-service:1.0"},
	})
	if !v.IsAI {
		t.Fatalf("two weak signals should classify: %+v", v)
	}
}

func TestDetect_OneWeakSignalDoesntFire(t *testing.T) {
	v := Detect(Workload{
		Images: []string{"ghcr.io/example/llm-frontend:latest"},
	})
	if v.IsAI {
		t.Fatalf("one weak signal alone should not classify: %+v", v)
	}
}

func TestDetect_ExplicitLabel(t *testing.T) {
	v := Detect(Workload{
		Labels: map[string]string{"ai-workload": "true"},
	})
	if !v.IsAI {
		t.Fatal("explicit label should fire")
	}
}

func TestDetect_NonAIWorkload(t *testing.T) {
	v := Detect(Workload{
		Namespace: "default", Name: "web",
		Images: []string{"nginx:1.27", "ghcr.io/example/api:1.0"},
		Processes: []string{"nginx", "api"},
	})
	if v.IsAI {
		t.Fatalf("plain web stack shouldn't classify as AI: %+v", v)
	}
}
