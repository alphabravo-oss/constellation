package scanner

import (
	"slices"
	"testing"
)

func TestRegistryEnvironmentInsecureUsesSyftAndGrypeEnv(t *testing.T) {
	t.Parallel()
	env := RegistryEnvironment(ScanOptions{Insecure: true})
	for _, want := range []string{
		"SYFT_REGISTRY_INSECURE_SKIP_TLS_VERIFY=true", "SYFT_REGISTRY_INSECURE_USE_HTTP=true",
		"GRYPE_REGISTRY_INSECURE_SKIP_TLS_VERIFY=true", "GRYPE_REGISTRY_INSECURE_USE_HTTP=true",
	} {
		if !slices.Contains(env, want) {
			t.Fatalf("missing %s", want)
		}
	}
	if slices.Contains(RegistryEnvironment(ScanOptions{}), "SYFT_REGISTRY_INSECURE_USE_HTTP=true") {
		t.Fatal("secure scans must not enable plain HTTP")
	}
}
