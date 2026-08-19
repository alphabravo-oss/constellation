package dp

import (
	"context"
	"testing"
)

// TestContainerEnforceProvider: only Enforce-flagged eth0 targets become
// EnforceTargets; lo/proxymesh (PMAC set) and non-enforce workloads are excluded.
func TestContainerEnforceProvider(t *testing.T) {
	tap := &ContainerTapProvider{
		procRoot:       "/proc",
		listContainers: func(ctx context.Context) ([]RunningContainer, error) {
			return []RunningContainer{
				{ID: "enf", PodName: "web", PID: 10, WAF: true, Enforce: true},
				{ID: "mon", PodName: "api", PID: 20, WAF: true, Enforce: false},
			}, nil
		},
		readIface: func(netns string) (string, string, []string, error) {
			switch netns {
			case "/proc/10/ns/net":
				return "eth0", "aa:aa:aa:aa:aa:aa", nil, nil
			default:
				return "eth0", "bb:bb:bb:bb:bb:bb", nil, nil
			}
		},
		meshDetect: func(int) bool { return false },
	}
	ep := NewContainerEnforceProvider(tap)
	got, err := ep.Desired(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].EPMAC != "aa:aa:aa:aa:aa:aa" {
		t.Fatalf("enforce targets = %+v; want only the Enforce-flagged eth0 (aa..)", got)
	}
}
