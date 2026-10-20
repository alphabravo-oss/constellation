package runtime

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
	"k8s.io/apimachinery/pkg/util/validation"
)

// Only trusted API configuration establishes cluster-specific protection. UI
// classification and workload labels never feed this map.
type quarantineProtection map[uuid.UUID]map[string]bool

func parseQuarantineProtection(raw string) (quarantineProtection, error) {
	out := quarantineProtection{}
	if strings.TrimSpace(raw) == "" {
		return out, nil
	}
	var configured map[string][]string
	if err := json.Unmarshal([]byte(raw), &configured); err != nil {
		return nil, err
	}
	for key, names := range configured {
		id, err := uuid.Parse(key)
		if err != nil || id == uuid.Nil {
			return nil, fmt.Errorf("invalid protection cluster UUID")
		}
		out[id] = map[string]bool{}
		for _, ns := range names {
			if len(validation.IsDNS1123Label(ns)) != 0 {
				return nil, fmt.Errorf("invalid protected namespace")
			}
			out[id][ns] = true
		}
	}
	return out, nil
}

func (p quarantineProtection) protects(cluster uuid.UUID, namespace string) bool {
	switch namespace {
	case "kube-system", "kube-public", "kube-node-lease":
		return true
	}
	return p[cluster][namespace]
}

// A missing namespace cannot safely be assumed to mean the default namespace.
// Return an error before any response action or quarantine record is queued.
func checkResponseWorkloadProtection(cluster uuid.UUID, workload string) error {
	namespace, name, ok := strings.Cut(strings.TrimSpace(workload), "/")
	if !ok || name == "" || len(validation.IsDNS1123Label(namespace)) != 0 {
		return fmt.Errorf("response action refused: workload namespace is required")
	}
	protection, err := parseQuarantineProtection(os.Getenv("CONSTELLATION_QUARANTINE_PROTECTED_NAMESPACES"))
	if err != nil {
		return fmt.Errorf("response action refused: protection configuration is invalid")
	}
	if protection.protects(cluster, namespace) {
		return fmt.Errorf("response action refused: protected system namespace %s", namespace)
	}
	return nil
}
