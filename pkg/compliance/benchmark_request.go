package compliance

import "strings"

// NormalizeBenchProfile retains the runner/API aliases while returning only
// the two profiles supported by the installed benchmark executables.
func NormalizeBenchProfile(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "kube-bench", "kubebench":
		return "kube-bench", true
	case "docker-bench", "docker":
		return "docker-bench", true
	default:
		return "", false
	}
}

// ValidBenchmarkID accepts distro/version pins, including custom installed
// benchmark names. Pins are identifiers, never paths, options or shell text.
// Empty selects the upstream executable's auto-detection behavior.
func ValidBenchmarkID(value string) bool {
	if len(value) > 128 {
		return false
	}
	for index, r := range value {
		alphaNumeric := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
		if !alphaNumeric && (index == 0 || r != '-' && r != '_' && r != '.') {
			return false
		}
	}
	return true
}
