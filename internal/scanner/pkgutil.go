package scanner

// Package-identity helpers shared across the scanner package (Syft package
// normalization, base-image detection, distro canonicalization, PURL parsing).
//
// These formerly lived alongside the constellation-vulndb bundle matcher; that
// matcher has been removed (Grype's package matcher now fills the canonical
// package-match slot), but these pure helpers are still consumed by syft.go and
// baseimage.go, so they live here with no external dependency.

import (
	"net/url"
	"strings"
)

func appendUnique(values []string, next string) []string {
	if strings.TrimSpace(next) == "" {
		return values
	}
	for _, value := range values {
		if value == next {
			return values
		}
	}
	return append(values, next)
}

func trimmedUniqueStrings(values []string) []string {
	out := []string{}
	for _, value := range values {
		out = appendUnique(out, strings.TrimSpace(value))
	}
	return out
}

func imageReferenceHints(ref string) (repository, tag string) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", ""
	}
	if at := strings.Index(ref, "@"); at >= 0 {
		ref = ref[:at]
	}
	lastSlash := strings.LastIndex(ref, "/")
	lastColon := strings.LastIndex(ref, ":")
	if lastColon > lastSlash {
		return strings.TrimSpace(ref[:lastColon]), strings.TrimSpace(ref[lastColon+1:])
	}
	return ref, ""
}

func isOSPackage(ecosystem, purlType, namespaceKind string) bool {
	namespaceKind = strings.ToLower(strings.TrimSpace(namespaceKind))
	if namespaceKind != "" && namespaceKind != "os" {
		return false
	}
	for _, value := range []string{purlType, ecosystem} {
		if osPackageTypes[strings.ToLower(strings.TrimSpace(value))] {
			return true
		}
	}
	return namespaceKind == "os"
}

var osPackageTypes = map[string]bool{
	"apk": true,
	"deb": true,
	"rpm": true,
}

func canonicalDistroName(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "amzn", "amazonlinux":
		return "amazon"
	case "ol", "oraclelinux":
		return "oracle"
	case "redhat":
		return "rhel"
	case "opensuse", "opensuse-leap", "sles":
		return "suse"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

type parsedPURL struct {
	Type       string
	Namespace  string
	Name       string
	Version    string
	Base       string
	Qualifiers map[string]string
}

func parsePURL(raw string) parsedPURL {
	raw = strings.TrimSpace(raw)
	parsed := parsedPURL{Qualifiers: map[string]string{}}
	if !strings.HasPrefix(strings.ToLower(raw), "pkg:") {
		return parsed
	}

	body := raw[len("pkg:"):]
	if idx := strings.Index(body, "#"); idx >= 0 {
		body = body[:idx]
	}
	qualifierText := ""
	if idx := strings.Index(body, "?"); idx >= 0 {
		qualifierText = body[idx+1:]
		body = body[:idx]
	}
	typ, packagePath, ok := strings.Cut(body, "/")
	if !ok {
		return parsed
	}
	typ = strings.ToLower(strings.TrimSpace(typ))
	packagePath = strings.Trim(packagePath, "/")
	if typ == "" || packagePath == "" {
		return parsed
	}

	packagePathWithoutVersion := packagePath
	if idx := strings.LastIndex(packagePathWithoutVersion, "@"); idx >= 0 {
		parsed.Version = unescapePURLPart(packagePathWithoutVersion[idx+1:])
		packagePathWithoutVersion = packagePathWithoutVersion[:idx]
	}
	parts := strings.Split(packagePathWithoutVersion, "/")
	if len(parts) == 0 {
		return parsed
	}
	name := unescapePURLPart(parts[len(parts)-1])
	namespace := ""
	if len(parts) > 1 {
		namespace = unescapePURLPart(strings.Join(parts[:len(parts)-1], "/"))
	}

	parsed.Type = typ
	parsed.Namespace = namespace
	parsed.Name = name
	parsed.Base = "pkg:" + typ + "/" + packagePathWithoutVersion
	parsed.Qualifiers = parsePURLQualifiers(qualifierText)
	return parsed
}

func parsePURLQualifiers(raw string) map[string]string {
	out := map[string]string{}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return out
	}
	for key, value := range values {
		if len(value) == 0 {
			continue
		}
		out[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value[0])
	}
	return out
}

func unescapePURLPart(value string) string {
	got, err := url.PathUnescape(value)
	if err != nil {
		return value
	}
	return got
}
