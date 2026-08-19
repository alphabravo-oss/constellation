package imageid

import "strings"

type Identity struct {
	Raw        string
	Normalized string
	Repository string
	Tag        string
	Digest     string
}

func Parse(ref string) Identity {
	raw := strings.TrimSpace(ref)
	if strings.HasPrefix(raw, "sha256:") {
		return Identity{
			Raw:        raw,
			Normalized: raw,
			Digest:     raw,
		}
	}
	base := raw
	digest := ""
	if idx := strings.LastIndex(base, "@"); idx >= 0 {
		digest = strings.TrimSpace(base[idx+1:])
		base = base[:idx]
		if !strings.HasPrefix(digest, "sha256:") {
			digest = ""
		}
	}

	tag := ""
	repository := base
	if colon := strings.LastIndex(repository, ":"); colon > strings.LastIndex(repository, "/") {
		tag = repository[colon+1:]
		repository = repository[:colon]
	}
	repository = normalizeRepository(repository)
	if tag == "" && digest == "" && repository != "" {
		tag = "latest"
	}

	normalized := repository
	if tag != "" {
		normalized += ":" + tag
	}
	if digest != "" {
		normalized += "@" + digest
	}
	return Identity{
		Raw:        raw,
		Normalized: normalized,
		Repository: repository,
		Tag:        tag,
		Digest:     digest,
	}
}

func normalizeRepository(repository string) string {
	repository = strings.TrimSpace(repository)
	if repository == "" {
		return ""
	}
	parts := strings.Split(repository, "/")
	first := parts[0]
	hasRegistry := strings.Contains(first, ".") || strings.Contains(first, ":") || first == "localhost"
	if !hasRegistry {
		if len(parts) == 1 {
			return "docker.io/library/" + repository
		}
		return "docker.io/" + repository
	}
	return repository
}
