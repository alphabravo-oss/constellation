package neuvector

import (
	"errors"
	"io"
	"net/url"
	"reflect"
	"regexp"
	"strings"

	"github.com/alphabravocompany/constellation/pkg/vulnprofile"
	"gopkg.in/yaml.v3"
)

// RemainingFamilies contains only reviewed metadata and exactly representable
// suppression rules. Unsupported diagnostics never contain raw source values.
type RemainingFamilies struct {
	VulnerabilityProfiles []TargetVulnerabilityProfile `json:"vulnerability_profiles"`
	Registries            []TargetRegistry             `json:"registries"`
	Unsupported           []UnsupportedObject          `json:"unsupported"`
}

type TargetVulnerabilityProfile struct {
	Name         string                  `json:"name"`
	Description  string                  `json:"description"`
	Active       bool                    `json:"active"`
	Entries      []vulnprofile.Entry     `json:"entries"`
	DomainScope  vulnprofile.DomainScope `json:"domain_scope"`
	ImportedFrom map[string]string       `json:"imported_from"`
}

// TargetRegistry must be persisted with manual cadence and auth_kind=none.
// Credentials and source scan schedules are never transferred.
type TargetRegistry struct {
	Name                string            `json:"name"`
	Kind                string            `json:"kind"`
	Endpoint            string            `json:"endpoint"`
	ImageGlobs          []string          `json:"image_globs"`
	ImportedFrom        map[string]string `json:"imported_from"`
	CredentialsRequired bool              `json:"credentials_required"`
}

type remainingSource struct {
	profiles, registries []*yaml.Node
	unsupported          []UnsupportedObject
}

func redactedParseError() error {
	return errors.New("neuvector: invalid export structure or syntax (source values REDACTED)")
}

// Decode into nodes first: unknown CRDs must not be decoded as security rules,
// and YAML type errors must not disclose secret scalar values.
func parseExportDocuments(raw []byte) ([]*yaml.Node, error) {
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	var docs []*yaml.Node
	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, redactedParseError()
		}
		if len(doc.Content) == 0 {
			continue
		}
		node := doc.Content[0]
		if node.Tag == "!!null" {
			continue
		}
		if node.Kind != yaml.MappingNode {
			return nil, redactedParseError()
		}
		// This also rejects duplicate mapping keys and invalid YAML aliases.
		var check map[string]any
		if err := node.Decode(&check); err != nil {
			return nil, redactedParseError()
		}
		if len(node.Content) > 0 {
			docs = append(docs, node)
		}
	}
	if len(docs) == 0 {
		return nil, errors.New("neuvector: empty export")
	}
	return docs, nil
}

func field(node *yaml.Node, name string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == name {
			return node.Content[i+1]
		}
	}
	return nil
}

func scalar(node *yaml.Node) string {
	if node == nil || node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		return ""
	}
	return node.Value
}

func legacyKind(kind string) bool {
	if strings.EqualFold(strings.TrimSpace(kind), "NvClusterSecurityRule") || strings.EqualFold(strings.TrimSpace(kind), "NvClusterSecurityRuleList") {
		return true
	}
	return isNetworkSecurityRuleKind(kind) || isGroupDefinitionKind(kind) || dpiCategoryFromKind(kind) != ""
}

var legacyFields = func() map[string]bool {
	out := map[string]bool{"apiVersion": true}
	t := reflect.TypeOf(SourceExport{})
	for i := 0; i < t.NumField(); i++ {
		out[t.Field(i).Tag.Get("yaml")] = true
	}
	return out
}()

func isVulnerabilityEnvelope(key string, node *yaml.Node) bool {
	if key != "profile" && key != "profiles" && key != "config" {
		return false
	}
	if field(node, "entries") != nil {
		return true
	}
	if node != nil && node.Kind == yaml.SequenceNode {
		for _, item := range node.Content {
			if field(item, "entries") != nil {
				return true
			}
		}
	}
	return false
}

func isRegistryEnvelope(key string, node *yaml.Node) bool {
	return key == "config" && field(node, "registry_type") != nil
}

func unknownGenericEnvelope(key string, node *yaml.Node) bool {
	if key != "config" && key != "configs" && key != "profile" && key != "profiles" {
		return false
	}
	if isVulnerabilityEnvelope(key, node) || isRegistryEnvelope(key, node) {
		return false
	}
	if node != nil && node.Kind == yaml.SequenceNode {
		for _, item := range node.Content {
			if unknownGenericEnvelope(key, item) {
				return true
			}
		}
		return false
	}
	if key == "config" || key == "configs" {
		return !onlyFields(node, "name comment cfg_type policy_mode profile_mode kind learned criteria") || (field(node, "criteria") == nil && field(node, "policy_mode") == nil && field(node, "profile_mode") == nil)
	}
	return !onlyFields(node, "group name mode cfg_type description filters rules") || (field(node, "filters") == nil && field(node, "rules") == nil && field(node, "group") == nil)
}

func legacyExportNode(node *yaml.Node) *yaml.Node {
	out := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	kind := strings.ToLower(scalar(field(node, "kind")))
	if kind != "" && kind != "list" && !legacyKind(kind) {
		return out
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if !legacyFields[key.Value] || isVulnerabilityEnvelope(key.Value, value) || isRegistryEnvelope(key.Value, value) || unknownGenericEnvelope(key.Value, value) {
			continue
		}
		if key.Value == "items" && value.Kind == yaml.SequenceNode {
			items := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
			for _, item := range value.Content {
				clean := legacyExportNode(item)
				if len(clean.Content) > 0 {
					items.Content = append(items.Content, clean)
				}
			}
			value = items
		}
		out.Content = append(out.Content, key, value)
	}
	return out
}

func redactedUnsupported(kind, reason, suggestion string) UnsupportedObject {
	return UnsupportedObject{Kind: kind, Name: "REDACTED", Reason: reason, Suggestion: suggestion,
		Source: map[string]any{"redacted": true}}
}

func remainingUnsupportedKind(key string) string {
	switch strings.ToLower(key) {
	case "users", "user":
		return "user"
	case "roles", "role":
		return "role"
	case "user_roles", "role_mappings", "mappings", "domains", "user_role_domains":
		return "role_mapping"
	case "compliance", "compliance_profiles", "compliance_profile", "nvcomplianceprofile", "nvcomplianceprofilelist":
		return "compliance"
	case "routing", "routes", "webhooks", "syslog", "notifications", "notification", "response_routes":
		return "routing"
	case "auth", "authentication", "servers", "ldap", "saml", "oidc", "auth_servers":
		return "authentication"
	case "tokens", "token", "api_tokens", "api_token", "api_keys", "apikeys", "apikey", "password", "secret", "secrets":
		return "credentials"
	case "federation", "federated", "fed", "federation_config":
		return "federation"
	default:
		return "unknown"
	}
}

func collectRemainingSource(raw []byte) (remainingSource, error) {
	docs, err := parseExportDocuments(raw)
	if err != nil {
		return remainingSource{}, err
	}
	out := remainingSource{}
	add := func(dst *[]*yaml.Node, node *yaml.Node) {
		if node != nil && node.Kind == yaml.SequenceNode {
			*dst = append(*dst, node.Content...)
		} else {
			*dst = append(*dst, node)
		}
	}
	unsupported := func(key string, node *yaml.Node) {
		n := 1
		if node != nil && node.Kind == yaml.SequenceNode {
			n = len(node.Content)
			if n == 0 {
				n = 1
			}
		}
		for i := 0; i < n; i++ {
			out.unsupported = append(out.unsupported, redactedUnsupported(remainingUnsupportedKind(key),
				"Source object is unsupported; all source values are REDACTED.",
				"Recreate through the appropriate reviewed workflow and reissue credentials or tokens; identities, privileges, credentials and federation are never imported."))
		}
	}
	var visit func(*yaml.Node)
	visit = func(node *yaml.Node) {
		kind := strings.ToLower(scalar(field(node, "kind")))
		if kind == "nvvulnerabilityprofile" {
			spec := field(node, "spec")
			profile := field(spec, "profile")
			if profile == nil {
				profile = spec
			} else if !onlyFields(spec, "profile") {
				// Unknown profile-level constraints could narrow suppression.
				profile = nil
			}
			add(&out.profiles, profile)
			for i := 0; i+1 < len(node.Content); i += 2 {
				key := node.Content[i].Value
				switch key {
				case "apiVersion", "kind", "metadata", "spec":
					continue
				}
				unsupported(key, node.Content[i+1])
			}
			return
		}
		if kind == "nvvulnerabilityprofilelist" || kind == "list" || (legacyKind(kind) && strings.HasSuffix(kind, "list")) {
			items := field(node, "items")
			if items == nil || items.Kind != yaml.SequenceNode {
				unsupported("unknown", node)
				return
			}
			for _, item := range items.Content {
				visit(item)
			}
			for i := 0; i+1 < len(node.Content); i += 2 {
				key := node.Content[i].Value
				switch key {
				case "apiVersion", "kind", "metadata", "items":
					continue
				}
				unsupported(key, node.Content[i+1])
			}
			return
		}
		if kind != "" && !legacyKind(kind) {
			unsupported(kind, node)
			return
		}
		if node == nil || node.Kind != yaml.MappingNode {
			unsupported("unknown", node)
			return
		}
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i].Value, node.Content[i+1]
			switch {
			case unknownGenericEnvelope(key, value):
				unsupported(key, value)
			case key == "vulnerability_profiles" || key == "vulnerability_profile" || isVulnerabilityEnvelope(key, value):
				add(&out.profiles, value)
			case key == "vulnerability":
				if !onlyFields(value, "profile profiles") && (field(value, "profile") != nil || field(value, "profiles") != nil) {
					add(&out.profiles, nil)
				} else if p := field(value, "profiles"); p != nil {
					add(&out.profiles, p)
				} else if p := field(value, "profile"); p != nil {
					add(&out.profiles, p)
				} else {
					add(&out.profiles, value)
				}
			case key == "registries" || key == "registry" || isRegistryEnvelope(key, value):
				add(&out.registries, value)
			case key == "items":
				if value.Kind == yaml.SequenceNode {
					for _, item := range value.Content {
						visit(item)
					}
				} else {
					unsupported(key, value)
				}
			case !legacyFields[key]:
				unsupported(key, value)
			}
		}
	}
	for _, doc := range docs {
		visit(doc)
	}
	return out, nil
}

// ConvertRemainingFamilies converts an exact, deliberately narrow vulnerability
// subset and registry metadata. It never returns source credentials or privileges.
func ConvertRemainingFamilies(raw []byte) (RemainingFamilies, error) {
	source, err := collectRemainingSource(raw)
	if err != nil {
		return RemainingFamilies{}, err
	}
	out := RemainingFamilies{VulnerabilityProfiles: []TargetVulnerabilityProfile{}, Registries: []TargetRegistry{}, Unsupported: source.unsupported}
	if out.Unsupported == nil {
		out.Unsupported = []UnsupportedObject{}
	}
	for _, node := range source.profiles {
		profile, ok := convertVulnerabilityProfile(node)
		if !ok {
			out.Unsupported = append(out.Unsupported, redactedUnsupported("vulnerability_profile",
				"Entire vulnerability profile rejected: its suppression semantics cannot be represented exactly.",
				"Review reserved/recent rules, image or domain constraints, federation and unknown fields manually."))
			continue
		}
		out.VulnerabilityProfiles = append(out.VulnerabilityProfiles, profile)
	}
	for _, node := range source.registries {
		registry, ok := convertRegistry(node)
		if !ok {
			out.Unsupported = append(out.Unsupported, redactedUnsupported("registry",
				"Registry metadata requires a supported adapter, a name and a clean HTTPS endpoint; source values are REDACTED.",
				"Recreate unsupported settings manually and reissue credentials."))
			continue
		}
		out.Registries = append(out.Registries, registry)
		if registry.CredentialsRequired {
			out.Unsupported = append(out.Unsupported, redactedUnsupported("registry_credentials",
				"Registry credentials were omitted and must be reissued.",
				"Keep auth_kind=none and manual cadence until fresh credentials are configured."))
		}
		if registryHasSettings(node) {
			out.Unsupported = append(out.Unsupported, redactedUnsupported("registry_settings",
				"Registry filters, scan schedules and non-metadata settings are not migrated.",
				"Review image scope and scan settings manually before enabling scans; use manual cadence."))
		}
	}
	return out, nil
}

func onlyFields(node *yaml.Node, allowed string) bool {
	if node == nil || node.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if !strings.Contains(" "+allowed+" ", " "+node.Content[i].Value+" ") {
			return false
		}
	}
	return true
}

func convertVulnerabilityProfile(node *yaml.Node) (TargetVulnerabilityProfile, bool) {
	if !onlyFields(node, "name description entries cfg_type active") {
		return TargetVulnerabilityProfile{}, false
	}
	var source struct {
		Name        string `yaml:"name"`
		Description string `yaml:"description"`
		CfgType     string `yaml:"cfg_type"`
		Active      *bool  `yaml:"active"`
		Entries     []struct {
			Name    string   `yaml:"name"`
			Comment string   `yaml:"comment"`
			Days    uint     `yaml:"days"`
			Domains []string `yaml:"domains"`
			Images  []string `yaml:"images"`
		} `yaml:"entries"`
	}
	if node.Decode(&source) != nil || strings.TrimSpace(source.Name) == "" || !localCfgType(source.CfgType) {
		return TargetVulnerabilityProfile{}, false
	}
	entries := field(node, "entries")
	if entries == nil || entries.Kind != yaml.SequenceNode {
		return TargetVulnerabilityProfile{}, false
	}
	for _, entry := range entries.Content {
		if !onlyFields(entry, "id name comment days domains images") {
			return TargetVulnerabilityProfile{}, false
		}
	}
	out := TargetVulnerabilityProfile{Name: source.Name, Description: source.Description, Active: true,
		Entries: []vulnprofile.Entry{}, ImportedFrom: map[string]string{"source": "neuvector", "source_kind": "vulnerability_profile"}}
	if source.Active != nil {
		out.Active = *source.Active
	}
	for _, entry := range source.Entries {
		// NeuVector's recent rules use different boundary/unknown-date behavior.
		// Its domain/image regexes do not share the target's scope/glob semantics.
		if entry.Name == "" || strings.HasPrefix(entry.Name, "_") || entry.Days != 0 || len(entry.Domains) != 0 || len(entry.Images) != 0 {
			return TargetVulnerabilityProfile{}, false
		}
		pattern := "(?i)^" + regexp.QuoteMeta(entry.Name) + "$"
		if strings.Contains(entry.Name, "*") {
			// Source wildcard names use an unanchored regex, preserving all other
			// regex metacharacters. Do not anchor or escape this branch.
			pattern = "(?i)" + strings.ReplaceAll(entry.Name, "*", ".*")
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return TargetVulnerabilityProfile{}, false
		}
		out.Entries = append(out.Entries, vulnprofile.Entry{Name: entry.Name, NameRegex: pattern, Action: vulnprofile.ActionSuppress, Comment: entry.Comment})
	}
	return out, true
}

func localCfgType(value string) bool {
	switch value {
	case "", "user_created", "ground", "learned":
		return true
	}
	return false
}

func convertRegistry(node *yaml.Node) (TargetRegistry, bool) {
	if node == nil || node.Kind != yaml.MappingNode {
		return TargetRegistry{}, false
	}
	name := scalar(field(node, "name"))
	endpoint := scalar(field(node, "registry"))
	if endpoint == "" {
		endpoint = scalar(field(node, "endpoint"))
	}
	kind := scalar(field(node, "registry_type"))
	if kind == "" {
		kind = scalar(field(node, "kind"))
	}
	kinds := map[string]string{
		"docker registry": "generic-v2", "docker hub": "docker-hub", "amazon ecr registry": "ecr",
		"azure container registry": "acr", "google container registry": "gcr", "jfrog artifactory": "jfrog",
		"openshift registry": "openshift", "red hat/openshift registry": "openshift", "sonatype nexus": "nexus",
		"gitlab": "gitlab", "ibm cloud container registry": "ibmcloud", "harbor registry": "harbor", "github container registry": "ghcr",
		"docker-hub": "docker-hub", "ghcr": "ghcr", "ecr": "ecr", "gcr": "gcr", "acr": "acr", "quay": "quay",
		"harbor": "harbor", "jfrog": "jfrog", "ibmcloud": "ibmcloud", "openshift": "openshift", "nexus": "nexus", "generic-v2": "generic-v2",
	}
	kind = kinds[strings.ToLower(kind)]
	if cfg := field(node, "cfg_type"); cfg != nil && (cfg.Kind != yaml.ScalarNode || cfg.Tag != "!!str") {
		return TargetRegistry{}, false
	}
	u, err := url.Parse(endpoint)
	if strings.TrimSpace(name) == "" || kind == "" || err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(endpoint, "#") || u.Opaque != "" || !localCfgType(scalar(field(node, "cfg_type"))) {
		return TargetRegistry{}, false
	}
	credentials := registryCredentialsPresent(node)
	return TargetRegistry{Name: name, Kind: kind, Endpoint: endpoint, ImageGlobs: []string{}, CredentialsRequired: credentials,
		ImportedFrom: map[string]string{"source": "neuvector", "source_kind": "registry", "cadence": "manual", "auth_kind": "none"}}, true
}

func registryCredentialField(key string) bool {
	key = strings.ToLower(key)
	if strings.Contains(key, "password") || strings.Contains(key, "secret") || strings.Contains(key, "token") || strings.Contains(key, "credential") {
		return true
	}
	switch key {
	case "auth", "auth_kind", "username", "password", "auth_token", "auth_with_token", "aws_key", "gcr_key", "gitlab_private_token", "credentials", "token", "secret", "client_secret", "private_key", "access_key", "secret_key", "api_key", "apikey", "service_account_json":
		return true
	}
	return false
}

func registryCredentialsPresent(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			if registryCredentialField(node.Content[i].Value) || registryCredentialsPresent(node.Content[i+1]) {
				return true
			}
		}
	} else if node.Kind == yaml.SequenceNode {
		for _, item := range node.Content {
			if registryCredentialsPresent(item) {
				return true
			}
		}
	}
	return false
}

func registryHasSettings(node *yaml.Node) bool {
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i].Value
		if registryCredentialField(key) {
			continue
		}
		switch key {
		case "name", "registry", "endpoint", "registry_type", "kind", "cfg_type":
			continue
		}
		return true
	}
	return false
}
