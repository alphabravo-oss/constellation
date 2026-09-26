package syscfg

import (
	"encoding/json"
	"reflect"
	"strings"

	"github.com/google/uuid"
)

type Source string

const (
	SourceDefault              Source = "default"
	SourceEnvironmentBootstrap Source = "environment_bootstrap"
	SourceDatabase             Source = "database"
)

type FieldProvenance struct {
	Source   Source `json:"source"`
	Redacted bool   `json:"redacted"`
}

type configOrigin struct {
	source Source
	value  any
}

type ProviderApplied struct {
	Component string `json:"component"`
	Scope     string `json:"scope"`
	Revision  *int64 `json:"revision"`
	Status    string `json:"status"`
}

func (p *Provider) Applied(orgID uuid.UUID, targetRevision int64) ProviderApplied {
	result := ProviderApplied{Component: "system_config_provider", Scope: "serving_replica", Status: "unavailable"}
	if p == nil {
		return result
	}
	p.mu.RLock()
	current, ok := p.cache[orgID]
	p.mu.RUnlock()
	if !ok {
		return result
	}
	result.Revision = &current.rev
	result.Status = "current"
	if current.rev < targetRevision {
		result.Status = "behind"
	} else if current.rev > targetRevision {
		result.Status = "ahead"
	}
	return result
}

func (c Config) Provenance() map[string]FieldProvenance {
	values := configValues(c)
	redacted := configValues(c.Redacted())
	result := make(map[string]FieldProvenance, len(values))
	for field, value := range values {
		source := SourceDatabase
		if origin, ok := c.origins[field]; ok && reflect.DeepEqual(origin.value, value) {
			source = origin.source
		}
		result[field] = FieldProvenance{Source: source, Redacted: !reflect.DeepEqual(value, redacted[field])}
	}
	return result
}

func trackConfig(cfg Config, sources map[string]Source, fallback Source) Config {
	values := configValues(cfg)
	cfg.origins = make(map[string]configOrigin, len(values))
	for field, value := range values {
		source := fallback
		if explicit, ok := sources[field]; ok {
			source = explicit
		}
		cfg.origins[field] = configOrigin{source: source, value: value}
	}
	return cfg
}

func configValues(cfg Config) map[string]any {
	values := make(map[string]any)
	var visit func(reflect.Value, string)
	visit = func(value reflect.Value, prefix string) {
		for index := 0; index < value.NumField(); index++ {
			field := value.Type().Field(index)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == "" || name == "-" {
				continue
			}
			name = prefix + name
			child := value.Field(index)
			if child.Kind() == reflect.Struct {
				visit(child, name+".")
			} else if child.Kind() == reflect.Slice {
				values[name] = append([]string(nil), child.Interface().([]string)...)
			} else {
				values[name] = child.Interface()
			}
		}
	}
	visit(reflect.ValueOf(cfg), "")
	return values
}

func patchFields(raw json.RawMessage) map[string]json.RawMessage {
	fields := make(map[string]json.RawMessage)
	var visit func(json.RawMessage, string)
	visit = func(raw json.RawMessage, prefix string) {
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) != nil {
			return
		}
		for key, value := range object {
			name := prefix + key
			if len(value) > 0 && value[0] == '{' {
				visit(value, name+".")
			} else {
				fields[name] = value
			}
		}
	}
	visit(raw, "")
	return fields
}

func (c Config) withPatchProvenance(merged Config, patch json.RawMessage) Config {
	sources := make(map[string]Source)
	for field, provenance := range c.Provenance() {
		sources[field] = provenance.Source
	}
	for field, raw := range patchFields(patch) {
		if redactedPatchEcho(field, raw) {
			continue
		}
		sources[field] = SourceDatabase
	}
	return trackConfig(merged, sources, SourceDatabase)
}

func redactedPatchEcho(field string, raw json.RawMessage) bool {
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return false
	}
	switch field {
	case "ca_bundle_pem", "nvd_api_key", "smtp.password", "syslog_siem_target.client_key":
		return value == redactedMarker
	case "egress_proxy.https_proxy", "nvd_mirror_url":
		return proxyUserinfoIsRedacted(value)
	default:
		return false
	}
}

func marshalStoredConfig(cfg Config) ([]byte, error) {
	blob, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(blob, &object); err != nil {
		return nil, err
	}
	sources := make(map[string]Source)
	for field, provenance := range cfg.Provenance() {
		sources[field] = provenance.Source
	}
	object["_provenance"], err = json.Marshal(sources)
	if err != nil {
		return nil, err
	}
	return json.Marshal(object)
}

func unmarshalStoredConfig(raw json.RawMessage) (Config, error) {
	cfg := Default()
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return Config{}, err
	}
	var metadata struct {
		Sources map[string]Source `json:"_provenance"`
	}
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return Config{}, err
	}
	sources := make(map[string]Source)
	for field := range patchFields(raw) {
		sources[field] = SourceDatabase
	}
	for field, source := range metadata.Sources {
		switch source {
		case SourceDefault, SourceEnvironmentBootstrap, SourceDatabase:
			sources[field] = source
		}
	}
	return trackConfig(cfg, sources, SourceDefault), nil
}

func cloneConfig(cfg Config) Config {
	cfg.SyslogSIEM.Categories = append([]string(nil), cfg.SyslogSIEM.Categories...)
	return cfg
}
