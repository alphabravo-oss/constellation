package syscfg

import (
	"os"
	"strconv"
	"strings"
)

// DefaultsFromEnv builds the bootstrap-default Config from environment variables. These
// are seeded into a fresh org's system_config row on first boot (see Provider seeding
// in the server); after that the DB row is the source of truth and env changes are
// ignored. Unset vars fall back to Default(). Env vars honored:
//
//	HTTPS_PROXY / NO_PROXY                  -> egress_proxy
//	CONSTELLATION_TLS_VERIFY (bool)         -> tls_verify (default true)
//	CONSTELLATION_CA_BUNDLE_PEM             -> ca_bundle_pem
//	CONSTELLATION_SYSLOG_HOST/PORT/PROTOCOL -> syslog_siem_target
func DefaultsFromEnv() Config {
	c := Default()
	sources := make(map[string]Source)

	// Standard proxy env vars (also honor lowercase, as is conventional).
	c.EgressProxy.HTTPSProxy = firstEnv("HTTPS_PROXY", "https_proxy")
	c.EgressProxy.NoProxy = firstEnv("NO_PROXY", "no_proxy")
	if c.EgressProxy.HTTPSProxy != "" {
		sources["egress_proxy.https_proxy"] = SourceEnvironmentBootstrap
	}
	if c.EgressProxy.NoProxy != "" {
		sources["egress_proxy.no_proxy"] = SourceEnvironmentBootstrap
	}

	if v, ok := os.LookupEnv("CONSTELLATION_TLS_VERIFY"); ok {
		if b, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil {
			c.TLSVerify = b
			sources["tls_verify"] = SourceEnvironmentBootstrap
		}
	}
	if v := strings.TrimSpace(os.Getenv("CONSTELLATION_CA_BUNDLE_PEM")); v != "" {
		c.CABundlePEM = v
		sources["ca_bundle_pem"] = SourceEnvironmentBootstrap
	}

	c.SyslogSIEM.Host = strings.TrimSpace(os.Getenv("CONSTELLATION_SYSLOG_HOST"))
	if _, ok := os.LookupEnv("CONSTELLATION_SYSLOG_HOST"); ok {
		sources["syslog_siem_target.host"] = SourceEnvironmentBootstrap
	}
	if p, err := strconv.Atoi(strings.TrimSpace(os.Getenv("CONSTELLATION_SYSLOG_PORT"))); err == nil {
		c.SyslogSIEM.Port = p
		sources["syslog_siem_target.port"] = SourceEnvironmentBootstrap
	}
	c.SyslogSIEM.Protocol = strings.TrimSpace(os.Getenv("CONSTELLATION_SYSLOG_PROTOCOL"))
	if _, ok := os.LookupEnv("CONSTELLATION_SYSLOG_PROTOCOL"); ok {
		sources["syslog_siem_target.protocol"] = SourceEnvironmentBootstrap
	}

	// A malformed env combo must not poison seeding; fall back to the safe baseline for the
	// offending fields by re-validating and resetting on failure.
	if c.Validate() != nil {
		d := Default()
		if c.SyslogSIEM.Port <= 0 || c.SyslogSIEM.Port > 65535 {
			c.SyslogSIEM = d.SyslogSIEM
			delete(sources, "syslog_siem_target.host")
			delete(sources, "syslog_siem_target.port")
			delete(sources, "syslog_siem_target.protocol")
		}
		if c.Validate() != nil {
			return d
		}
	}
	return trackConfig(c, sources, SourceDefault)
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}
