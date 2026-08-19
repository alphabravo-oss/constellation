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

	// Standard proxy env vars (also honor lowercase, as is conventional).
	c.EgressProxy.HTTPSProxy = firstEnv("HTTPS_PROXY", "https_proxy")
	c.EgressProxy.NoProxy = firstEnv("NO_PROXY", "no_proxy")

	if v, ok := os.LookupEnv("CONSTELLATION_TLS_VERIFY"); ok {
		if b, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil {
			c.TLSVerify = b
		}
	}
	if v := strings.TrimSpace(os.Getenv("CONSTELLATION_CA_BUNDLE_PEM")); v != "" {
		c.CABundlePEM = v
	}

	c.SyslogSIEM.Host = strings.TrimSpace(os.Getenv("CONSTELLATION_SYSLOG_HOST"))
	if p, err := strconv.Atoi(strings.TrimSpace(os.Getenv("CONSTELLATION_SYSLOG_PORT"))); err == nil {
		c.SyslogSIEM.Port = p
	}
	c.SyslogSIEM.Protocol = strings.TrimSpace(os.Getenv("CONSTELLATION_SYSLOG_PROTOCOL"))

	// A malformed env combo must not poison seeding; fall back to the safe baseline for the
	// offending fields by re-validating and resetting on failure.
	if c.Validate() != nil {
		d := Default()
		if c.SyslogSIEM.Port <= 0 || c.SyslogSIEM.Port > 65535 {
			c.SyslogSIEM = d.SyslogSIEM
		}
		if c.Validate() != nil {
			return d
		}
	}
	return c
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}
