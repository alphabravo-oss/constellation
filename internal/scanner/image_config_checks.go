package scanner

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Image config (CIS-Docker-style) checks derived from the OCI image config — the "checks[]"
// tab NeuVector ships on every image report. These are cheap: they read only the image
// CONFIG (no layer blob walk), so they add negligible cost to a scan.

// ImageConfigCheck is one evaluated best-practice control on the image config.
type ImageConfigCheck struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Status      string `json:"status"` // pass | fail | warn
	Severity    string `json:"severity"`
	Detail      string `json:"detail,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

// ImageConfigCheckReport is the artifact stored per scan.
type ImageConfigCheckReport struct {
	ImageRef  string             `json:"image_ref"`
	Platform  string             `json:"platform,omitempty"`
	Checks    []ImageConfigCheck `json:"checks"`
	PassCount int                `json:"pass_count"`
	FailCount int                `json:"fail_count"`
	WarnCount int                `json:"warn_count"`
	Status    string             `json:"status"` // ok | error
	Reason    string             `json:"reason,omitempty"`
	Error     string             `json:"error,omitempty"`
}

// ScanImageConfigChecks pulls the image config and evaluates the CIS-Docker image controls.
func ScanImageConfigChecks(ctx context.Context, ref string, platform string, insecure bool) (*ImageConfigCheckReport, error) {
	parseOpts := []name.Option{}
	if insecure {
		parseOpts = append(parseOpts, name.Insecure)
	}
	parsed, err := name.ParseReference(ref, parseOpts...)
	if err != nil {
		return nil, fmt.Errorf("config-checks: parse ref: %w", err)
	}
	remoteOpts := []remote.Option{
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithUserAgent("constellation-scanner"),
	}
	if strings.TrimSpace(platform) != "" {
		p, err := v1.ParsePlatform(platform)
		if err != nil {
			return nil, fmt.Errorf("config-checks: parse platform: %w", err)
		}
		remoteOpts = append(remoteOpts, remote.WithPlatform(*p))
	}
	img, err := remote.Image(parsed, remoteOpts...)
	if err != nil {
		return nil, fmt.Errorf("config-checks: pull image metadata: %w", err)
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("config-checks: read config: %w", err)
	}
	return imageConfigChecksFrom(ref, platform, parsed, cfg), nil
}

func imageConfigChecksFrom(ref, platform string, parsed name.Reference, cfg *v1.ConfigFile) *ImageConfigCheckReport {
	rep := &ImageConfigCheckReport{ImageRef: ref, Platform: platform, Status: "ok"}
	c := cfg.Config

	add := func(id, title, status, sev, detail, rem string) {
		rep.Checks = append(rep.Checks, ImageConfigCheck{ID: id, Title: title, Status: status, Severity: sev, Detail: detail, Remediation: rem})
	}

	// 1) Runs as root (CIS-Docker 4.1). USER unset / 0 / root, in either "uid" or
	// "user:group" form (e.g. "0", "root", "0:0", "root:root", "root:0").
	user := strings.TrimSpace(c.User)
	userPart := user
	if i := strings.IndexByte(user, ':'); i >= 0 {
		userPart = user[:i]
	}
	userRoot := userPart == "" || userPart == "0" || strings.EqualFold(userPart, "root")
	if userRoot {
		add("image-runs-as-root", "Image runs as root", "fail", "high",
			fmt.Sprintf("USER is %q", firstNonEmptyStr(user, "unset")),
			"Add a non-root USER instruction to the Dockerfile and pin a numeric UID.")
	} else {
		add("image-runs-as-root", "Image runs as a non-root user", "pass", "high", "USER "+user, "")
	}

	// 2) HEALTHCHECK defined (CIS-Docker 4.6).
	if c.Healthcheck != nil && len(c.Healthcheck.Test) > 0 {
		add("image-healthcheck", "HEALTHCHECK instruction present", "pass", "low", "", "")
	} else {
		add("image-healthcheck", "No HEALTHCHECK instruction", "warn", "low", "",
			"Add a HEALTHCHECK so the orchestrator can detect an unhealthy container.")
	}

	// 3) Floating :latest tag (CIS-Docker 4.7 — avoid mutable image tags).
	tag := ""
	if t, ok := parsed.(name.Tag); ok {
		tag = t.TagStr()
	}
	if tag == "" || tag == "latest" {
		add("image-latest-tag", "Image uses a mutable tag (:latest or untagged)", "warn", "medium",
			fmt.Sprintf("tag %q", firstNonEmptyStr(tag, "none")),
			"Pin images to an immutable tag or digest for reproducible, auditable deploys.")
	} else {
		add("image-latest-tag", "Image is pinned to a specific tag", "pass", "medium", "tag "+tag, "")
	}

	// 4) Secrets in env (CIS-Docker 4.10 — no secrets in the image).
	secretEnvs := []string{}
	for _, e := range c.Env {
		k := strings.ToUpper(e)
		if i := strings.IndexByte(e, '='); i > 0 {
			k = strings.ToUpper(e[:i])
		}
		for _, needle := range []string{"PASSWORD", "PASSWD", "SECRET", "TOKEN", "APIKEY", "API_KEY", "PRIVATE_KEY", "ACCESS_KEY"} {
			if strings.Contains(k, needle) {
				name := e
				if i := strings.IndexByte(e, '='); i > 0 {
					name = e[:i]
				}
				secretEnvs = append(secretEnvs, name)
				break
			}
		}
	}
	if len(secretEnvs) > 0 {
		add("image-env-secrets", "Secret-looking environment variables baked into the image", "fail", "critical",
			"env: "+strings.Join(secretEnvs, ", "),
			"Remove secrets from the image; inject them at runtime via a secret store or mounted volume.")
	} else {
		add("image-env-secrets", "No secret-looking environment variables", "pass", "critical", "", "")
	}

	// 5) Privileged exposed ports (<1024 hints at a service that must bind privileged ports).
	privPorts := []string{}
	for p := range c.ExposedPorts {
		numStr := p
		if i := strings.IndexByte(p, '/'); i > 0 {
			numStr = p[:i]
		}
		if n, err := strconv.Atoi(numStr); err == nil && n > 0 && n < 1024 {
			privPorts = append(privPorts, p)
		}
	}
	if len(privPorts) > 0 {
		add("image-privileged-ports", "Image exposes privileged ports (<1024)", "warn", "medium",
			"ports: "+strings.Join(privPorts, ", "),
			"Prefer unprivileged ports (>=1024) so the container need not run with extra capabilities.")
	}

	for _, ck := range rep.Checks {
		switch ck.Status {
		case "pass":
			rep.PassCount++
		case "fail":
			rep.FailCount++
		case "warn":
			rep.WarnCount++
		}
	}
	return rep
}

func firstNonEmptyStr(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
