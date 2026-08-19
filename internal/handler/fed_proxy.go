package handler

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	neturl "net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/auth"
	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/federation"
	"github.com/alphabravocompany/constellation/pkg/rbac"
)

// ── D3: cross-cluster admin reverse-proxy ────────────────────────────────────
//
// A master operates its joints from a single pane: ANY /api/v1/federation/clusters/{id}/*
// resolves the joint's endpoint from the fed membership record, attaches the master's
// federation credential (a D1 sync ticket minted on demand + — when D2 mTLS is on — a
// CA-issued client certificate), forwards the request preserving method/headers/body, and
// streams the response back. It is RBAC-gated: any reader may drive a READ-ONLY allowlist
// of GET paths on a joint, but only a federation admin (VerbManageOrg / GlobalAdmin) may
// forward a mutating verb.
//
// SSRF posture: the target host is taken ONLY from the registered fed_members.endpoint for
// the requested cluster id — never from caller input. The {*} suffix contributes the joint
// API PATH only; it can never redirect to another host. The inbound user credential
// (Authorization/Cookie) and all hop-by-hop headers are stripped BEFORE the master's own
// fed credential is attached, so a joint never sees the caller's bearer and the master's
// credential is the only identity on the wire.

// fedProxyCredentialTTL bounds the on-demand fed credential (sync ticket + client cert) the
// master mints to authenticate ONE proxied request to a joint. Short-lived: the master
// re-mints per use, so a captured proxy credential expires quickly.
const fedProxyCredentialTTL = 5 * time.Minute

// fedProxyDefaultReadPaths is the default read-only allowlist (matched on the first path
// segment of the joint sub-path) a non-admin may GET through the proxy. It is intentionally
// limited to clearly read-only resources. The server may override it from config (B1), so it
// is not a hardcoded policy — operators tune the surface a non-admin can observe cross-cluster.
var fedProxyDefaultReadPaths = []string{
	"findings", "scan-results", "scans", "assets", "images", "vulnerabilities",
	"compliance", "audit-logs", "dashboards", "reports", "network", "runtime",
	"federation", "health", "version",
}

// FedProxy forwards an admin's request to a federated joint's API. It is wired once on the
// master controller; nil fedSigner/fedCA degrade gracefully (the request is still forwarded,
// just without that credential layer — a deployment that terminates fed auth differently).
type FedProxy struct {
	db        *db.DB
	auditLog  *audit.Logger
	fedSigner *auth.FedSigner
	fedCA     *auth.FedCA

	// authorize reports whether subj holds verb in its own org scope. Wired from the server
	// so org-defined custom roles are honored. When nil, the static role assignments on the
	// Subject are consulted directly (the path unit tests drive).
	authorize func(ctx context.Context, subj Subject, verb rbac.Verb) bool

	// readAllowlist is the non-admin GET allowlist (first path segment). Empty => the default.
	readAllowlist []string

	// client is the base HTTP client for the bearer-only path (tests inject one that reaches
	// an httptest joint). nil => http.DefaultClient.
	client *http.Client

	mu         sync.Mutex
	mtlsClient *http.Client // lazily built when fedCA != nil
}

// NewFedProxy builds the cross-cluster proxy handler.
func NewFedProxy(d *db.DB, a *audit.Logger) *FedProxy {
	return &FedProxy{db: d, auditLog: a}
}

// WithFedCredentials wires the D1 signer + D2 CA used to authenticate the master to a joint.
func (h *FedProxy) WithFedCredentials(signer *auth.FedSigner, ca *auth.FedCA) *FedProxy {
	h.fedSigner = signer
	h.fedCA = ca
	return h
}

// WithAuthorizer wires the org-scoped verb check (custom-role aware).
func (h *FedProxy) WithAuthorizer(fn func(ctx context.Context, subj Subject, verb rbac.Verb) bool) *FedProxy {
	h.authorize = fn
	return h
}

// WithReadAllowlist overrides the non-admin GET allowlist (first path segments). An empty or
// nil list leaves the default.
func (h *FedProxy) WithReadAllowlist(paths []string) *FedProxy {
	cleaned := cleanAllowlist(paths)
	if len(cleaned) > 0 {
		h.readAllowlist = cleaned
	}
	return h
}

// WithClient injects the base HTTP client (tests).
func (h *FedProxy) WithClient(c *http.Client) *FedProxy {
	h.client = c
	return h
}

// Forward proxies the inbound request to the joint identified by {id}. It is the single
// handler registered for every method on /federation/clusters/{id}/* — the route-level RBAC
// gate already restricts mutating verbs to admins; this handler additionally enforces the
// non-admin read allowlist on GET and the SSRF guard.
func (h *FedProxy) Forward(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	clusterID := strings.TrimSpace(chi.URLParam(r, "id"))
	if clusterID == "" {
		jsonError(w, http.StatusNotFound, "federation: cluster not found")
		return
	}

	// SSRF guard: the endpoint is resolved ONLY from the registered membership row for this
	// org+cluster. An unknown/arbitrary cluster id has no row -> 404, so the proxy can never
	// be pointed at an attacker-supplied host.
	endpoint, status, err := h.resolveJoint(r.Context(), subj.OrgID, clusterID)
	if errors.Is(err, errFedClusterNotFound) {
		jsonError(w, http.StatusNotFound, "federation: cluster not registered")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "federation: resolve cluster")
		return
	}
	if endpoint == "" {
		jsonError(w, http.StatusNotFound, "federation: cluster has no registered endpoint")
		return
	}
	if status == federation.MemberStatusKicked {
		jsonError(w, http.StatusForbidden, "federation: cluster revoked")
		return
	}

	admin := h.isAdmin(r.Context(), subj)
	subPath := strings.TrimLeft(chi.URLParam(r, "*"), "/")
	// SSRF / allowlist-bypass guard: reject any '.' or '..' segment (raw or percent-encoded)
	// BEFORE the allowlist check and URL construction. Without this a non-admin could pass
	// `findings/../../users` — the first-segment allowlist sees `findings` and the master
	// forwards `/api/v1/findings/../../users` verbatim under its own fed credential, escaping
	// both the read allowlist and the /api/v1 SSRF-path invariant once the joint normalizes.
	if !fedProxySubPathSafe(subPath) {
		jsonError(w, http.StatusBadRequest, "federation: path must not contain '.' or '..' segments")
		return
	}
	if !admin {
		// Non-admins are read-only: GET/HEAD on the allowlist only. The route gate already
		// blocks mutating methods for non-admins; this is the in-handler defense-in-depth that
		// also covers the GET allowlist the route gate cannot express.
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			jsonError(w, http.StatusForbidden, "federation: read-only for non-admins")
			return
		}
		if !h.readAllowed(subPath) {
			jsonError(w, http.StatusForbidden, "federation: path not in cross-cluster read allowlist")
			return
		}
	}

	target, err := fedProxyTargetURL(endpoint, subPath, r.URL.RawQuery)
	if err != nil {
		jsonError(w, http.StatusBadGateway, "federation: invalid joint endpoint")
		return
	}

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, target, r.Body)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "federation: build upstream request")
		return
	}
	// Strip hop-by-hop + the inbound user credential AND any header a joint might trust for
	// identity / authz / client-IP, THEN attach the master's fed credential, so a caller can
	// never smuggle a trusted header (e.g. X-Forwarded-For/-User, X-Real-IP, X-Api-Key, a
	// forwarded client cert) under the master's attached identity — the master is the only
	// identity on the wire.
	copyProxyRequestHeaders(outReq.Header, r.Header)
	for _, hdr := range fedProxyStripRequestHeaders {
		outReq.Header.Del(hdr)
	}

	client, err := h.attachFedCredential(r.Context(), outReq, subj.OrgID, clusterID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "federation: attach credential")
		return
	}

	resp, err := client.Do(outReq)
	if err != nil {
		jsonError(w, http.StatusBadGateway, "federation: joint unreachable")
		return
	}
	defer resp.Body.Close()

	copyProxyResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)

	oid := subj.OrgID
	uid := subj.UserID
	_, _, _ = h.auditLog.Log(r.Context(), audit.Event{OrgID: &oid, ActorID: &uid,
		Action: "federation.proxy", TargetKind: "fed-cluster", TargetID: clusterID,
		After: map[string]any{"method": r.Method, "path": "/" + subPath, "status": resp.StatusCode}})
}

var errFedClusterNotFound = errors.New("federation: cluster not registered")

// resolveJoint returns the registered endpoint + membership status for org+cluster, or
// errFedClusterNotFound if no membership row exists (the SSRF guard).
func (h *FedProxy) resolveJoint(ctx context.Context, orgID uuid.UUID, clusterID string) (endpoint, status string, err error) {
	err = h.db.Pool().QueryRow(ctx,
		`SELECT COALESCE(endpoint,''), status FROM fed_members WHERE org_id=$1 AND cluster_id=$2`,
		orgID, clusterID).Scan(&endpoint, &status)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", errFedClusterNotFound
		}
		return "", "", err
	}
	return strings.TrimSpace(endpoint), status, nil
}

// isAdmin reports whether the subject may forward mutating verbs (a federation admin).
func (h *FedProxy) isAdmin(ctx context.Context, subj Subject) bool {
	if h.authorize != nil {
		return h.authorize(ctx, subj, rbac.VerbManageOrg)
	}
	return rbac.Authorize(subj.Assignments, rbac.VerbManageOrg, rbac.Resource{OrgID: subj.OrgID}) == nil
}

// fedProxyStripRequestHeaders are inbound headers the proxy MUST drop before attaching the
// master's federation credential: the user credential plus every header a downstream joint
// might trust for identity, authorization, or client IP. Stripping them prevents a caller
// from smuggling a trusted header under the master's master-level identity. http.Header.Del
// canonicalizes the key, so the exact casing here is not significant.
var fedProxyStripRequestHeaders = []string{
	"Authorization", "Cookie", "Proxy-Authorization",
	"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
	"X-Forwarded-Port", "X-Forwarded-User", "X-Forwarded-Client-Cert",
	"X-Real-Ip", "X-Api-Key", "X-Auth-Token", "X-Auth-Request-User",
	"X-User", "X-User-Id", "X-Org-Id", "Ssl-Client-Cert", "X-Ssl-Client-Cert",
}

// fedProxySubPathSafe reports whether the proxied sub-path is free of '.' / '..' segments
// (raw OR percent-encoded). A dot segment is rejected so the forwarded URL cannot escape the
// joint's /api/v1 base or slip past the first-segment read allowlist.
func fedProxySubPathSafe(subPath string) bool {
	for _, seg := range strings.Split(subPath, "/") {
		if isDotSegment(seg) {
			return false
		}
		if dec, err := neturl.PathUnescape(seg); err == nil && isDotSegment(dec) {
			return false
		}
	}
	return true
}

func isDotSegment(s string) bool { return s == "." || s == ".." }

// readAllowed reports whether subPath's first segment is in the non-admin read allowlist.
func (h *FedProxy) readAllowed(subPath string) bool {
	list := h.readAllowlist
	if len(list) == 0 {
		list = fedProxyDefaultReadPaths
	}
	seg := subPath
	if i := strings.IndexByte(seg, '/'); i >= 0 {
		seg = seg[:i]
	}
	if i := strings.IndexByte(seg, '?'); i >= 0 {
		seg = seg[:i]
	}
	seg = strings.ToLower(strings.TrimSpace(seg))
	if seg == "" {
		return false
	}
	for _, p := range list {
		if seg == p {
			return true
		}
	}
	return false
}

// attachFedCredential mints + attaches the master's federation credential for this joint and
// returns the HTTP client to use. The bearer is a fresh, short-lived D1 sync ticket carrying
// the cluster's current epoch (so a revoked joint's epoch bump invalidates it); when the D2
// CA is configured it also returns a client that presents a CA-issued client certificate for
// mTLS to the joint. Best-effort: a missing fed_credentials row leaves epoch 0.
func (h *FedProxy) attachFedCredential(ctx context.Context, req *http.Request, orgID uuid.UUID, clusterID string) (*http.Client, error) {
	if h.fedSigner != nil {
		var epoch int64
		_ = h.db.Pool().QueryRow(ctx,
			`SELECT epoch FROM fed_credentials WHERE org_id=$1 AND cluster_id=$2`,
			orgID, clusterID).Scan(&epoch)
		ticket, err := h.fedSigner.IssueSyncTicket(orgID, clusterID, epoch, fedProxyCredentialTTL)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+ticket)
	}
	if h.fedCA != nil {
		return h.mtlsClientFor()
	}
	if h.client != nil {
		return h.client, nil
	}
	return http.DefaultClient, nil
}

// mtlsClientFor lazily builds (and caches) the HTTP client that presents a CA-issued client
// certificate identifying the master to a joint over mTLS. The cert is minted once from the
// fed CA and reused for the process lifetime, so the hot proxy path does no per-request
// keygen. The joint's SERVER certificate is verified against the system roots (D4 adds the
// configurable master/joint CA + skip-verify knob); this method only attaches the master's
// CLIENT identity.
func (h *FedProxy) mtlsClientFor() (*http.Client, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.mtlsClient != nil {
		return h.mtlsClient, nil
	}
	certPEM, keyPEM, err := h.fedCA.IssueClientCert("constellation-federation-master", 0)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	timeout := 30 * time.Second
	if h.client != nil && h.client.Timeout > 0 {
		timeout = h.client.Timeout
	}
	h.mtlsClient = &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{cert},
			},
		},
	}
	return h.mtlsClient, nil
}

// fedProxyTargetURL builds the absolute joint URL from the REGISTERED endpoint (host) plus the
// proxied sub-path and the inbound raw query. The sub-path can only extend the joint's own
// /api/v1 path; it cannot change scheme/host (the SSRF invariant).
func fedProxyTargetURL(endpoint, subPath, rawQuery string) (string, error) {
	base, err := neturl.Parse(strings.TrimSpace(endpoint))
	if err != nil {
		return "", err
	}
	if base.Host == "" || (base.Scheme != "http" && base.Scheme != "https") {
		return "", errors.New("federation: joint endpoint must be an absolute http(s) URL")
	}
	// The sub-path only extends the joint's own /api/v1 path; scheme+host come solely from the
	// registered endpoint, so it can never redirect to another host.
	target := *base
	target.Path = strings.TrimRight(base.Path, "/") + "/api/v1/" + strings.TrimLeft(subPath, "/")
	target.RawQuery = rawQuery
	target.Fragment = ""
	return target.String(), nil
}

// fedProxyHopByHop are the hop-by-hop headers that must not be forwarded across the proxy
// (RFC 7230 §6.1), plus the inbound credential headers the proxy replaces with its own.
var fedProxyHopByHop = map[string]bool{
	"connection":          true,
	"proxy-connection":    true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailer":             true,
	"transfer-encoding":   true,
	"upgrade":             true,
}

// copyProxyRequestHeaders copies inbound request headers minus hop-by-hop headers (and any
// header named in a Connection: token). Authorization/Cookie are dropped by the caller after
// this so the master's own credential is the only one attached.
func copyProxyRequestHeaders(dst, src http.Header) {
	drop := connectionTokens(src)
	for k, vv := range src {
		lk := strings.ToLower(k)
		if fedProxyHopByHop[lk] || drop[lk] {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// copyProxyResponseHeaders copies upstream response headers minus hop-by-hop headers.
func copyProxyResponseHeaders(dst, src http.Header) {
	drop := connectionTokens(src)
	for k, vv := range src {
		lk := strings.ToLower(k)
		if fedProxyHopByHop[lk] || drop[lk] {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// connectionTokens returns the set of header names listed in any Connection header, which are
// per-connection and must also be stripped.
func connectionTokens(h http.Header) map[string]bool {
	out := map[string]bool{}
	for _, c := range h["Connection"] {
		for _, tok := range strings.Split(c, ",") {
			if t := strings.ToLower(strings.TrimSpace(tok)); t != "" {
				out[t] = true
			}
		}
	}
	return out
}

// cleanAllowlist normalizes a configured allowlist to lowercased, trimmed, non-empty segments.
func cleanAllowlist(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		p = strings.ToLower(strings.TrimSpace(strings.Trim(p, "/")))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
