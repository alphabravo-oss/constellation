# Browser and automation sessions

Browser login now sets `__Host-constellation-session` and
`__Host-constellation-refresh` cookies. Both are HttpOnly, Secure, Path `/` and
SameSite Strict, with no Domain attribute. Browser responses contain expiry
metadata only; the SPA removes the obsolete localStorage token on startup.
Deploy the UI and API behind the same HTTPS origin. Plain HTTP remote-host
deployments cannot use these Secure cookies; do not disable Secure as a workaround.

Apply migrations through **171** before rolling out the current API and matching
frontend. The API checks its required schema before initializing services; Helm
uses the same API image with `--check-schema` as its init-container gate.
Clients holding old localStorage credentials must sign in again. Explicit bearer
clients continue using `POST /api/v1/auth/login` without browser headers and
receive a JSON token; personal access tokens remain the preferred automation
credential. An explicitly supplied Authorization header always wins over cookies,
including when the header is invalid.

## Lifetime and revocation

- Access tokens expire within 15 minutes, or sooner under the organization policy.
- Browser refresh families have a seven-day absolute maximum; an explicitly
  configured organization session timeout can shorten it. Rotation never extends
  that deadline. Refresh also enforces inactivity, account disablement and epoch
  revocation.
- Only SHA-256 refresh-token digests are stored. Refresh atomically consumes the
  current secret, retains its digest for replay detection, and issues a new secret.
  Reusing a consumed token deletes the session family, invalidating its access
  tokens immediately and emitting `auth.refresh.reuse` audit evidence.
- Logout invalidates all sessions for the user and clears browser cookies.
  Password and role changes use the same persisted session-epoch revocation.
- Login/logout clear identity-scoped query caches. BroadcastChannel notifies
  other open tabs to reload their identity instead of retaining another user's
  cached organization data.
- The SPA coalesces concurrent refreshes and uses Web Locks, where available, to
  coordinate tabs. Strict replay detection still applies to duplicate refresh
  requests; browsers without Web Locks can require reauthentication after a
  cross-tab race.

## Operational cleanup

Migration 171 records the absolute expiry of newly issued tracked sessions.
Browser login atomically extends that row to cover its refresh family's absolute
deadline. Rotation does not extend that deadline. Legacy session rows with no
recorded expiry remain untouched; guessing from last activity could revoke a
still-valid credential.

The API leader reaps once at startup and every minute, with at most 1,000 rows
per family per pass and a five-second deadline per statement. Locked rows are
skipped. Refresh rows expire one minute after their absolute deadline, including
consumed digests; consumed but unexpired digests remain for reuse detection.
A session is eligible only after its recorded deadline plus one minute **and**
after all its refresh rows have gone, preventing an unbounded foreign-key cascade.
Other replicas can take over with the leader lease; deployments without leader
election can run concurrent, bounded passes safely.

The same worker removes network snapshots and undelivered network-session kill
requests older than five minutes. Delivery independently rejects expired commands.
The API and console expose the delivery deadline; a queued request is not proof
of agent execution. Audit receipts are preserved. Durable delivery/acknowledgement
and the other operational-history families remain separate parity work.

Metrics use four fixed family labels, with no session, user, cluster or token
identifiers: `constellation_session_cleanup_deleted_total{family}`,
`constellation_session_cleanup_failures_total`,
`constellation_session_cleanup_last_success_timestamp_seconds`, and
`constellation_session_cleanup_duration_seconds`. The last-success gauge is zero
until a pass completes. Aggregate across API replicas when evaluating worker
freshness because follower gauges remain zero. These measurements do not yet
provide a backlog alarm or prove the 1,000-row/minute budget handles a given load.

## CSRF contract

Cookie-authenticated mutations, browser login and `/api/v1/auth/refresh` require
`X-Constellation-Client: browser` and an exact same-origin or explicitly allowed
Origin. When Origin is absent, only `Sec-Fetch-Site: same-origin` is accepted.
Wildcard origins are not accepted. Bearer-only automation is not subject to the
ambient-cookie CSRF check. The SAML ACS retains its signed assertion/state
validation instead of the same-origin mutation check.

Browser SAML logins must begin at the SP login endpoint. A five-minute,
single-use nonce binds RelayState to a Secure HttpOnly `__Host-` cookie with
SameSite None so it can return on the IdP's cross-site POST. Unsolicited
IdP-initiated browser ACS requests are rejected rather than creating an unbound
cookie session. Existing non-browser bearer SAML remains supported. SAML pending
requests/bindings are currently process-local: login affinity is required across
replicas, and restarting the API requires restarting an in-flight SAML login.

Reverse proxies must preserve the original Host, including a nondefault port;
the shipped nginx and Helm frontend configurations do so. Cookies are not an
XSS prevention mechanism: they prevent JavaScript from reading credentials, not
an injected script from making authenticated requests.

## Verification

`GOOSE_BIN=goose bash scripts/test-browser.sh` builds the actual API and frontend
images, migrates and seeds an isolated PostgreSQL instance, and tests the built
SPA through nginx. It binds published ports to loopback and removes its containers
and network afterward. Install Playwright Chromium first with
`cd frontend && npx playwright install --with-deps chromium`, or set
`PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH` to a compatible local browser.

Additional Playwright spec paths can be passed to the script. Logs/image IDs are
stored under `artifacts/browser`; Playwright retains failure traces and screenshots.
This gate does not claim live external-IdP, multi-replica, CNI or production rollout
coverage. Real PostgreSQL tests cover expiry, batch/cascade bounds, locked rows,
legacy sessions, cluster/node key collisions, browser refresh and reuse revocation.
Live cleanup/backlog alerting, measured capacity and broader TSG security
requirements remain tracked in `NEUVECTOR-PARITY-PLAN.md`.
