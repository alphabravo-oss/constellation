# Browser and automation sessions

The browser signs in through the configured OIDC provider using authorization
code + PKCE. A five-minute, one-use Postgres login attempt binds state and nonce
to a Secure HttpOnly `__Host-constellation-oidc` cookie. The callback consumes the
attempt before exchanging the code; issuer, client audience, signature, expiry,
issued-at, authorized party and nonce are validated before creating an identity.

Successful sign-in sets one opaque `__Host-constellation-session` cookie:
HttpOnly, Secure, Path `/`, SameSite Lax, no Domain. Only its SHA-256 digest is
stored. Its immutable grants come from the configured roles claim and exact
mapping; it expires with the ID token, at most ten minutes. No refresh cookie or
local refresh extends the provider's roles. Removing a group removes access on
the next token. A new token with no mapped roles clears the old browser cookie
and denies access. Accounts are keyed by issuer and subject, never by email.

The emergency administrator is disabled by default. When explicitly enabled it
requires the Secret-configured Argon2id password and TOTP. Its opaque session
uses the same cookie but expires after five minutes by default (maximum ten),
and cannot refresh. The database enforces five attempts per five minutes across
all API replicas and consumes each TOTP step once. Successful creation commits
with a critical audit event; a Prometheus counter and alert record use.

Unsafe cookie requests require `X-Constellation-Client: browser` and a same-origin
request, or an explicitly allowed CORS origin. Explicit Authorization headers
always win over cookies, including when the bearer is invalid. Logout deletes
the user's local browser sessions and clears the cookie; upstream SSO remains
owned by the provider. Disabled/deleted users and session-epoch changes reject
stored sessions immediately across replicas. Expired sessions and login attempts
are removed in bounded batches by the existing leader-owned cleanup worker.

Automation can present a signed OIDC access token for the configured API
audience, or a scoped product API token. Issuer tokens are memoized only after
successful verification, checked for expiry on every hit and bounded to 10,000
entries. The JWKS cache keeps last-good keys on failed or empty refreshes.
Requests never wait for discovery/JWKS HTTP: an unknown key fails closed and
triggers a rate-limited background refresh. Normal refresh cadence is 15 minutes.
Machine tokens and federation trust remain separate from human browser sign-in.

Apply migration **187** before rolling out the matching API and frontend. It
destroys the retired passwords, policies, provider types, signing keys and local
refresh sessions. Take a CNPG backup before this cutover. Deploy behind one HTTPS
origin and reauthenticate old sessions. See [deployment configuration](deployment-helm.md).
