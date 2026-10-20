# 0010: One OIDC relying party and emergency administrator

Constellation delegates human authentication to one deployment-configured OIDC provider.
The issuer, client, API audience, roles claim (default `alphabravo_roles`) and exact
claim-value to product-role mapping are configured under `auth.oidc`. Compact platform
claims use the `constellation` member; external providers can use a flat claim.
No default role is granted. Accounts are linked by issuer and subject, never by email.

Use golang-jwt/v5, the proven spike JWKS cache and bounded verify-once memoization.
A request never waits for discovery or JWKS HTTP. Unknown signing keys trigger a
background refresh and fail closed until it completes. Failed/empty refreshes keep
last-good keys. Successful signatures are cached until token expiry, at most 10k.
Tokens must have a subject, issuer, audience, issued-at and expiry, and a lifetime
of at most ten minutes. Browser authorization uses code + PKCE + nonce and an atomic,
one-use Postgres attempt bound to a secure host cookie. Browser sessions are opaque,
hashed in Postgres and expire with the verified ID token; no local refresh extends
issuer roles. A new token recomputes permissions. Logout clears local browser sessions;
an upstream SSO session remains owned by the provider.

The only local credential is an explicitly enabled emergency administrator, with a
Secret-supplied Argon2id hash and mandatory TOTP. Its session defaults to five minutes
and cannot exceed ten. A database guard limits all replicas together and consumes each
TOTP step once. Successful login and its critical audit event commit atomically. Every
attempt increments a Prometheus counter; a PrometheusRule alerts on successful use.
The emergency path requires Postgres, but never the issuer, discovery or JWKS.

Remove SAML, LDAP, multiple provider types, the Astronomer adapter, password lifecycle
policies and ordinary local-password management. Keep machine-token authentication and
federation trust, which are independent of human sign-in. Forward-only migration 187
drops the replaced tables, credentials and browser refresh tokens. Settings show the
configured OIDC provider and emergency status; deployment Secrets are never returned.
