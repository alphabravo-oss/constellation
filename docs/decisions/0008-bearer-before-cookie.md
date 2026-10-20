---
status: "accepted"
date: 2026-10-20
deciders: ["AlphaBravoCompany"]
title: "Explicit bearer token takes precedence over the browser session cookie"
tags: [security, auth]
---

# Explicit bearer token takes precedence over the browser session cookie

## Context

The Technology Selection Guide (ch.06, browser sessions) describes the browser
receiving its access token in an `HttpOnly; Secure; SameSite` cookie and
programmatic clients presenting a bearer token, and notes the cookie "takes
precedence when both are present". It does not make precedence a MUST and gives
no threat model for the mixed case.

Constellation's `authMiddleware` (`internal/server/server.go`) reads the
`Authorization: Bearer` header first and falls back to the
`__Host-constellation-session` cookie only when the header is empty. Phase 0
implemented cookie-first and reverted it because the browser-session security
suite (`internal/server/browser_sessions_security_test.go`, e.g.
`TestBrowserSessionsSecurityCookieCannotOverrideMutationBearer`) asserts the
opposite invariant.

## Decision Drivers

- A request that explicitly presents a scoped credential (a PAT narrowed to a
  verb set, a service token, a foreign-org token) must be authorised as that
  credential. A cookie the browser attaches implicitly must never widen it.
- A tracked browser session must not be swapped mid-request by a cookie when the
  caller presented a different identity.
- CSRF protection (`browserCSRF`) applies to the cookie path; the bearer path is
  not cookie-borne and needs none.

## Considered Options

1. Cookie first (the guide's description).
2. Bearer first, cookie as fallback (current behaviour).
3. Reject requests that carry both.

## Decision Outcome

Option 2. When an `Authorization` header is present it alone authenticates the
request; the session cookie is consulted only when the header is absent.
Option 1 lets ambient browser state override an explicit, possibly narrower
credential — the property the security suite exists to prevent. Option 3 would
break the browser client during the cookie migration and buys nothing over 2.

### Consequences

- Good: an explicit credential is never widened by ambient cookies; the existing
  security suite stays green and is the regression gate for this ADR.
- Neutral: a browser that also sends a stale bearer header is authenticated by
  that header; the frontend sends either the cookie or a header, never both.
- Recorded deviation from the guide's descriptive (non-MUST) precedence note.

## Links

- `internal/server/server.go` (`authMiddleware`, precedence comment)
- `internal/server/browser_sessions_security_test.go`
- `readiness-assessment-2026-10-20/exec-constellation-phase0.md` (revert record)
