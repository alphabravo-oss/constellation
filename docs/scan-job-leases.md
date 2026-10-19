# Scan job lease ownership

Each claim returns a fresh `lease_id` UUID. The scanner must echo it in
`X-Constellation-Scan-Lease` on completion, failure, renewal and registry credential
requests. Authentication, organization ownership and scanner-instance identity
are still required. The UUID identifies an attempt; it is not an authentication
credential and must not replace the scanner token.

Reclaiming a timed-out job or retrying a terminal job creates a different UUID,
even when the scanner instance or reset attempt counter is identical. Expired or
superseded mutation requests return HTTP 409 without changing results or retry
state. Credential requests for the wrong lease return the same HTTP 404 response
as an unavailable registry. Malformed lease IDs return HTTP 400.

Completed/canceled jobs keep their existing idempotent acknowledgement behavior;
those acknowledgements do not accept new results. Completion checks the database
clock after locking job/target rows. Failure and renewal lock the owned job before
checking its current expiry and claim identity.

## Upgrade order

Deploy the new scanner before the API: it can consume old claim responses without
a lease ID and will start echoing IDs when the API supplies them. Apply additive
migration 184 before starting the new API. Pre-upgrade running rows retain NULL
lease IDs and can drain only while their existing lease remains valid. New claims
always receive an ID; an older worker cannot complete or renew them without it.
Upgrade every active scanner instance before switching the API.

The standalone scanner's authenticated registry mode accepts `--lease-id` together
with the existing `--job-id` and `--instance-id`; use the values returned by claim.
Do not invent an ID or retrieve another attempt's ID to retry a stale result.

The current lease lasts 30 minutes and workers renew every five minutes. A dead
worker's job becomes reclaimable after expiry; this is not immediate pod-deletion
detection. Explicit lease IDs fence late requests even when the replacement worker
uses the same stable instance name. Shorter recovery deadlines and immutable
attempt history across manual retry are separate follow-up work.

`Scan lease validation` runs the scanner and handler regression suites against a
fresh migrated database on a hosted runner. `Scanner lease candidates` builds OCI
artifacts for scanner, API and the development migration overlay. Building these
artifacts does not authorize promotion: inspect the regression result, verify
artifact/source identities, run the published-image gates, and follow the upgrade
order above. The overlay preserves the pinned runtime packages and rebuilds Goose
v3.27.1 from its verified module archive using `deploy/docker/goose` dependency
locks. Only its PostgreSQL driver is included; Constellation does not use the
other database drivers. The hosted candidate must migrate a fresh database,
repeat the upgrade, and roll migration 184 back and forward under UID 10001 with
a read-only root filesystem. The tagged release migration recipe remains a
separate hardening follow-up.
