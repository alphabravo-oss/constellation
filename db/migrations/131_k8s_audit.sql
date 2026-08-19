-- +goose Up
-- +goose StatementBegin
-- C1: Kubernetes-audit / control-plane monitoring.
--
-- k8s_audit_events stores Kubernetes API-server audit events ingested via the
-- audit-webhook receiver (POST /api/v1/k8s-audit:bulk). Each row is one
-- audit.k8s.io/v1 Event the apiserver posted: who (user, source_ip) did what
-- (verb) to which object (resource[/subresource], namespace, name), and whether
-- the authorizer allowed it (decision).
--
-- High-signal events — exec into a pod (pods/exec), secret reads (secrets get),
-- RBAC mutations (rbac.authorization.k8s.io writes), privileged pod creates —
-- are additionally fanned out to the notify dispatcher + audit log + response
-- rule engine at ingest time (see internal/handler/k8saudit). The `signal` and
-- `severity` columns record that classification so the console can filter to the
-- high-signal subset without re-deriving it.
--
-- `raw` keeps the full audit Event JSON for forensics / future extraction (e.g.
-- pulling the pod spec out of a Request/RequestResponse-level event to confirm a
-- privileged create). Not partitioned: control-plane audit volume is far lower
-- than dataplane flow volume; a future migration can partition by `at` if any
-- one cluster crosses ~1M rows.
CREATE TABLE IF NOT EXISTS k8s_audit_events (
    id            UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    org_id        UUID NOT NULL,
    cluster_id    UUID NOT NULL,

    -- What happened.
    verb          TEXT NOT NULL,                    -- get|list|create|update|patch|delete|watch|...
    resource      TEXT,                             -- pods|secrets|roles|...
    subresource   TEXT,                             -- exec|log|... (empty for the object itself)
    api_group     TEXT,                             -- ""=core, rbac.authorization.k8s.io, ...
    namespace     TEXT,
    name          TEXT,                             -- objectRef.name (object instance)

    -- Who did it.
    "user"        TEXT,                             -- user.username
    source_ip     TEXT,                             -- first of sourceIPs

    -- Authorizer verdict + our classification.
    decision      TEXT,                             -- allow|forbid|"" (annotation authorization.k8s.io/decision)
    signal        TEXT,                             -- pod_exec|secret_access|rbac_change|privileged_create|"" (high-signal tag)
    severity      TEXT,                             -- info|low|medium|high|critical

    audit_id      TEXT,                             -- apiserver auditID (dedup / correlation)

    raw           JSONB,                            -- full audit.k8s.io/v1 Event

    reported_at   TIMESTAMPTZ,                      -- requestReceivedTimestamp from the apiserver
    at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_k8s_audit_org_at
  ON k8s_audit_events(org_id, at DESC);
CREATE INDEX IF NOT EXISTS idx_k8s_audit_org_cluster_at
  ON k8s_audit_events(org_id, cluster_id, at DESC);
CREATE INDEX IF NOT EXISTS idx_k8s_audit_org_signal_at
  ON k8s_audit_events(org_id, signal, at DESC) WHERE signal IS NOT NULL AND signal <> '';
CREATE INDEX IF NOT EXISTS idx_k8s_audit_org_resource_at
  ON k8s_audit_events(org_id, resource, at DESC);
CREATE INDEX IF NOT EXISTS idx_k8s_audit_org_user_at
  ON k8s_audit_events(org_id, "user", at DESC) WHERE "user" IS NOT NULL AND "user" <> '';
CREATE INDEX IF NOT EXISTS idx_k8s_audit_org_namespace_at
  ON k8s_audit_events(org_id, namespace, at DESC) WHERE namespace IS NOT NULL AND namespace <> '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS k8s_audit_events;
-- +goose StatementEnd
