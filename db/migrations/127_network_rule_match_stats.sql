-- +goose Up
-- +goose StatementBegin
-- A7: per-rule match telemetry + dead-rule detection.
--
-- Network rules carried no match telemetry: an operator could not tell which
-- rules ever fired, nor spot a rule that has gone silent (traffic pattern
-- changed, workload retired) and is now dead weight in the policy.
--
-- This sidecar table records, per matched rule, a cumulative match counter and
-- the first/last time a flow was attributed to it. It is written from the
-- flow-ingest / policy-eval path: every ingested flow row carries the dp rule
-- id that produced its verdict in `network_flows.policy_id` (NeuVector's
-- CLUSConnection.PolicyId convention — the id of the matched policy RULE, not
-- a coarse "policy" grouping), so `rule_id` here is exactly that value.
--
-- Models NeuVector RESTPolicyRule.MatchCntr (match_count) and
-- RESTPolicyRule.LastMatchTS (last_matched_at). See controller/api/apis.go.
--
-- Dead-rule signal: a rule is "dead" over a window W when it has had zero
-- matches during W — i.e. last_matched_at < now()-W (or, for rules that have
-- literally never matched, no row here at all; enumerating those requires the
-- authored rule set — see TODO(matrix) in pkg/netpolicy/matchstats.go).
--
-- SAFETY: pure telemetry. Writing/reading these rows never changes an
-- enforcement verdict; the dead-rule signal is advisory (surfaced in the
-- lifecycle/list API) and blocks nothing.
CREATE TABLE IF NOT EXISTS network_rule_match_stats (
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id      UUID NOT NULL,
    rule_id         BIGINT NOT NULL,           -- = network_flows.policy_id (matched dp rule id)
    match_count     BIGINT NOT NULL DEFAULT 0,
    first_matched_at TIMESTAMPTZ,
    last_matched_at  TIMESTAMPTZ,
    PRIMARY KEY (org_id, cluster_id, rule_id)
);

-- Dead-rule scan: "for this cluster, order rules by staleness".
CREATE INDEX IF NOT EXISTS idx_rule_match_stats_last_matched
    ON network_rule_match_stats(org_id, cluster_id, last_matched_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS network_rule_match_stats;
-- +goose StatementEnd
