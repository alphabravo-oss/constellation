-- +goose Up
-- +goose StatementBegin
-- F1 — FQDN-anchored egress policy generation (network-segmentation parity).
--
-- Cilium enforces egress-to-DNS-name policy via its DNS proxy, expressed as
-- toFQDNs rules. The netpolicy generator (pkg/netpolicy.GenerateCilium) already
-- emits toFQDNs from netpolicy.Flow.Fqdn, but the value was never captured: the
-- runtime-agent observes the destination DNS name on Cilium Hubble flows, yet
-- network_flows had nowhere to store it. Add a nullable fqdn column so the
-- ingest path can persist the observed name and the policy-generate read path
-- can anchor egress allow rules to it. Nullable + no default: legacy bpf/dp rows
-- (which carry no DNS name) stay NULL and are unaffected.
ALTER TABLE network_flows
    ADD COLUMN IF NOT EXISTS fqdn TEXT;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE network_flows
    DROP COLUMN IF EXISTS fqdn;
-- +goose StatementEnd
