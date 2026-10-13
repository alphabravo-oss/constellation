import { describe, expect, it } from 'vitest';
import { findingBelongsToCluster, findingDTOReady, findingEpochNanos, findingHref, findingInstanceReady, findingRevisionValid, findingReceiptMatches, findingRowKey, sameFindingTimestamp } from './finding-instance';
import type { Finding } from '@/api/client';
const first = '2026-01-01T00:00:00.123456Z';
const identity = { id: 'finding', first_seen_at: first, row_id: 'finding:1767225600.123456', revision: '9007199254740995', source_cluster_id: 'source', target_cluster_id: 'target' };
describe('finding observation identity', () => {
  it('retains raw sub-millisecond selectors in detail and dedicated authoring URLs', () => {
    expect(findingHref(identity, 'target', 'comments/new')).toBe('/clusters/target/findings/finding/comments/new?first_seen_at=2026-01-01T00%3A00%3A00.123456Z');
    expect(findingHref(identity)).toContain('/clusters/source/');
    expect(findingRowKey(identity)).not.toBe(findingRowKey({ ...identity, first_seen_at: '2026-01-01T00:00:00.123457Z' }));
  });
  it('compares microseconds without millisecond Date rounding and permits equivalent offsets', () => {
    expect(sameFindingTimestamp(first, '2026-01-01T01:00:00.123456+01:00')).toBe(true);
    expect(sameFindingTimestamp(first, '2026-01-01T00:00:00.123457Z')).toBe(false);
    expect(findingEpochNanos('1969-12-31T23:59:59.900000Z')).toBe(-100000000n);
  });
  it.each(['2026-02-30T00:00:00Z', '2026-01-01T24:00:00Z', '2026-01-01T00:00:00.1234567Z', '2026-01-01', '', null])('rejects invalid or nonrepresentable timestamp %s', value => expect(findingEpochNanos(value)).toBeNull());
  it('requires physical row identity and decimal revision without treating asset row IDs as generic IDs', () => {
    expect(findingInstanceReady(identity)).toBe(true);
    expect(findingInstanceReady({ ...identity, row_id: 'asset:finding:1767225600.123456' })).toBe(false);
    expect(findingInstanceReady({ ...identity, row_id: 'finding:1767225600.123457' })).toBe(false);
    expect(findingInstanceReady({ ...identity, revision: undefined })).toBe(false);
    for (const revision of ['0', '04', '9223372036854775808', '1.0', '-1']) expect(findingRevisionValid(revision)).toBe(false);
    expect(findingRevisionValid('9223372036854775807')).toBe(true);
  });
  it('allows actual source or effective target and rejects a sibling cluster', () => {
    expect(findingBelongsToCluster(identity, 'source')).toBe(true);
    expect(findingBelongsToCluster(identity, 'target')).toBe(true);
    expect(findingBelongsToCluster(identity, 'sibling')).toBe(false);
    expect(findingDTOReady(identity as Finding, 'finding', 'target', first)).toBe(true);
    expect(findingDTOReady(identity as Finding, 'finding', 'target', '2026-01-01T00:00:00.123457Z')).toBe(false);
  });
  it('never confirms a successful response for another recurrence', () => {
    expect(findingReceiptMatches({ ...identity, status: 'ok', revision: '9007199254740996' }, identity, 'target')).toBe(true);
    expect(findingReceiptMatches(identity, identity, 'target')).toBe(false);
    expect(findingReceiptMatches(identity, identity, 'target', true)).toBe(true);
    expect(findingReceiptMatches({ ...identity, status: 'ok', source_cluster_id: 'other', revision: '9007199254740996' }, identity, 'target')).toBe(false);
    expect(findingReceiptMatches({ ...identity, row_id: 'finding:1767225600.123457', first_seen_at: '2026-01-01T00:00:00.123457Z' }, identity, 'target')).toBe(false);
  });
});
