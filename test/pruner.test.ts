import { describe, it, expect, beforeEach } from 'vitest';
import { AttestationPrunerDaemon } from '../src/pruner.js';
import { type Hex } from 'viem';

describe('AttestationPrunerDaemon', () => {
  let daemon: AttestationPrunerDaemon;

  const agent1: Hex = '0x1111111111111111111111111111111111111111111111111111111111111111';
  const digest1: Hex = '0xaaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111';

  beforeEach(() => {
    daemon = new AttestationPrunerDaemon(3600_000);
  });

  it('enforces maxRetainedCapacity during continuous ingestion', () => {
    const limited = new AttestationPrunerDaemon(86_400_000, 3);
    for (let i = 1n; i <= 5n; i++) {
      limited.recordAttestation({
        agentId: '0x01',
        epoch: i,
        anchoredTimestamp: Date.now(),
        attestationDigest: '0x02',
      });
    }
    expect(limited.getRecordCount()).toBe(3);
    const records = limited.getRecords();
    expect(records.map((r) => r.epoch)).toEqual([3n, 4n, 5n]);
  });

  it('selectively prunes targeted agent IDs while preserving others', () => {
    const filtered = new AttestationPrunerDaemon();
    filtered.recordAttestation({
      agentId: '0xaa',
      epoch: 2n,
      anchoredTimestamp: Date.now() - 100_000_000,
      attestationDigest: '0x01',
    });
    filtered.recordAttestation({
      agentId: '0xbb',
      epoch: 2n,
      anchoredTimestamp: Date.now() - 100_000_000,
      attestationDigest: '0x02',
    });

    const report = filtered.prune({ targetAgentIds: ['0xaa'] });
    expect(report.prunedCount).toBe(1);
    expect(filtered.getRecords()).toHaveLength(1);
    expect(filtered.getRecords()[0].agentId).toBe('0xbb');
  });

  it('filters records by agent correctly', () => {
    daemon.recordAttestation({
      agentId: agent1,
      epoch: 1n,
      anchoredTimestamp: Date.now(),
      attestationDigest: '0x01',
    });
    daemon.recordAttestation({
      agentId: '0x2222222222222222222222222222222222222222222222222222222222222222',
      epoch: 2n,
      anchoredTimestamp: Date.now(),
      attestationDigest: '0x02',
    });

    const records = daemon.getRecordsByAgent(agent1);
    expect(records).toHaveLength(1);
    expect(records[0].epoch).toBe(1n);
  });

  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, -1])(
    'rejects invalid default max age %s at construction',
    (value) => {
      expect(() => new AttestationPrunerDaemon(value)).toThrow('non-negative finite number');
    }
  );

  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, -1])(
    'rejects invalid pruning max age %s before modifying the archive',
    (value) => {
      daemon.recordAttestation({
        agentId: agent1,
        epoch: 10n,
        anchoredTimestamp: Date.now(),
        attestationDigest: digest1,
      });
      expect(() => daemon.prune({ maxAgeMs: value })).toThrow('non-negative finite number');
      expect(daemon.getRecordCount()).toBe(1);
    }
  );

  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, 0, -1])(
    'rejects invalid anchored timestamp %s without recording it',
    (anchoredTimestamp) => {
      expect(() => daemon.recordAttestation({
        agentId: agent1,
        epoch: 10n,
        anchoredTimestamp,
        attestationDigest: digest1,
      })).toThrow('positive finite number');
      expect(daemon.getRecordCount()).toBe(0);
    }
  );

  it('accepts a zero max age and prunes past records', () => {
    daemon.recordAttestation({
      agentId: agent1,
      epoch: 10n,
      anchoredTimestamp: Date.now() - 1,
      attestationDigest: digest1,
    });

    expect(daemon.prune({ maxAgeMs: 0 }).prunedCount).toBe(1);
    expect(daemon.getRecordCount()).toBe(0);
  });
});
