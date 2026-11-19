import { describe, it, expect, beforeEach } from 'vitest';
import { AttestationPrunerDaemon } from '../src/pruner.js';
import { type Hex } from 'viem';

describe('AttestationPrunerDaemon', () => {
  let daemon: AttestationPrunerDaemon;

  const agent1: Hex = '0x1111111111111111111111111111111111111111111111111111111111111111';
  const digest1: Hex = '0xaaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111';

  beforeEach(() => {
    daemon = new AttestationPrunerDaemon(3600_000); // 1 hour default
  });

  it('records new attestation entries', () => {
    daemon.recordAttestation({
      agentId: agent1,
      epoch: 10n,
      anchoredTimestamp: Date.now(),
      attestationDigest: digest1,
    });

    expect(daemon.getRecordCount()).toBe(1);
    expect(daemon.getRecords()[0].epoch).toBe(10n);
  });

  it('prunes expired entries by timestamp age', () => {
    const twoHoursAgo = Date.now() - 7200_000;
    daemon.recordAttestation({
      agentId: agent1,
      epoch: 5n,
      anchoredTimestamp: twoHoursAgo,
      attestationDigest: digest1,
    });
    daemon.recordAttestation({
      agentId: agent1,
      epoch: 10n,
      anchoredTimestamp: Date.now(),
      attestationDigest: digest1,
    });

    const report = daemon.prune();
    expect(report.scannedCount).toBe(2);
    expect(report.prunedCount).toBe(1);
    expect(report.retainedCount).toBe(1);
    expect(daemon.getRecordCount()).toBe(1);
    expect(daemon.getRecords()[0].epoch).toBe(10n);
  });

  it('prunes entries by retention epoch threshold', () => {
    daemon.recordAttestation({
      agentId: agent1,
      epoch: 5n,
      anchoredTimestamp: Date.now(),
      attestationDigest: digest1,
    });
    daemon.recordAttestation({
      agentId: agent1,
      epoch: 15n,
      anchoredTimestamp: Date.now(),
      attestationDigest: digest1,
    });

    const report = daemon.prune({ retentionEpochThreshold: 10n });
    expect(report.prunedCount).toBe(1);
    expect(report.retainedCount).toBe(1);
    expect(daemon.getRecords()[0].epoch).toBe(15n);
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
