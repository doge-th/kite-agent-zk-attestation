import { type Hex } from 'viem';

export interface PruningFilter {
  maxAgeMs?: number;
  retentionEpochThreshold?: bigint;
}

export interface EpochArchiveEntry {
  agentId: Hex;
  epoch: bigint;
  anchoredTimestamp: number;
  attestationDigest: Hex;
}

export interface PruningReport {
  scannedCount: number;
  prunedCount: number;
  retainedCount: number;
  prunedEpochs: Array<{ agentId: Hex; epoch: bigint }>;
}

function assertMaxAgeMs(value: number, field: string): void {
  if (!Number.isFinite(value) || value < 0) {
    throw new RangeError(`${field} must be a non-negative finite number`);
  }
}

/**
 * AttestationPrunerDaemon
 * Manages cache lifecycle and purges expired epoch attestation proofs from local hot storage
 */
export class AttestationPrunerDaemon {
  private archive: EpochArchiveEntry[] = [];
  private defaultMaxAgeMs: number;

  constructor(defaultMaxAgeMs: number = 86_400_000) {
    assertMaxAgeMs(defaultMaxAgeMs, 'defaultMaxAgeMs');
    this.defaultMaxAgeMs = defaultMaxAgeMs;
  }

  public recordAttestation(entry: EpochArchiveEntry): void {
    if (!Number.isFinite(entry.anchoredTimestamp) || entry.anchoredTimestamp <= 0) {
      throw new RangeError('anchoredTimestamp must be a positive finite number');
    }
    this.archive.push({ ...entry });
  }

  public getRecordCount(): number {
    return this.archive.length;
  }

  public getRecords(): readonly EpochArchiveEntry[] {
    return this.archive.map(entry => ({ ...entry }));
  }

  /**
   * Runs GC cycle based on age and epoch boundaries
   */
  public prune(filter: PruningFilter = {}): PruningReport {
    const maxAgeMs = filter.maxAgeMs ?? this.defaultMaxAgeMs;
    assertMaxAgeMs(maxAgeMs, 'maxAgeMs');
    const now = Date.now();
    const thresholdEpoch = filter.retentionEpochThreshold;

    const retained: EpochArchiveEntry[] = [];
    const pruned: EpochArchiveEntry[] = [];

    for (const item of this.archive) {
      const isExpiredByAge = now - item.anchoredTimestamp > maxAgeMs;
      const isExpiredByEpoch = thresholdEpoch !== undefined && item.epoch < thresholdEpoch;

      if (isExpiredByAge || isExpiredByEpoch) {
        pruned.push(item);
      } else {
        retained.push(item);
      }
    }

    this.archive = retained;

    return {
      scannedCount: retained.length + pruned.length,
      prunedCount: pruned.length,
      retainedCount: retained.length,
      prunedEpochs: pruned.map((p) => ({ agentId: p.agentId, epoch: p.epoch })),
    };
  }
}
