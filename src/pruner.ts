import { type Hex } from 'viem';

export interface PruningFilter {
  maxAgeMs?: number;
  retentionEpochThreshold?: bigint;
  /**
   * Optional whitelist of agent IDs to selectively prune or retain.
   */
  targetAgentIds?: Hex[];
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
  private maxRetainedCapacity?: number;

  constructor(defaultMaxAgeMs: number = 86_400_000, maxRetainedCapacity?: number) {
    assertMaxAgeMs(defaultMaxAgeMs, 'defaultMaxAgeMs');
    this.defaultMaxAgeMs = defaultMaxAgeMs;
    this.maxRetainedCapacity = maxRetainedCapacity;
  }

  public recordAttestation(entry: EpochArchiveEntry): void {
    if (!Number.isFinite(entry.anchoredTimestamp) || entry.anchoredTimestamp <= 0) {
      throw new RangeError('anchoredTimestamp must be a positive finite number');
    }
    this.archive.push({ ...entry });

    // Enforce high-watermark capacity if set
    if (this.maxRetainedCapacity !== undefined && this.archive.length > this.maxRetainedCapacity) {
      // Sort ascending by epoch and drop oldest
      this.archive.sort((a, b) => (a.epoch < b.epoch ? -1 : a.epoch > b.epoch ? 1 : 0));
      while (this.archive.length > this.maxRetainedCapacity) {
        this.archive.shift();
      }
    }
  }

  public getRecordCount(): number {
    return this.archive.length;
  }

  public getRecords(): readonly EpochArchiveEntry[] {
    return this.archive.map((entry) => ({ ...entry }));
  }

  public getRecordsByAgent(agentId: Hex): readonly EpochArchiveEntry[] {
    const target = agentId.toLowerCase();
    return this.archive
      .filter((entry) => entry.agentId.toLowerCase() === target)
      .map((entry) => ({ ...entry }));
  }

  /**
   * Runs GC cycle based on age, epoch boundaries, and optional agent filters
   */
  public prune(filter: PruningFilter = {}): PruningReport {
    const maxAgeMs = filter.maxAgeMs ?? this.defaultMaxAgeMs;
    assertMaxAgeMs(maxAgeMs, 'maxAgeMs');
    const now = Date.now();
    const thresholdEpoch = filter.retentionEpochThreshold;
    const targetAgents = filter.targetAgentIds?.map((id) => id.toLowerCase());

    const retained: EpochArchiveEntry[] = [];
    const pruned: EpochArchiveEntry[] = [];

    for (const item of this.archive) {
      const matchesAgent = !targetAgents || targetAgents.includes(item.agentId.toLowerCase());
      if (matchesAgent) {
        const isExpiredByAge = now - item.anchoredTimestamp > maxAgeMs;
        const isExpiredByEpoch = thresholdEpoch !== undefined && item.epoch < thresholdEpoch;

        if (isExpiredByAge || isExpiredByEpoch) {
          pruned.push(item);
          continue;
        }
      }
      retained.push(item);
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
