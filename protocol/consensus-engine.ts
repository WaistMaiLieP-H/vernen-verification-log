/**
 * Consensus Engine — Cross-model verification layer.
 *
 * Layer 5c of the verification protocol. Builds on the basic consensus_group_id
 * support in VerificationEngine to provide:
 *
 *   - Weighted consensus across models with different trust weights
 *   - Provider deduplication (3 Claude variants ≠ 3 providers)
 *   - Threshold-based "consensus reached" / "dispute" classification
 *   - Dispute records for human review when models disagree
 *   - Aggregate statistics across all consensus groups
 *
 * This is the model-agnostic verification layer that turns Vernen from
 * "Claude tool" into "verification standard usable by any frontier model."
 *
 * Public domain — CC0-1.0
 */

import type { Env } from "../index.js";

// ─── Default weights (configurable per deployment) ──────────────────────────

export const DEFAULT_MODEL_WEIGHTS: Record<string, number> = {
  // Anthropic
  "claude-opus-4-6": 1.0,
  "claude-sonnet-4-6": 0.9,
  "claude-haiku-4-5": 0.7,
  "claude-3-opus": 0.85,
  "claude-3-sonnet": 0.75,

  // OpenAI
  "gpt-4o": 0.9,
  "gpt-4-turbo": 0.85,
  "gpt-4": 0.8,
  "o1-preview": 0.95,
  "o1-mini": 0.8,

  // Google
  "gemini-2-pro": 0.9,
  "gemini-1-5-pro": 0.85,
  "gemini-1-5-flash": 0.7,

  // Meta / open source
  "llama-3-1-405b": 0.8,
  "llama-3-1-70b": 0.7,

  // Deterministic baseline
  "deterministic": 0.6,

  // Unknown / fallback
  "unknown": 0.5,
};

// ─── Provider mapping for deduplication ─────────────────────────────────────

export const MODEL_TO_PROVIDER: Record<string, string> = {
  "claude-opus-4-6": "anthropic",
  "claude-sonnet-4-6": "anthropic",
  "claude-haiku-4-5": "anthropic",
  "claude-3-opus": "anthropic",
  "claude-3-sonnet": "anthropic",
  "gpt-4o": "openai",
  "gpt-4-turbo": "openai",
  "gpt-4": "openai",
  "o1-preview": "openai",
  "o1-mini": "openai",
  "gemini-2-pro": "google",
  "gemini-1-5-pro": "google",
  "gemini-1-5-flash": "google",
  "llama-3-1-405b": "meta",
  "llama-3-1-70b": "meta",
  "deterministic": "vernen",
};

export type ConsensusStatus = "PENDING" | "REACHED" | "DISPUTED" | "INSUFFICIENT";

export interface ConsensusThresholds {
  minMembers: number;          // Minimum total records to call consensus
  minProviders: number;        // Minimum distinct providers required
  minAgreementPercent: number; // Minimum weighted agreement % to count as consensus
}

export const DEFAULT_THRESHOLDS: ConsensusThresholds = {
  minMembers: 3,
  minProviders: 2,
  minAgreementPercent: 67,
};

// ─── Types ───────────────────────────────────────────────────────────────────

export interface WeightedConsensusResult {
  consensusGroupId: string;
  status: ConsensusStatus;
  memberCount: number;
  uniqueProviderCount: number;
  uniqueModelCount: number;
  weightedDeterminations: Record<string, number>;
  rawDeterminations: Record<string, number>;
  majorityDetermination: string | null;
  weightedAgreementPercent: number;
  rawAgreementPercent: number;
  thresholds: ConsensusThresholds;
  members: Array<{
    seq: number;
    recordId: string;
    modelName: string;
    provider: string;
    weight: number;
    determination: string;
  }>;
}

// ─── Engine ──────────────────────────────────────────────────────────────────

export class ConsensusEngine {
  constructor(
    private env: Env,
    private weights: Record<string, number> = DEFAULT_MODEL_WEIGHTS,
    private thresholds: ConsensusThresholds = DEFAULT_THRESHOLDS
  ) {}

  /**
   * Bootstrap the consensus tables. Idempotent.
   */
  async ensureTables(): Promise<void> {
    const db = this.env.DB;
    await db.batch([
      db.prepare(`CREATE TABLE IF NOT EXISTS consensus_disputes (
        id TEXT PRIMARY KEY,
        consensus_group_id TEXT NOT NULL,
        member_count INTEGER NOT NULL,
        unique_providers INTEGER NOT NULL,
        weighted_agreement_percent INTEGER NOT NULL,
        majority_determination TEXT,
        all_determinations TEXT NOT NULL,
        notes TEXT,
        status TEXT NOT NULL DEFAULT 'OPEN',
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        resolved_at TEXT,
        resolved_by TEXT,
        resolution TEXT
      )`),
      db.prepare(`CREATE INDEX IF NOT EXISTS idx_disputes_group ON consensus_disputes(consensus_group_id)`),
      db.prepare(`CREATE INDEX IF NOT EXISTS idx_disputes_status ON consensus_disputes(status)`),
      db.prepare(`CREATE TABLE IF NOT EXISTS consensus_events (
        id TEXT PRIMARY KEY,
        consensus_group_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        member_count INTEGER NOT NULL,
        weighted_agreement_percent INTEGER NOT NULL,
        majority_determination TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      )`),
      db.prepare(`CREATE INDEX IF NOT EXISTS idx_events_group ON consensus_events(consensus_group_id)`),
      db.prepare(`CREATE INDEX IF NOT EXISTS idx_events_type ON consensus_events(event_type)`),
    ]);
  }

  /**
   * Compute the full weighted consensus for a group.
   */
  async computeConsensus(consensusGroupId: string): Promise<WeightedConsensusResult> {
    await this.ensureTables();
    const db = this.env.DB;

    const rows = await db
      .prepare(
        `SELECT seq, record_id, model_name, metadata
         FROM verification_log
         WHERE consensus_group_id = ?1
         ORDER BY seq ASC`
      )
      .bind(consensusGroupId)
      .all<{
        seq: number;
        record_id: string;
        model_name: string | null;
        metadata: string | null;
      }>();

    const members = (rows.results ?? []).map((r) => {
      let determination = "UNKNOWN";
      try {
        const meta = JSON.parse(r.metadata ?? "{}") as Record<string, unknown>;
        determination = (meta["determination"] as string) ?? "UNKNOWN";
      } catch {
        // ignore
      }
      const modelName = r.model_name ?? "unknown";
      const provider = MODEL_TO_PROVIDER[modelName] ?? "unknown";
      const weight = this.weights[modelName] ?? this.weights["unknown"] ?? 0.5;
      return {
        seq: r.seq,
        recordId: r.record_id,
        modelName,
        provider,
        weight,
        determination,
      };
    });

    // Raw counts
    const rawDeterminations: Record<string, number> = {};
    const weightedDeterminations: Record<string, number> = {};
    const providersSeen = new Set<string>();
    const modelsSeen = new Set<string>();

    for (const m of members) {
      rawDeterminations[m.determination] = (rawDeterminations[m.determination] ?? 0) + 1;
      weightedDeterminations[m.determination] =
        (weightedDeterminations[m.determination] ?? 0) + m.weight;
      providersSeen.add(m.provider);
      modelsSeen.add(m.modelName);
    }

    // Find majority by weighted score
    let majorityDetermination: string | null = null;
    let maxWeight = 0;
    let totalWeight = 0;
    for (const [det, w] of Object.entries(weightedDeterminations)) {
      totalWeight += w;
      if (w > maxWeight) {
        maxWeight = w;
        majorityDetermination = det;
      }
    }

    const weightedAgreementPercent =
      totalWeight > 0 ? Math.round((maxWeight / totalWeight) * 100) : 0;

    // Find majority by raw count
    let rawMaxCount = 0;
    let rawTotal = 0;
    for (const c of Object.values(rawDeterminations)) {
      rawTotal += c;
      if (c > rawMaxCount) rawMaxCount = c;
    }
    const rawAgreementPercent =
      rawTotal > 0 ? Math.round((rawMaxCount / rawTotal) * 100) : 0;

    // Determine status
    let status: ConsensusStatus;
    if (members.length < this.thresholds.minMembers) {
      status = "INSUFFICIENT";
    } else if (providersSeen.size < this.thresholds.minProviders) {
      status = "INSUFFICIENT";
    } else if (weightedAgreementPercent >= this.thresholds.minAgreementPercent) {
      status = "REACHED";
    } else {
      status = "DISPUTED";
    }

    return {
      consensusGroupId,
      status,
      memberCount: members.length,
      uniqueProviderCount: providersSeen.size,
      uniqueModelCount: modelsSeen.size,
      weightedDeterminations,
      rawDeterminations,
      majorityDetermination,
      weightedAgreementPercent,
      rawAgreementPercent,
      thresholds: this.thresholds,
      members,
    };
  }

  /**
   * Run consensus computation and side-effect: create dispute or event records.
   */
  async finalizeConsensus(consensusGroupId: string): Promise<{
    status: ConsensusStatus;
    eventCreated: boolean;
    disputeCreated: boolean;
    result: WeightedConsensusResult;
  }> {
    await this.ensureTables();
    const result = await this.computeConsensus(consensusGroupId);
    const db = this.env.DB;
    const id = `evt_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

    let eventCreated = false;
    let disputeCreated = false;

    if (result.status === "REACHED") {
      // Log a "consensus reached" event
      await db
        .prepare(
          `INSERT INTO consensus_events
            (id, consensus_group_id, event_type, member_count,
             weighted_agreement_percent, majority_determination)
           VALUES (?1, ?2, 'CONSENSUS_REACHED', ?3, ?4, ?5)`
        )
        .bind(
          id,
          consensusGroupId,
          result.memberCount,
          result.weightedAgreementPercent,
          result.majorityDetermination ?? null
        )
        .run();
      eventCreated = true;
    } else if (result.status === "DISPUTED") {
      // Create a dispute record + log event
      const disputeId = `disp_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
      await db
        .prepare(
          `INSERT INTO consensus_disputes
            (id, consensus_group_id, member_count, unique_providers,
             weighted_agreement_percent, majority_determination,
             all_determinations, notes, status)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'OPEN')`
        )
        .bind(
          disputeId,
          consensusGroupId,
          result.memberCount,
          result.uniqueProviderCount,
          result.weightedAgreementPercent,
          result.majorityDetermination ?? null,
          JSON.stringify(result.weightedDeterminations),
          `Models disagreed: ${Object.keys(result.weightedDeterminations).join(", ")}`
        )
        .run();
      await db
        .prepare(
          `INSERT INTO consensus_events
            (id, consensus_group_id, event_type, member_count,
             weighted_agreement_percent, majority_determination)
           VALUES (?1, ?2, 'DISPUTE_OPENED', ?3, ?4, ?5)`
        )
        .bind(
          id,
          consensusGroupId,
          result.memberCount,
          result.weightedAgreementPercent,
          result.majorityDetermination ?? null
        )
        .run();
      eventCreated = true;
      disputeCreated = true;
    }

    return {
      status: result.status,
      eventCreated,
      disputeCreated,
      result,
    };
  }

  /**
   * List all consensus groups (deduplicated).
   */
  async listConsensusGroups(filters: {
    status?: ConsensusStatus;
    limit?: number;
  } = {}): Promise<Array<{
    consensusGroupId: string;
    memberCount: number;
    firstSeen: string;
    lastSeen: string;
  }>> {
    await this.ensureTables();
    const db = this.env.DB;
    const limit = Math.min(filters.limit ?? 50, 200);
    const result = await db
      .prepare(
        `SELECT consensus_group_id, COUNT(*) as cnt,
                MIN(created_at) as first_seen,
                MAX(created_at) as last_seen
         FROM verification_log
         WHERE consensus_group_id IS NOT NULL
         GROUP BY consensus_group_id
         ORDER BY MAX(seq) DESC
         LIMIT ?1`
      )
      .bind(limit)
      .all<{
        consensus_group_id: string;
        cnt: number;
        first_seen: string;
        last_seen: string;
      }>();

    return (result.results ?? []).map((r) => ({
      consensusGroupId: r.consensus_group_id,
      memberCount: r.cnt,
      firstSeen: r.first_seen,
      lastSeen: r.last_seen,
    }));
  }

  /**
   * Aggregate stats across all consensus groups.
   */
  async getStats(): Promise<{
    totalGroups: number;
    totalMembers: number;
    averageMembersPerGroup: number;
    eventsLogged: number;
    openDisputes: number;
    resolvedDisputes: number;
  }> {
    await this.ensureTables();
    const db = this.env.DB;

    const [groupsRow, eventsRow, openDisp, resolvedDisp] = await db.batch([
      db.prepare(
        `SELECT COUNT(DISTINCT consensus_group_id) as groups,
                COUNT(*) as members
         FROM verification_log
         WHERE consensus_group_id IS NOT NULL`
      ),
      db.prepare(`SELECT COUNT(*) as cnt FROM consensus_events`),
      db.prepare(`SELECT COUNT(*) as cnt FROM consensus_disputes WHERE status = 'OPEN'`),
      db.prepare(`SELECT COUNT(*) as cnt FROM consensus_disputes WHERE status = 'RESOLVED'`),
    ]);

    const groups = (groupsRow?.results?.[0] as { groups: number; members: number } | undefined) ?? { groups: 0, members: 0 };
    const events = (eventsRow?.results?.[0] as { cnt: number } | undefined) ?? { cnt: 0 };
    const open = (openDisp?.results?.[0] as { cnt: number } | undefined) ?? { cnt: 0 };
    const resolved = (resolvedDisp?.results?.[0] as { cnt: number } | undefined) ?? { cnt: 0 };

    return {
      totalGroups: groups.groups,
      totalMembers: groups.members,
      averageMembersPerGroup: groups.groups > 0 ? Math.round((groups.members / groups.groups) * 10) / 10 : 0,
      eventsLogged: events.cnt,
      openDisputes: open.cnt,
      resolvedDisputes: resolved.cnt,
    };
  }
}
