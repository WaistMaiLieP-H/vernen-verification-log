/**
 * VerificationEngine — Cryptographic verifiability for Citizen activity.
 *
 * Implements an append-only hash chain (Layer 1) and daily Merkle tree
 * computation (Layer 2). External anchoring (GitHub / Bitcoin) is handled
 * by VerificationAnchor.
 *
 * See docs/VERIFIABILITY_ARCHITECTURE.md for the full spec.
 *
 * Implementation notes:
 * - All hashing uses Web Crypto (`crypto.subtle.digest`) — Workers compatible.
 * - Canonical JSON: object keys sorted recursively before stringify.
 * - Genesis hash: SHA-256("VERNEN_GENESIS_2026") — hardcoded constant.
 * - Merkle: standard binary tree, duplicate last leaf if odd, SHA256(left||right).
 * - All writes go through db.batch() / db.prepare().run() — never db.exec().
 *
 * NOTE: This file replaces the previous compliance-stamp VerificationEngine.
 * That class had no callers in the codebase at the time of replacement.
 */

import type { Env } from "../index.js";

const GENESIS_SEED = "VERNEN_GENESIS_2026";

export interface AppendRecordParams {
  recordId: string;
  recordType: string;
  sourceTable: string;
  sourceId: string;
  content: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

export interface AppendRecordResult {
  seq: number;
  combinedHash: string;
  contentHash: string;
  prevHash: string;
}

export interface VerifyRecordResult {
  valid: boolean;
  seq: number;
  contentMatches: boolean;
  chainIntact: boolean;
  inMerkleTree: boolean;
  merkleRoot: string | null;
  githubAnchor: string | null;
  error?: string;
}

export interface DailyRootResult {
  root: string;
  recordCount: number;
  firstSeq: number;
  lastSeq: number;
}

export interface MerkleProofResult {
  root: string;
  proofPath: string[];
  leafIndex: number;
}

interface VerLogRow {
  seq: number;
  record_id: string;
  record_type: string;
  source_table: string;
  source_id: string;
  content_hash: string;
  prev_hash: string;
  combined_hash: string;
  created_at: string;
  metadata: string | null;
}

export class VerificationEngine {
  constructor(private env: Env) {}

  // ─────────────────────────────────────────────────────────────────────────
  // Table bootstrap (idempotent — safe to call before any operation)
  // ─────────────────────────────────────────────────────────────────────────
  async ensureTables(): Promise<void> {
    const db = this.env.DB;
    await db.batch([
      db.prepare(
        `CREATE TABLE IF NOT EXISTS verification_log (
          seq INTEGER PRIMARY KEY AUTOINCREMENT,
          record_id TEXT NOT NULL UNIQUE,
          record_type TEXT NOT NULL,
          source_table TEXT NOT NULL,
          source_id TEXT NOT NULL,
          content_hash TEXT NOT NULL,
          prev_hash TEXT NOT NULL,
          combined_hash TEXT NOT NULL,
          created_at TEXT NOT NULL DEFAULT (datetime('now')),
          metadata TEXT DEFAULT '{}'
        )`
      ),
      db.prepare(`CREATE INDEX IF NOT EXISTS idx_verlog_type ON verification_log(record_type)`),
      db.prepare(`CREATE INDEX IF NOT EXISTS idx_verlog_source ON verification_log(source_table, source_id)`),
      db.prepare(`CREATE INDEX IF NOT EXISTS idx_verlog_created ON verification_log(created_at DESC)`),
      db.prepare(`CREATE INDEX IF NOT EXISTS idx_verlog_combined ON verification_log(combined_hash)`),
      db.prepare(
        `CREATE TABLE IF NOT EXISTS verification_merkle_roots (
          date TEXT PRIMARY KEY,
          merkle_root TEXT NOT NULL,
          record_count INTEGER NOT NULL,
          first_seq INTEGER NOT NULL,
          last_seq INTEGER NOT NULL,
          github_commit_sha TEXT,
          github_commit_url TEXT,
          ots_proof BLOB,
          ots_btc_block INTEGER,
          computed_at TEXT NOT NULL DEFAULT (datetime('now'))
        )`
      ),
      db.prepare(`CREATE INDEX IF NOT EXISTS idx_merkle_date ON verification_merkle_roots(date DESC)`),
      db.prepare(
        `CREATE TABLE IF NOT EXISTS verification_proofs (
          record_id TEXT PRIMARY KEY,
          merkle_root TEXT NOT NULL,
          proof_path TEXT NOT NULL,
          leaf_index INTEGER NOT NULL,
          computed_at TEXT NOT NULL DEFAULT (datetime('now'))
        )`
      ),
      db.prepare(`CREATE INDEX IF NOT EXISTS idx_proofs_root ON verification_proofs(merkle_root)`),
    ]);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Core: append a new record to the hash chain
  // ─────────────────────────────────────────────────────────────────────────
  async appendRecord(params: AppendRecordParams): Promise<AppendRecordResult> {
    await this.ensureTables();
    const db = this.env.DB;

    const contentHash = await this.canonicalHash(params.content);
    const prevHash = await this.getLatestHash(db);
    const createdAt = new Date().toISOString();

    // combined_hash = SHA-256(content_hash + prev_hash + record_id + timestamp)
    const combinedHash = await sha256Hex(
      contentHash + prevHash + params.recordId + createdAt
    );

    const metadataStr = JSON.stringify(params.metadata ?? {});

    const result = await db
      .prepare(
        `INSERT INTO verification_log
          (record_id, record_type, source_table, source_id,
           content_hash, prev_hash, combined_hash, created_at, metadata)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)`
      )
      .bind(
        params.recordId,
        params.recordType,
        params.sourceTable,
        params.sourceId,
        contentHash,
        prevHash,
        combinedHash,
        createdAt,
        metadataStr
      )
      .run();

    const seq = Number(result.meta.last_row_id ?? 0);
    return { seq, combinedHash, contentHash, prevHash };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Canonical JSON hashing — deterministic across systems
  // ─────────────────────────────────────────────────────────────────────────
  async canonicalHash(content: Record<string, unknown>): Promise<string> {
    const canonical = canonicalize(content);
    return sha256Hex(canonical);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Get the most recent combined_hash (or genesis if chain empty)
  // ─────────────────────────────────────────────────────────────────────────
  async getLatestHash(db: D1Database): Promise<string> {
    const row = await db
      .prepare(`SELECT combined_hash FROM verification_log ORDER BY seq DESC LIMIT 1`)
      .first<{ combined_hash: string }>();
    if (row?.combined_hash) return row.combined_hash;
    return await getGenesisHash();
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Verify a single record's integrity
  // ─────────────────────────────────────────────────────────────────────────
  async verifyRecord(recordId: string): Promise<VerifyRecordResult> {
    const db = this.env.DB;

    const row = await db
      .prepare(`SELECT * FROM verification_log WHERE record_id = ?1`)
      .bind(recordId)
      .first<VerLogRow>();

    if (!row) {
      return {
        valid: false,
        seq: 0,
        contentMatches: false,
        chainIntact: false,
        inMerkleTree: false,
        merkleRoot: null,
        githubAnchor: null,
        error: "record not found",
      };
    }

    // Verify the combined_hash is internally consistent
    const recomputed = await sha256Hex(
      row.content_hash + row.prev_hash + row.record_id + row.created_at
    );
    const contentMatches = recomputed === row.combined_hash;

    // Verify the prev_hash chain — fetch previous row by seq
    let chainIntact = true;
    if (row.seq > 1) {
      const prev = await db
        .prepare(`SELECT combined_hash FROM verification_log WHERE seq = ?1`)
        .bind(row.seq - 1)
        .first<{ combined_hash: string }>();
      chainIntact = prev?.combined_hash === row.prev_hash;
    } else {
      // Genesis link
      const genesis = await getGenesisHash();
      chainIntact = row.prev_hash === genesis;
    }

    // Check if the record is anchored in a Merkle root
    const proofRow = await db
      .prepare(`SELECT merkle_root FROM verification_proofs WHERE record_id = ?1`)
      .bind(recordId)
      .first<{ merkle_root: string }>();

    const merkleRoot: string | null = proofRow?.merkle_root ?? null;
    let githubAnchor: string | null = null;

    if (merkleRoot) {
      const anchor = await db
        .prepare(`SELECT github_commit_url FROM verification_merkle_roots WHERE merkle_root = ?1`)
        .bind(merkleRoot)
        .first<{ github_commit_url: string | null }>();
      githubAnchor = anchor?.github_commit_url ?? null;
    }

    return {
      valid: contentMatches && chainIntact,
      seq: row.seq,
      contentMatches,
      chainIntact,
      inMerkleTree: merkleRoot !== null,
      merkleRoot,
      githubAnchor,
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Walk the chain from genesis, verify every link
  // Uses a single aggregate query to stay under D1 subrequest limits.
  // ─────────────────────────────────────────────────────────────────────────
  async verifyFullChain(): Promise<{ valid: boolean; brokenAt: number | null; checked: number }> {
    const db = this.env.DB;

    const result = await db
      .prepare(
        `SELECT seq, record_id, content_hash, prev_hash, combined_hash, created_at
         FROM verification_log ORDER BY seq ASC`
      )
      .all<VerLogRow>();

    const rows = (result.results ?? []) as VerLogRow[];
    if (rows.length === 0) return { valid: true, brokenAt: null, checked: 0 };

    const genesis = await getGenesisHash();
    let expectedPrev = genesis;

    for (const row of rows) {
      if (row.prev_hash !== expectedPrev) {
        return { valid: false, brokenAt: row.seq, checked: rows.length };
      }
      const recomputed = await sha256Hex(
        row.content_hash + row.prev_hash + row.record_id + row.created_at
      );
      if (recomputed !== row.combined_hash) {
        return { valid: false, brokenAt: row.seq, checked: rows.length };
      }
      expectedPrev = row.combined_hash;
    }

    return { valid: true, brokenAt: null, checked: rows.length };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Compute the daily Merkle root for a given UTC date (YYYY-MM-DD)
  // ─────────────────────────────────────────────────────────────────────────
  async computeDailyRoot(date: string): Promise<DailyRootResult> {
    await this.ensureTables();
    const db = this.env.DB;

    // Pull all rows for that day in a single query (matches ISO timestamps like 2026-04-07T05:13:14.185Z)
    const result = await db
      .prepare(
        `SELECT seq, record_id, combined_hash FROM verification_log
         WHERE substr(created_at, 1, 10) = ?1
         ORDER BY seq ASC`
      )
      .bind(date)
      .all<{ seq: number; record_id: string; combined_hash: string }>();

    const rows = (result.results ?? []) as Array<{ seq: number; record_id: string; combined_hash: string }>;
    if (rows.length === 0) {
      return { root: "", recordCount: 0, firstSeq: 0, lastSeq: 0 };
    }

    // Build leaves: SHA-256 of each combined_hash
    const leaves: string[] = [];
    for (const r of rows) {
      leaves.push(await sha256Hex(r.combined_hash));
    }

    const tree = await buildMerkleTree(leaves);
    const root = tree[tree.length - 1]![0]!;

    const firstSeq = rows[0]!.seq;
    const lastSeq = rows[rows.length - 1]!.seq;

    // Persist daily root
    await db
      .prepare(
        `INSERT INTO verification_merkle_roots
           (date, merkle_root, record_count, first_seq, last_seq, computed_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(date) DO UPDATE SET
           merkle_root = excluded.merkle_root,
           record_count = excluded.record_count,
           first_seq = excluded.first_seq,
           last_seq = excluded.last_seq,
           computed_at = excluded.computed_at`
      )
      .bind(date, root, rows.length, firstSeq, lastSeq, new Date().toISOString())
      .run();

    // Cache proofs for each leaf — batched to stay under subrequest limits
    const proofStatements: D1PreparedStatement[] = [];
    const computedAt = new Date().toISOString();
    for (let i = 0; i < rows.length; i++) {
      const proofPath = computeProofPath(tree, i);
      proofStatements.push(
        db
          .prepare(
            `INSERT INTO verification_proofs (record_id, merkle_root, proof_path, leaf_index, computed_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(record_id) DO UPDATE SET
               merkle_root = excluded.merkle_root,
               proof_path = excluded.proof_path,
               leaf_index = excluded.leaf_index,
               computed_at = excluded.computed_at`
          )
          .bind(rows[i]!.record_id, root, JSON.stringify(proofPath), i, computedAt)
      );
    }

    // Batch in chunks of 50 to stay safely under the 1000 subrequest limit
    const CHUNK = 50;
    for (let i = 0; i < proofStatements.length; i += CHUNK) {
      const chunk = proofStatements.slice(i, i + CHUNK);
      if (chunk.length > 0) await db.batch(chunk);
    }

    // Layer 3: anchor the root to GitHub if configured. Failure must NOT
    // break root computation — wrap in try/catch and log only.
    if (this.env.GITHUB_TOKEN) {
      try {
        const { VerificationAnchor } = await import("./verification-anchor.js");
        const anchor = new VerificationAnchor(this.env);
        const result = await anchor.publishToGitHub(
          date,
          root,
          rows.length,
          firstSeq,
          lastSeq
        );
        if (result.commitSha) {
          await db
            .prepare(
              `UPDATE verification_merkle_roots
               SET github_commit_sha = ?1, github_commit_url = ?2
               WHERE date = ?3`
            )
            .bind(result.commitSha, result.commitUrl, date)
            .run();
        }
      } catch (err) {
        console.error(
          `[VerificationEngine] GitHub anchoring failed for ${date}:`,
          err instanceof Error ? err.message : err
        );
      }
    }

    return { root, recordCount: rows.length, firstSeq, lastSeq };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Get the cached Merkle proof for a record
  // ─────────────────────────────────────────────────────────────────────────
  async getMerkleProof(recordId: string): Promise<MerkleProofResult> {
    const db = this.env.DB;
    const row = await db
      .prepare(
        `SELECT merkle_root, proof_path, leaf_index FROM verification_proofs WHERE record_id = ?1`
      )
      .bind(recordId)
      .first<{ merkle_root: string; proof_path: string; leaf_index: number }>();

    if (!row) {
      throw new Error(`No Merkle proof cached for record ${recordId}`);
    }

    return {
      root: row.merkle_root,
      proofPath: JSON.parse(row.proof_path) as string[],
      leafIndex: row.leaf_index,
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Pure verification — no DB. Anyone can run this with a leaf, proof, and root.
  // ─────────────────────────────────────────────────────────────────────────
  static async verifyMerkleProof(
    leafHash: string,
    proofPath: string[],
    leafIndex: number,
    expectedRoot: string
  ): Promise<boolean> {
    let current = leafHash;
    let index = leafIndex;
    for (const sibling of proofPath) {
      const left = index % 2 === 0 ? current : sibling;
      const right = index % 2 === 0 ? sibling : current;
      current = await sha256Hex(left + right);
      index = Math.floor(index / 2);
    }
    return current === expectedRoot;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Stats helper
  // ─────────────────────────────────────────────────────────────────────────
  async getStats(): Promise<{
    totalRecords: number;
    latestSeq: number;
    latestCombinedHash: string | null;
    latestMerkleRoot: { date: string; root: string; githubCommit: string | null } | null;
  }> {
    await this.ensureTables();
    const db = this.env.DB;

    const totals = await db
      .prepare(`SELECT COUNT(*) AS total, MAX(seq) AS max_seq FROM verification_log`)
      .first<{ total: number; max_seq: number | null }>();

    const latest = await db
      .prepare(`SELECT combined_hash FROM verification_log ORDER BY seq DESC LIMIT 1`)
      .first<{ combined_hash: string }>();

    const latestRoot = await db
      .prepare(
        `SELECT date, merkle_root, github_commit_url FROM verification_merkle_roots
         ORDER BY date DESC LIMIT 1`
      )
      .first<{ date: string; merkle_root: string; github_commit_url: string | null }>();

    return {
      totalRecords: totals?.total ?? 0,
      latestSeq: totals?.max_seq ?? 0,
      latestCombinedHash: latest?.combined_hash ?? null,
      latestMerkleRoot: latestRoot
        ? { date: latestRoot.date, root: latestRoot.merkle_root, githubCommit: latestRoot.github_commit_url }
        : null,
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Module-private helpers (pure functions)
// ═══════════════════════════════════════════════════════════════════════════

/** Hex-encoded SHA-256 of a UTF-8 string. */
async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const buf = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Genesis hash — SHA-256("VERNEN_GENESIS_2026"). Cached after first call. */
let _genesisHashCache: string | null = null;
async function getGenesisHash(): Promise<string> {
  if (_genesisHashCache) return _genesisHashCache;
  _genesisHashCache = await sha256Hex(GENESIS_SEED);
  return _genesisHashCache;
}

/** Recursively canonicalize: sort object keys, preserve array order. */
function canonicalize(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalize).join(",") + "]";
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return (
    "{" +
    keys.map((k) => JSON.stringify(k) + ":" + canonicalize(obj[k])).join(",") +
    "}"
  );
}

/**
 * Build a Merkle tree as an array of levels.
 * tree[0] = leaves, tree[N-1] = [root].
 * Odd levels duplicate the last node before hashing pairs.
 */
async function buildMerkleTree(leaves: string[]): Promise<string[][]> {
  if (leaves.length === 0) return [[]];
  const tree: string[][] = [leaves.slice()];
  let level = leaves.slice();
  while (level.length > 1) {
    if (level.length % 2 === 1) level.push(level[level.length - 1]!);
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(await sha256Hex(level[i]! + level[i + 1]!));
    }
    tree.push(next);
    level = next;
  }
  return tree;
}

/** Compute the sibling-path proof for a given leaf index. */
function computeProofPath(tree: string[][], leafIndex: number): string[] {
  const proof: string[] = [];
  let index = leafIndex;
  for (let level = 0; level < tree.length - 1; level++) {
    const nodes = tree[level]!;
    // Mirror the duplication logic from buildMerkleTree
    const padded = nodes.length % 2 === 1 ? [...nodes, nodes[nodes.length - 1]!] : nodes;
    const siblingIndex = index % 2 === 0 ? index + 1 : index - 1;
    proof.push(padded[siblingIndex]!);
    index = Math.floor(index / 2);
  }
  return proof;
}
