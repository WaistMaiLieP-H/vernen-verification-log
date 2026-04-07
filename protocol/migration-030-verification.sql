-- Migration 030: Verification Engine (Hash Chain + Merkle Anchors)
-- Creates the substrate for cryptographically verifiable Citizen activity.
-- See docs/VERIFIABILITY_ARCHITECTURE.md

-- ─────────────────────────────────────────────────────────────────────────────
-- verification_log — append-only hash chain
-- Each row links to the previous via prev_hash. The combined_hash is what
-- gets folded into the daily Merkle tree.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS verification_log (
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
);

CREATE INDEX IF NOT EXISTS idx_verlog_type ON verification_log(record_type);
CREATE INDEX IF NOT EXISTS idx_verlog_source ON verification_log(source_table, source_id);
CREATE INDEX IF NOT EXISTS idx_verlog_created ON verification_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_verlog_combined ON verification_log(combined_hash);

-- ─────────────────────────────────────────────────────────────────────────────
-- verification_merkle_roots — daily Merkle anchors
-- Computed at end of each UTC day. Optionally published to GitHub / Bitcoin.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS verification_merkle_roots (
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
);

CREATE INDEX IF NOT EXISTS idx_merkle_date ON verification_merkle_roots(date DESC);
CREATE INDEX IF NOT EXISTS idx_merkle_root ON verification_merkle_roots(merkle_root);

-- ─────────────────────────────────────────────────────────────────────────────
-- verification_proofs — cached Merkle proofs for individual records
-- Lets external parties verify a record exists without trusting us or
-- recomputing the entire tree.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS verification_proofs (
  record_id TEXT PRIMARY KEY,
  merkle_root TEXT NOT NULL,
  proof_path TEXT NOT NULL,
  leaf_index INTEGER NOT NULL,
  computed_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_proofs_root ON verification_proofs(merkle_root);
