# Vernen Verifiability Architecture
**Status:** Spec — ready to build
**Created:** 2026-04-06
**Author:** Michael Vernen Thomas Hartmann + Claude

---

## Goal

Make every Citizen execution, audit finding, document intake, and skill log **cryptographically verifiable** without depending on blockchain. Provide the substrate for a future federal verification protocol (Net-Link) where any system can verify any record from any other system without seeing the underlying data.

## Design Principles

1. **Append-only** — records cannot be modified or deleted after creation
2. **Hash-chained** — each record contains the SHA-256 hash of the previous record
3. **Externally anchored** — daily Merkle roots published outside Cloudflare's control
4. **Publicly verifiable** — anyone can verify any record without our cooperation
5. **Privacy preserving** — verify a record exists without revealing its contents
6. **Blockchain optional** — supports OpenTimestamps anchoring for premium tier, but not required

---

## Architecture (4 Layers)

### Layer 1: Hash Chain (D1)
Every verifiable event is appended to a single immutable log.

### Layer 2: Daily Merkle Tree
At end of each UTC day, all records from that day are hashed into a Merkle tree. The root is the day's verification anchor.

### Layer 3: Public Anchoring (GitHub)
Daily Merkle roots are committed to a public GitHub repository (`vernen-verification-log`). Git's distributed nature means once committed, the root is in every clone — can't be silently rewritten.

### Layer 4: Blockchain (Optional, OpenTimestamps)
For high-stakes records (court filings, fraud findings), the daily Merkle root can also be anchored to Bitcoin via OpenTimestamps. Free, automatic, gives Bitcoin-grade immutability.

---

## Database Schema

### `verification_log` (the hash chain)
```sql
CREATE TABLE IF NOT EXISTS verification_log (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  record_id TEXT NOT NULL UNIQUE,
  record_type TEXT NOT NULL,           -- 'skill_execution', 'audit_finding', 'document_intake', 'case_filing', etc.
  source_table TEXT NOT NULL,          -- which D1 table this references
  source_id TEXT NOT NULL,             -- the original record's PK
  content_hash TEXT NOT NULL,          -- SHA-256 of canonical content
  prev_hash TEXT NOT NULL,             -- SHA-256 of previous record (or genesis hash for first)
  combined_hash TEXT NOT NULL,         -- SHA-256(content_hash + prev_hash + record_id + timestamp)
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  metadata TEXT DEFAULT '{}'           -- optional: domain, severity, tags
);
CREATE INDEX idx_verlog_type ON verification_log(record_type);
CREATE INDEX idx_verlog_source ON verification_log(source_table, source_id);
CREATE INDEX idx_verlog_created ON verification_log(created_at DESC);
```

### `verification_merkle_roots` (daily anchors)
```sql
CREATE TABLE IF NOT EXISTS verification_merkle_roots (
  date TEXT PRIMARY KEY,               -- YYYY-MM-DD
  merkle_root TEXT NOT NULL,           -- SHA-256 root of all records from that date
  record_count INTEGER NOT NULL,
  first_seq INTEGER NOT NULL,
  last_seq INTEGER NOT NULL,
  github_commit_sha TEXT,              -- SHA of the GitHub commit anchoring this root
  github_commit_url TEXT,
  ots_proof BLOB,                      -- OpenTimestamps proof (optional)
  ots_btc_block INTEGER,               -- Bitcoin block height (optional)
  computed_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_merkle_date ON verification_merkle_roots(date DESC);
```

### `verification_proofs` (cached Merkle proofs)
```sql
CREATE TABLE IF NOT EXISTS verification_proofs (
  record_id TEXT PRIMARY KEY,
  merkle_root TEXT NOT NULL,
  proof_path TEXT NOT NULL,            -- JSON array of sibling hashes
  leaf_index INTEGER NOT NULL,
  computed_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (merkle_root) REFERENCES verification_merkle_roots(merkle_root)
);
```

---

## Service Design

### `src/services/verification-engine.ts`

```typescript
export class VerificationEngine {
  // Core: append a record to the hash chain
  async appendRecord(params: {
    recordId: string;
    recordType: string;
    sourceTable: string;
    sourceId: string;
    content: Record<string, unknown>;
    metadata?: Record<string, unknown>;
  }): Promise<{ seq: number; combinedHash: string }>;

  // Compute canonical hash of content (deterministic JSON)
  canonicalHash(content: Record<string, unknown>): string;

  // Get the most recent hash (for chaining new records)
  async getLatestHash(db: D1Database): Promise<string>;

  // Verify a single record's chain integrity
  async verifyRecord(recordId: string): Promise<{
    valid: boolean;
    seq: number;
    contentMatches: boolean;
    chainIntact: boolean;
    inMerkleTree: boolean;
    merkleRoot: string | null;
    githubAnchor: string | null;
  }>;

  // Verify the entire chain from genesis
  async verifyFullChain(): Promise<{ valid: boolean; brokenAt: number | null }>;

  // Compute and store daily Merkle root
  async computeDailyRoot(date: string): Promise<{
    root: string;
    recordCount: number;
    firstSeq: number;
    lastSeq: number;
  }>;

  // Get Merkle proof for a specific record
  async getMerkleProof(recordId: string): Promise<{
    root: string;
    proofPath: string[];
    leafIndex: number;
  }>;

  // Verify a Merkle proof without DB access (pure function)
  static verifyMerkleProof(
    leafHash: string,
    proofPath: string[],
    leafIndex: number,
    expectedRoot: string
  ): boolean;
}
```

### `src/services/verification-anchor.ts`

```typescript
export class VerificationAnchor {
  // Publish daily root to GitHub
  async publishToGitHub(date: string, root: string): Promise<{
    commitSha: string;
    commitUrl: string;
  }>;

  // Optional: anchor to Bitcoin via OpenTimestamps
  async anchorToBitcoin(root: string): Promise<{
    proof: Buffer;
  }>;

  // Cron handler: run at end of UTC day
  async runDailyAnchor(): Promise<void>;
}
```

---

## Integration Points

Hook the verification engine into existing services. Each becomes a one-line addition:

### Skill executions (`src/services/skill-registry.ts`)
After `INSERT INTO skill_executions`:
```typescript
await verificationEngine.appendRecord({
  recordId: execution.id,
  recordType: 'skill_execution',
  sourceTable: 'skill_executions',
  sourceId: execution.id,
  content: { skillId, citizenName, findings, determination, executionSummary },
  metadata: { citizen: execution.citizenName }
});
```

### Document intake (`src/services/intake-pipeline.ts`)
After `INSERT INTO document_intake`:
```typescript
await verificationEngine.appendRecord({
  recordId: intake.id,
  recordType: 'document_intake',
  sourceTable: 'document_intake',
  sourceId: intake.id,
  content: { filename, contentHash, extractedTextHash, classifiedAs },
});
```

### Audit findings (`src/services/execution-engine.ts`)
After `INSERT INTO audit_findings`:
```typescript
await verificationEngine.appendRecord({
  recordId: finding.id,
  recordType: 'audit_finding',
  sourceTable: 'audit_findings',
  sourceId: finding.id,
  content: { ruleId, severity, evidence, determination, citizen },
});
```

### Case filings (`src/services/case-management.ts`)
Same pattern. Every cross-document finding gets a hash entry.

---

## API Endpoints

### `src/api/verify.ts`

```
GET  /api/verify/record/:recordId
     → Returns: { valid, seq, contentMatches, chainIntact, inMerkleTree, merkleRoot, githubAnchor }

GET  /api/verify/merkle/:date
     → Returns: { date, merkleRoot, recordCount, githubCommit, btcBlock }

GET  /api/verify/proof/:recordId
     → Returns: { recordId, merkleRoot, proofPath, leafIndex } 
     → Lets external party verify record exists without trusting us

POST /api/verify/document
     → Body: { content }
     → Returns: { hash, exists, firstSeenAt, merkleRoot }
     → Lets anyone hash a document and check if we've seen it

GET  /api/verify/chain/integrity
     → Admin only. Verifies entire hash chain from genesis.

GET  /api/verify/genesis
     → Returns the genesis hash and creation timestamp.

GET  /api/verify/stats
     → Total records, latest seq, latest merkle root, latest github anchor
```

---

## GitHub Anchor Repository

**Repo name:** `vernen-verification-log`
**Visibility:** Public
**Structure:**
```
vernen-verification-log/
├── README.md (explains what this is, how to verify)
├── genesis.json (genesis hash, creation timestamp, version)
├── 2026/
│   ├── 04/
│   │   ├── 06.json  (date, root, count, first_seq, last_seq)
│   │   ├── 07.json
│   │   └── ...
│   └── ...
└── verify.html (browser-based verification tool — pure JS, no backend)
```

Each daily commit message: `Daily Merkle root for 2026-04-06: <root> (<count> records)`

**Why this works:** GitHub's history is itself append-only via Git's hash chain. Multiple parties can clone the repo. If we ever try to rewrite history, anyone with an earlier clone can prove it.

---

## Canonical Hashing

Content hashing must be deterministic across systems. Use:
1. JSON-stringify with sorted keys (recursive)
2. UTF-8 encoding
3. SHA-256
4. Hex-encoded output

```typescript
function canonicalHash(obj: Record<string, unknown>): string {
  const canonical = canonicalize(obj); // sort keys recursively
  const utf8 = new TextEncoder().encode(canonical);
  return crypto.subtle.digest('SHA-256', utf8).then(buf => 
    Array.from(new Uint8Array(buf))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
  );
}
```

---

## Merkle Tree Implementation

Standard binary Merkle tree:
- Leaf nodes: SHA-256 of each record's `combined_hash`
- Internal nodes: SHA-256(left || right)
- Odd number of leaves: duplicate the last one
- Root: top of tree

Proof for a single leaf: array of sibling hashes from leaf to root.

---

## Cron Handler

```typescript
// src/cron.ts (new file)
export async function scheduled(event: ScheduledEvent, env: Env): Promise<void> {
  const yesterday = new Date(Date.now() - 86400000).toISOString().split('T')[0];
  const engine = new VerificationEngine(env);
  const anchor = new VerificationAnchor(env);
  
  // 1. Compute yesterday's Merkle root
  const result = await engine.computeDailyRoot(yesterday);
  
  // 2. Publish to GitHub
  if (env.GITHUB_TOKEN) {
    await anchor.publishToGitHub(yesterday, result.root);
  }
  
  // 3. Optional: anchor to Bitcoin
  if (env.OTS_ENABLED === 'true') {
    await anchor.anchorToBitcoin(result.root);
  }
}
```

`wrangler.toml`:
```toml
[triggers]
crons = ["0 1 * * *"]  # 1 AM UTC daily
```

---

## Required Secrets

```
GITHUB_TOKEN          # PAT with repo write access to vernen-verification-log
GITHUB_REPO           # "michaelvernen/vernen-verification-log"
OTS_ENABLED           # "true" to enable OpenTimestamps anchoring
```

---

## Build Order (Critical Path)

1. **Migration** — create 3 D1 tables (`migration-030-verification.sql`)
2. **VerificationEngine service** — core hash chain logic, ~400 lines
3. **API routes** — `src/api/verify.ts`, ~200 lines
4. **Router registration** — add routes to `src/router.ts`
5. **Integration: skill_executions** — wire into `skill-registry.ts`
6. **Backfill** — script to hash existing 235 skill executions into the chain
7. **Test** — append 5 records, verify each, verify full chain
8. **Daily Merkle root computation** — manual trigger first
9. **GitHub publishing** — set up repo, PAT, publish first root
10. **Cron handler** — automate daily anchoring
11. **Backfill remaining sources** — document intake, audit findings, case filings
12. **Public verify.html** — browser-based verification UI in the GitHub repo
13. **OpenTimestamps anchor (optional)** — Bitcoin anchoring for high-value records

**Estimated effort:** 2-3 build sessions (~$15-25 of credit)

---

## Post-Build: The Demo

To prove verifiability works, run this end-to-end:

1. Submit a real document (e.g., one of your court filings) via `POST /api/intake`
2. System processes it → creates `document_intake` record → `verification_engine.appendRecord()` fires
3. Get the record's verification proof: `GET /api/verify/proof/:recordId`
4. Wait until next daily Merkle root computation
5. Verify the GitHub commit exists for that day
6. Use a third-party Git client to clone `vernen-verification-log` and confirm the same root
7. Modify the original document, hash it again, prove the hash differs
8. Show the proof chain: document → record_id → seq → merkle_root → github_commit → (optional) bitcoin block

Screenshot/record this for the Anthropic pitch.

---

## Why This Architecture is Better Than "Blockchain Everything"

| Concern | Blockchain Approach | This Approach |
|---------|---------------------|---------------|
| Cost per record | $0.01-$50 (gas) | $0 |
| Cost per day | $0.50-$200 (anchoring) | $0 (GitHub) |
| Verification speed | Seconds (RPC call) | Milliseconds (HTTP GET) |
| External dependencies | Ethereum/Bitcoin RPC | GitHub (with backup mirrors) |
| Privacy of contents | Public on-chain | Hashes only, contents stay in D1 |
| Court acceptance | Novel, untested | Established (Cert Transparency, RFC 3161) |
| Implementation effort | Weeks | Days |
| Can add blockchain later | N/A | Yes — Layer 4 is optional anchoring |

---

## Future: The Federation Protocol

Once this exists, expanding to "every court in America" works like this:

1. Each court runs their own Vernen instance with their own hash chain
2. Each court publishes daily Merkle roots to their own public location
3. A federated verification protocol lets any court verify any other court's record
4. Cross-court verification: "Did Santa Clara County issue this order on this date?" → Hash query → Merkle proof from Santa Clara's chain → Yes/No, no underlying record exposed

That's the Net-Link pitch. This document is the foundation.

---

**END OF SPEC**
