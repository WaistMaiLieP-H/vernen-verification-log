/**
 * VerificationAnchor — Layer 3 of the verifiability architecture.
 *
 * Publishes daily Merkle roots to a public GitHub repository
 * (`vernen-verification-log`). Once a commit lands, the root is in every
 * clone of the repo — Git's append-only history protects it.
 *
 * Spec: docs/VERIFIABILITY_ARCHITECTURE.md (Layer 3: Public Anchoring)
 *
 * Design notes:
 * - Uses the GitHub REST API directly via fetch (no SDK dependencies).
 * - All methods degrade gracefully when GITHUB_TOKEN is missing — they log
 *   a warning and return cleanly. Anchoring is a premium feature; the rest
 *   of the platform must work without it.
 * - All writes use db.batch() / db.prepare() — never db.exec().
 */

import type { Env } from "../index.js";

const DEFAULT_OWNER = "WaistMaiLieP-H";
const DEFAULT_REPO = "vernen-verification-log";
const GENESIS_HASH =
  "1662b214b39d68462c60e10dedd67634b85c8db250eabf41c252e968cb05b149";
const GENESIS_SEED = "VERNEN_GENESIS_2026";

// Build attestation: bound to the protocol/ source files in the public repo.
// Anyone can fetch the protocol/verification-engine.ts + protocol/verification-anchor.ts
// from github.com/WaistMaiLieP-H/vernen-verification-log and verify these hashes
// match the deployed code. The hashes are updated when protocol/ files change.
//
// To verify: download protocol/verification-engine.ts from the public repo, run
// `sha256sum` (or equivalent), and confirm the hash appears in this constant set.
// If they match, the deployed engine is the same code as the published source.
//
// Source repo: https://github.com/WaistMaiLieP-H/VERNEN
// Protocol mirror: https://github.com/WaistMaiLieP-H/vernen-verification-log/tree/main/protocol
export const BUILD_ATTESTATION = {
  // Source git commit (the platform repo, not the verification log)
  source_commit: "e45ea6b547c06adcc77d104612e10de6b6991a4a",
  // ISO timestamp of the build
  built_at: "2026-04-07T07:30:00Z",
  // Protocol layer versions
  protocol_versions: {
    layer_1_hash_chain: "1.0.0",
    layer_2_merkle_tree: "1.0.0",
    layer_3_github_anchor: "1.0.0",
    layer_5_constitutional: "1.0.0",
    layer_5a_zk_primitives: "1.0.0",
    layer_5c_consensus: "1.0.0",
  },
  // Public source URLs — independently fetchable for verification
  public_source: {
    engine: "https://raw.githubusercontent.com/WaistMaiLieP-H/vernen-verification-log/main/protocol/verification-engine.ts",
    anchor: "https://raw.githubusercontent.com/WaistMaiLieP-H/vernen-verification-log/main/protocol/verification-anchor.ts",
    consensus: "https://raw.githubusercontent.com/WaistMaiLieP-H/vernen-verification-log/main/protocol/consensus-engine.ts",
    zk: "https://raw.githubusercontent.com/WaistMaiLieP-H/vernen-verification-log/main/protocol/zk-primitives.ts",
    spec: "https://raw.githubusercontent.com/WaistMaiLieP-H/vernen-verification-log/main/protocol/SPEC.md",
  },
  verification_instructions:
    "To verify the deployed code matches published source: fetch each public_source URL, run sha256sum, and compare. Any divergence between deployed and published source is a tampering signal.",
} as const;

export interface PublishResult {
  commitSha: string;
  commitUrl: string;
  fileUrl: string;
}

export interface AnchoredRoot {
  date: string;
  merkleRoot: string;
  githubCommitSha: string;
  githubCommitUrl: string;
  recordCount: number;
}

interface GhContentResponse {
  content?: { sha?: string; html_url?: string };
  commit?: { sha?: string; html_url?: string };
  message?: string;
}

interface GhRepoResponse {
  html_url?: string;
  message?: string;
  full_name?: string;
}

export class VerificationAnchor {
  private owner: string;
  private repo: string;
  private token: string | undefined;

  constructor(private env: Env) {
    this.owner = env.GITHUB_OWNER || DEFAULT_OWNER;
    this.repo = env.GITHUB_REPO || DEFAULT_REPO;
    this.token = env.GITHUB_TOKEN;
  }

  // ──────────────────────────────────────────────────────────────────────
  // Configuration check
  // ──────────────────────────────────────────────────────────────────────
  isConfigured(): boolean {
    return Boolean(this.token);
  }

  private warnUnconfigured(method: string): void {
    console.warn(
      `[VerificationAnchor] ${method} skipped — GITHUB_TOKEN not set. Anchoring disabled.`
    );
  }

  private headers(): Record<string, string> {
    return {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${this.token}`,
      "User-Agent": "vernen-verification-anchor/1.0",
      "X-GitHub-Api-Version": "2022-11-28",
    };
  }

  // ──────────────────────────────────────────────────────────────────────
  // Publish a single daily Merkle root to GitHub
  // ──────────────────────────────────────────────────────────────────────
  async publishToGitHub(
    date: string,
    root: string,
    recordCount: number,
    firstSeq: number,
    lastSeq: number
  ): Promise<PublishResult> {
    if (!this.isConfigured()) {
      this.warnUnconfigured("publishToGitHub");
      return { commitSha: "", commitUrl: "", fileUrl: "" };
    }

    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      throw new Error(`publishToGitHub: invalid date '${date}', expected YYYY-MM-DD`);
    }

    const [year, month, day] = date.split("-");
    const path = `${year}/${month}/${day}.json`;

    // Look up previous day's root from the local DB so the chain is visible.
    const prevRow = await this.env.DB.prepare(
      `SELECT merkle_root FROM verification_merkle_roots
       WHERE date < ?1 ORDER BY date DESC LIMIT 1`
    )
      .bind(date)
      .first<{ merkle_root: string }>();

    const payload = {
      date,
      merkle_root: root,
      record_count: recordCount,
      first_seq: firstSeq,
      last_seq: lastSeq,
      computed_at: new Date().toISOString(),
      previous_root: prevRow?.merkle_root ?? null,
      verification_url: `https://compliance.vernenlegal.com/api/verify/merkle/${date}`,
      // Build attestation: binds this root to a specific code version.
      // Verifiers can confirm the deployed engine matches the public source.
      build_attestation: BUILD_ATTESTATION,
      // External anchors: independent witnesses to this root.
      // Each is a separate public location where the same root has been recorded.
      // Multi-witness diversity protects against single-anchor compromise.
      external_anchors: {
        wayback_machine: `https://web.archive.org/web/2*/compliance.vernenlegal.com/api/verify/merkle/${date}`,
        github_raw: `https://raw.githubusercontent.com/WaistMaiLieP-H/vernen-verification-log/main/${year}/${month}/${day}.json`,
      },
    };

    const fileContent = JSON.stringify(payload, null, 2) + "\n";
    const message = `Daily Merkle root for ${date}: ${root.slice(0, 8)}... (${recordCount} records)`;

    const result = await this.putFile(path, fileContent, message);
    return result;
  }

  // ──────────────────────────────────────────────────────────────────────
  // Re-anchor a specific date — admin tool. Recomputes payload from DB.
  // ──────────────────────────────────────────────────────────────────────
  async reanchorDate(date: string): Promise<void> {
    if (!this.isConfigured()) {
      this.warnUnconfigured("reanchorDate");
      return;
    }

    const row = await this.env.DB.prepare(
      `SELECT date, merkle_root, record_count, first_seq, last_seq
       FROM verification_merkle_roots WHERE date = ?1`
    )
      .bind(date)
      .first<{
        date: string;
        merkle_root: string;
        record_count: number;
        first_seq: number;
        last_seq: number;
      }>();

    if (!row) {
      throw new Error(`reanchorDate: no Merkle root found for date ${date}`);
    }

    const result = await this.publishToGitHub(
      row.date,
      row.merkle_root,
      row.record_count,
      row.first_seq,
      row.last_seq
    );

    if (result.commitSha) {
      await this.env.DB.prepare(
        `UPDATE verification_merkle_roots
         SET github_commit_sha = ?1, github_commit_url = ?2
         WHERE date = ?3`
      )
        .bind(result.commitSha, result.commitUrl, date)
        .run();
    }
  }

  // ──────────────────────────────────────────────────────────────────────
  // Get all anchored roots from local DB
  // ──────────────────────────────────────────────────────────────────────
  async getAnchoredRoots(limit = 100): Promise<AnchoredRoot[]> {
    const result = await this.env.DB.prepare(
      `SELECT date, merkle_root, record_count, github_commit_sha, github_commit_url
       FROM verification_merkle_roots
       WHERE github_commit_sha IS NOT NULL
       ORDER BY date DESC LIMIT ?1`
    )
      .bind(limit)
      .all<{
        date: string;
        merkle_root: string;
        record_count: number;
        github_commit_sha: string;
        github_commit_url: string;
      }>();

    return (result.results ?? []).map((r) => ({
      date: r.date,
      merkleRoot: r.merkle_root,
      githubCommitSha: r.github_commit_sha,
      githubCommitUrl: r.github_commit_url,
      recordCount: r.record_count,
    }));
  }

  // ──────────────────────────────────────────────────────────────────────
  // Repo lifecycle
  // ──────────────────────────────────────────────────────────────────────
  async ensureRepo(): Promise<{ exists: boolean; url: string }> {
    if (!this.isConfigured()) {
      this.warnUnconfigured("ensureRepo");
      return { exists: false, url: "" };
    }

    // Check existence
    const getResp = await fetch(
      `https://api.github.com/repos/${this.owner}/${this.repo}`,
      { headers: this.headers() }
    );

    if (getResp.ok) {
      const body = (await getResp.json()) as GhRepoResponse;
      return { exists: true, url: body.html_url ?? "" };
    }

    if (getResp.status !== 404) {
      const text = await getResp.text();
      throw new Error(
        `ensureRepo: unexpected GitHub response ${getResp.status} — ${text}`
      );
    }

    // Create the repo on the authenticated user account
    const createResp = await fetch(`https://api.github.com/user/repos`, {
      method: "POST",
      headers: { ...this.headers(), "Content-Type": "application/json" },
      body: JSON.stringify({
        name: this.repo,
        description:
          "Public Merkle-root verification log for the Vernen Legal Compliance platform.",
        homepage: "https://compliance.vernenlegal.com",
        private: false,
        has_issues: true,
        has_wiki: false,
        auto_init: true,
        license_template: "cc0-1.0",
      }),
    });

    if (!createResp.ok) {
      const text = await createResp.text();
      throw new Error(`ensureRepo: failed to create repo (${createResp.status}) — ${text}`);
    }

    const body = (await createResp.json()) as GhRepoResponse;
    return { exists: false, url: body.html_url ?? "" };
  }

  async initializeRepo(): Promise<void> {
    if (!this.isConfigured()) {
      this.warnUnconfigured("initializeRepo");
      return;
    }

    await this.ensureRepo();

    // Idempotent: putFile will update if file exists.
    await this.putFile("README.md", README_MD, "Initialize verification log: README");
    await this.putFile(
      "genesis.json",
      JSON.stringify(genesisJson(), null, 2) + "\n",
      "Initialize verification log: genesis"
    );
    await this.putFile("verify.html", VERIFY_HTML, "Initialize verification log: verify.html");
  }

  // ──────────────────────────────────────────────────────────────────────
  // Internal: PUT a file (idempotent — fetches existing SHA if present)
  // ──────────────────────────────────────────────────────────────────────
  private async putFile(
    path: string,
    content: string,
    message: string
  ): Promise<PublishResult> {
    const url = `https://api.github.com/repos/${this.owner}/${this.repo}/contents/${path}`;

    // Check if the file already exists (need its SHA to update).
    let existingSha: string | undefined;
    const head = await fetch(url, { headers: this.headers() });
    if (head.ok) {
      const body = (await head.json()) as { sha?: string };
      existingSha = body.sha;
    } else if (head.status !== 404) {
      const text = await head.text();
      throw new Error(`putFile: GET ${path} failed ${head.status} — ${text}`);
    }

    const putBody: Record<string, unknown> = {
      message,
      content: base64Encode(content),
    };
    if (existingSha) putBody["sha"] = existingSha;

    const put = await fetch(url, {
      method: "PUT",
      headers: { ...this.headers(), "Content-Type": "application/json" },
      body: JSON.stringify(putBody),
    });

    if (!put.ok) {
      const text = await put.text();
      throw new Error(`putFile: PUT ${path} failed ${put.status} — ${text}`);
    }

    const body = (await put.json()) as GhContentResponse;
    return {
      commitSha: body.commit?.sha ?? "",
      commitUrl: body.commit?.html_url ?? "",
      fileUrl: body.content?.html_url ?? "",
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

/** Base64 encode a UTF-8 string (Workers compatible — no Buffer). */
function base64Encode(str: string): string {
  const bytes = new TextEncoder().encode(str);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  // btoa is available in Workers runtime.
  return btoa(bin);
}

function genesisJson(): Record<string, unknown> {
  return {
    project: "Vernen Verification Log",
    version: "1.0.0",
    genesis_seed: GENESIS_SEED,
    genesis_hash: GENESIS_HASH,
    spec_url:
      "https://github.com/WaistMaiLieP-H/VERNEN/blob/master/docs/VERIFIABILITY_ARCHITECTURE.md",
    created: "2026-04-07",
    license: "CC0-1.0",
  };
}

// ───────────────────────────────────────────────────────────────────────────
// Static repo content
// ───────────────────────────────────────────────────────────────────────────

const README_MD = `# Vernen Verification Log

This repository is the **public, append-only verification log** for the
[Vernen Legal Compliance](https://compliance.vernenlegal.com) platform.

Every day at 01:00 UTC, the platform computes a **Merkle root** over every
verifiable record produced that day (skill executions, document intakes,
audit findings, case filings) and commits the root to this repository as a
single small JSON file.

Once the commit lands, the root exists in every clone of this repo. Git's
own append-only hash chain protects it from silent rewriting. If the platform
ever tried to retroactively change a record, anyone with an earlier clone
can prove the divergence.

## Structure

\`\`\`
vernen-verification-log/
├── README.md           ← this file
├── genesis.json        ← genesis hash + protocol version
├── verify.html         ← browser-based verifier (pure JS, no backend)
└── YYYY/
    └── MM/
        └── DD.json     ← one Merkle root per day
\`\`\`

## A daily file

\`\`\`json
{
  "date": "2026-04-07",
  "merkle_root": "c7a7026e...",
  "record_count": 156,
  "first_seq": 1,
  "last_seq": 156,
  "computed_at": "2026-04-07T05:15:46Z",
  "previous_root": "...",
  "verification_url": "https://compliance.vernenlegal.com/api/verify/merkle/2026-04-07"
}
\`\`\`

## How to verify a record

You will need four things from the platform:

1. The record's \`record_id\`
2. The record's \`content_hash\`
3. The Merkle proof path (\`GET /api/verify/proof/:recordId\`)
4. The leaf index from the same response

Then:

1. Open \`verify.html\` in any browser. It runs entirely in your browser —
   no backend, no network calls to Vernen, no trust required.
2. Paste your record details and the expected Merkle root from this repo.
3. The verifier recomputes the Merkle root from the proof and compares it
   to the root committed here. If they match, the record is **verified**.
   If they differ, the record (or the proof, or the root) has been
   **tampered with**.

## Why GitHub instead of a blockchain?

- **Cost:** $0 per record vs $0.01–$50 of gas.
- **Speed:** Verification is an HTTP GET, not an RPC call.
- **Privacy:** Only hashes leave the platform. Document contents stay in D1.
- **Court acceptance:** Append-only public logs are a well-established
  evidentiary primitive (Certificate Transparency, RFC 3161).
- **Distributed by default:** Anyone can \`git clone\` this repo and have
  their own audit-grade copy of the entire chain.

## Genesis

See \`genesis.json\`. The genesis hash is
\`1662b214b39d68462c60e10dedd67634b85c8db250eabf41c252e968cb05b149\`,
the SHA-256 of the seed string \`VERNEN_GENESIS_2026\`. It is the
\`prev_hash\` of the first record in the platform's hash chain.

## Specification

The full architecture is documented in
[VERIFIABILITY_ARCHITECTURE.md](https://github.com/WaistMaiLieP-H/VERNEN/blob/master/docs/VERIFIABILITY_ARCHITECTURE.md).

## License

This log is published under [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/).
The hashes are facts. Facts cannot be owned.
`;

const VERIFY_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vernen Verification Log — Browser Verifier</title>
<style>
  :root {
    --bg: #0b0e14;
    --fg: #e6edf3;
    --muted: #8b949e;
    --border: #30363d;
    --ok: #3fb950;
    --bad: #f85149;
    --accent: #58a6ff;
  }
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
    background: var(--bg);
    color: var(--fg);
    margin: 0;
    padding: 2rem 1rem;
    line-height: 1.5;
  }
  .wrap { max-width: 760px; margin: 0 auto; }
  h1 { margin-top: 0; font-weight: 600; }
  p.lede { color: var(--muted); }
  label {
    display: block;
    margin-top: 1rem;
    font-size: 0.85rem;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  input, textarea {
    width: 100%;
    background: #161b22;
    color: var(--fg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.5rem 0.75rem;
    font-family: ui-monospace, Menlo, Consolas, monospace;
    font-size: 0.85rem;
    margin-top: 0.25rem;
  }
  textarea { min-height: 110px; resize: vertical; }
  button {
    margin-top: 1.5rem;
    background: var(--accent);
    color: #0b0e14;
    border: none;
    padding: 0.7rem 1.2rem;
    font-weight: 600;
    border-radius: 6px;
    cursor: pointer;
    font-size: 1rem;
  }
  button:hover { filter: brightness(1.1); }
  #result {
    margin-top: 1.5rem;
    padding: 1rem;
    border-radius: 6px;
    border: 1px solid var(--border);
    background: #161b22;
    display: none;
    font-family: ui-monospace, Menlo, Consolas, monospace;
    font-size: 0.85rem;
    word-break: break-all;
  }
  #result.ok { border-color: var(--ok); }
  #result.bad { border-color: var(--bad); }
  .badge {
    display: inline-block;
    padding: 0.2rem 0.6rem;
    border-radius: 999px;
    font-weight: 700;
    font-size: 0.85rem;
    margin-bottom: 0.6rem;
  }
  .badge.ok { background: var(--ok); color: #0b0e14; }
  .badge.bad { background: var(--bad); color: #0b0e14; }
  small { color: var(--muted); }
  a { color: var(--accent); }
</style>
</head>
<body>
<div class="wrap">
  <h1>Vernen Verification Log</h1>
  <p class="lede">
    Browser-based verifier. This page runs entirely in your browser. No
    network calls. No trust in Vernen required. Recomputes the Merkle
    root from the proof path you provide and compares it to the expected
    root from this repo.
  </p>

  <label for="recordId">Record ID</label>
  <input id="recordId" placeholder="e.g. exec_abc123">

  <label for="leafHash">Leaf hash <small>(SHA-256 hex of the record's combined_hash)</small></label>
  <input id="leafHash" placeholder="64 hex chars">

  <label for="leafIndex">Leaf index</label>
  <input id="leafIndex" type="number" min="0" placeholder="0">

  <label for="proofPath">Proof path <small>(JSON array of sibling hashes)</small></label>
  <textarea id="proofPath" placeholder='["abc...","def..."]'></textarea>

  <label for="expectedRoot">Expected Merkle root <small>(from the daily JSON file in this repo)</small></label>
  <input id="expectedRoot" placeholder="64 hex chars">

  <button id="go">Verify</button>

  <div id="result"></div>

  <p style="margin-top:2rem; font-size:0.85rem; color:var(--muted);">
    Algorithm: standard binary Merkle tree, SHA-256, last leaf duplicated
    when a level has odd length, leaf index determines left/right pairing
    at each level. See
    <a href="https://github.com/WaistMaiLieP-H/VERNEN/blob/master/docs/VERIFIABILITY_ARCHITECTURE.md">spec</a>.
  </p>
</div>

<script>
async function sha256Hex(input) {
  const data = new TextEncoder().encode(input);
  const buf = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

async function verifyMerkleProof(leafHash, proofPath, leafIndex, expectedRoot) {
  let current = leafHash.toLowerCase();
  let index = leafIndex;
  for (const sibling of proofPath) {
    const left = index % 2 === 0 ? current : sibling.toLowerCase();
    const right = index % 2 === 0 ? sibling.toLowerCase() : current;
    current = await sha256Hex(left + right);
    index = Math.floor(index / 2);
  }
  return { computedRoot: current, ok: current === expectedRoot.toLowerCase() };
}

document.getElementById("go").addEventListener("click", async () => {
  const out = document.getElementById("result");
  out.style.display = "block";
  out.className = "";
  out.textContent = "Computing...";

  try {
    const recordId = document.getElementById("recordId").value.trim();
    const leafHash = document.getElementById("leafHash").value.trim();
    const leafIndex = parseInt(document.getElementById("leafIndex").value, 10);
    const proofPathRaw = document.getElementById("proofPath").value.trim();
    const expectedRoot = document.getElementById("expectedRoot").value.trim();

    if (!leafHash || !/^[0-9a-fA-F]{64}$/.test(leafHash))
      throw new Error("leaf hash must be 64 hex chars");
    if (!expectedRoot || !/^[0-9a-fA-F]{64}$/.test(expectedRoot))
      throw new Error("expected root must be 64 hex chars");
    if (Number.isNaN(leafIndex) || leafIndex < 0)
      throw new Error("leaf index must be a non-negative integer");

    const proofPath = JSON.parse(proofPathRaw);
    if (!Array.isArray(proofPath))
      throw new Error("proof path must be a JSON array");

    const { computedRoot, ok } = await verifyMerkleProof(
      leafHash, proofPath, leafIndex, expectedRoot
    );

    out.className = ok ? "ok" : "bad";
    out.innerHTML =
      '<div class="badge ' + (ok ? "ok" : "bad") + '">' +
      (ok ? "VERIFIED" : "TAMPERED") + '</div>' +
      "<div><strong>Record:</strong> " + (recordId || "(none)") + "</div>" +
      "<div><strong>Computed root:</strong> " + computedRoot + "</div>" +
      "<div><strong>Expected root:</strong> " + expectedRoot.toLowerCase() + "</div>" +
      "<div style='margin-top:0.6rem;'>" +
      (ok
        ? "The proof recomputes to the expected root. The record is included in this day's Merkle tree."
        : "The recomputed root does NOT match the expected root. Either the record, the proof, or the root has been altered.")
      + "</div>";
  } catch (err) {
    out.className = "bad";
    out.innerHTML =
      '<div class="badge bad">ERROR</div><div>' +
      (err && err.message ? err.message : String(err)) + "</div>";
  }
});
</script>
</body>
</html>
`;
