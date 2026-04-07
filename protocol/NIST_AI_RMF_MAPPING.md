# NIST AI RMF 1.0 — Vernen Verification Protocol Mapping

**Date:** 2026-04-07
**Framework:** NIST AI Risk Management Framework 1.0 (NIST AI 100-1, January 2023)
**Subject:** Vernen verification protocol — `compliance.vernenlegal.com` + public anchor at https://github.com/WaistMaiLieP-H/vernen-verification-log

This document maps the Vernen verification protocol to the seven characteristics of trustworthy AI defined in NIST AI RMF 1.0, plus the four core functions (GOVERN, MAP, MEASURE, MANAGE). It is intended to demonstrate that the verification infrastructure is designed for and aligned with established AI risk management standards, not invented in isolation.

---

## Trustworthy AI Characteristics (NIST AI RMF Section 3)

### 1. Valid and Reliable

**NIST definition:** "AI systems that operate as intended, providing confidence in their outputs and managing their failure modes."

**How Vernen addresses this:**
- Every Citizen action is logged with a `combined_hash` derived from a canonicalized JSON representation of the action's content. The hash is deterministic across systems — three independent implementations (TypeScript on Cloudflare Workers, Python, browser JavaScript) produce the same root.
- The chain integrity check (`/api/verify/chain/integrity`) walks the entire hash chain from genesis. As of 2026-04-07, 8,049 records verify with zero broken links.
- Every Merkle proof is independently reproducible without server access. See `protocol/PROOF_DEMO.md` for the end-to-end proof.

**Evidence:** `verification-engine.ts:verifyFullChain()`, `protocol/SPEC.md` Section "Layer 1: Hash Chain"

### 2. Safe

**NIST definition:** "Endeavoring to keep humans and the systems and environment they operate in safe from harm."

**How Vernen addresses this:**
- Verification append failures are non-fatal by design — if the verification chain is unreachable, the underlying business operation (compliance report, skill execution) still completes successfully. This prevents verification infrastructure failure from becoming an availability risk.
- All cryptographic operations use Web Crypto API standards (`crypto.subtle.digest`), no custom or experimental crypto.
- The protocol is privacy-preserving by design: Merkle proofs reveal only hashes, never underlying record contents.

**Evidence:** `verification-engine.ts:appendRecord()` exception handling, `regulis/index.ts` try/catch wrapper around verification calls.

### 3. Secure and Resilient

**NIST definition:** "AI systems that can withstand unexpected adverse events or unexpected changes in their environment or use."

**How Vernen addresses this:**
- **Multiple independent anchor layers:**
  - Layer 1: Internal hash chain (D1)
  - Layer 2: Daily Merkle tree (D1)
  - Layer 3: GitHub commit history (distributed clones)
  - Layer 4: Bitcoin via OpenTimestamps (designed in, optional)
- An adversary would need to compromise all four layers simultaneously to silently rewrite history.
- GitHub anchoring uses a separate secret (`GITHUB_TOKEN`) from the primary API key, providing credential isolation.
- The protocol supports degraded operation: if GitHub publishing fails, the local chain still grows and the daily root is still computed; the publish can be retried later via `POST /api/verify/anchor/publish/:date`.

**Evidence:** `protocol/SPEC.md` Section "4 Layers", `verification-anchor.ts:publishToGitHub()` idempotency.

### 4. Accountable and Transparent

**NIST definition:** "AI system actions [are] transparent... including the actions of a wide range of human actors involved in the design, deployment, and use of the system."

**How Vernen addresses this:**
- **This is the protocol's primary purpose.** Every Citizen action is cryptographically anchored to a public location (GitHub) where it cannot be silently rewritten.
- Constitutional traceability metadata (Layer 5) attaches explicit principle tags to every record — e.g., `HONEST.evidence_backed`, `LEGAL_ACCOUNTABILITY.statutory_citation`. The principles being claimed are part of the hashed content, so they cannot be retroactively asserted.
- 26 named principles across 7 categories, queryable via `GET /api/verify/by-principle/:principle`.
- Public verifier (`verify.html`, `verify.py`) lets any third party verify any record without contacting Vernen.
- The protocol implementation, the spec, and the daily Merkle roots are all in a public CC0/MIT-licensed repository.

**Evidence:** Public repo https://github.com/WaistMaiLieP-H/vernen-verification-log, `constitutional-mapping.ts`, `verify.ts` API routes.

### 5. Explainable and Interpretable

**NIST definition:** "AI systems whose operations can be understood by their stakeholders."

**How Vernen addresses this:**
- Every Citizen has a declared scope (NAICS sub-industry, jurisdiction, governing standards) recorded in `citizen_catalog_positions`.
- Skills are not prompts — they are clusters of real federal failure data with explicit `audit_triggers` and `audit_checklist` fields. The reasoning path from input to finding is reconstructable from the failure cluster.
- The constitutional alignment metadata (Layer 5) makes the *intent* of an action explicit, not just the action itself.
- Architecture is documented in `protocol/SPEC.md` (14 KB) — the entire system is designed to be readable, not opaque.

**Evidence:** `failure-taxonomy.ts`, `skill-discovery.ts`, `citizen-catalog-2880.ts`.

### 6. Privacy-Enhanced

**NIST definition:** "AI systems that uphold user values and prevent undue invasions of privacy."

**How Vernen addresses this:**
- The verification chain stores only hashes, not contents. Anyone querying the chain learns *that* a record exists, not *what* it contains.
- Merkle proofs reveal only the leaf hash and ~13 sibling hashes — none of the other records in the day are exposed.
- Constitutional principle `HARMLESS.privacy_preserving` is automatically tagged on `document_intake` records.
- The architecture is designed to support Zero-Knowledge proofs (Layer 5b — Pedersen commitments + selective disclosure) for cases where even the existence of certain fields needs to be hidden while still being verifiable.

**Evidence:** `migration-030-verification.sql` schema (no content fields in `verification_log`), `constitutional-mapping.ts:HARMLESS` category.

### 7. Fair – with Harmful Bias Managed

**NIST definition:** "AI systems that have addressed concerns about... harmful biases."

**How Vernen addresses this:**
- Citizens are assembled from federal enforcement data. Their skill sets reflect what regulators actually penalize — not synthetic training data, not what a developer thought should matter. This grounds the system in observable real-world consequences rather than speculation.
- The taxonomy engine classifies failures by NAICS code (industry-objective), violation type (regulatory-objective), and governing standard (CFR/USC citation, statutory-objective). No subjective scoring of "deserving" or "undeserving" entities.
- The verification protocol is content-agnostic — it cannot distinguish a finding favorable to one party from a finding favorable to another. The math is symmetric.
- The constitutional principle `HARMLESS.proportional_severity` is auto-tagged on audit findings.

**Open issue:** The platform does not yet implement explicit bias auditing (e.g., demographic parity tests across Citizen findings). This is a gap that should be addressed before any high-stakes deployment in domains where it matters.

---

## Core Functions (NIST AI RMF Section 5)

### GOVERN

The protocol is structured as a stewardship foundation, not a company. The governance model is described in `project_governance_structure.md`:
- Tripartite framework: Board (5), Oversight (4), ICT (4)
- Citizens are stewards of their professional knowledge, not assets owned by an entity
- 16 common law trademarks established March 15, 2026
- The verification protocol itself is open source under MIT/CC0, decoupling protocol governance from platform governance

### MAP

The system maps risks at multiple levels:
- **Per-record:** every action carries a `metadata.constitutional` field declaring which principles it claims to uphold
- **Per-Citizen:** every Citizen has a declared scope (jurisdiction, NAICS codes, skill set, governing standards)
- **Per-pipeline:** every intelligence pipeline declares its source agency, data type, and risk scoring methodology
- **System-level:** the architecture spec (`protocol/SPEC.md`) maps the four verification layers and their failure modes

### MEASURE

Quantifiable metrics produced by the platform:
- Total chained records (currently 8,049)
- Daily Merkle root (publicly anchored)
- Per-pipeline lead counts (40 pipelines)
- Per-Citizen execution counts (queryable via `/api/verify/by-principle/`)
- Chain integrity status (binary: valid / broken-at-seq-N)
- Risk distribution (critical/high/medium/low across all leads)
- Pipeline health grades (A-F per pipeline based on success rate)

### MANAGE

Operational responses to identified risks:
- Alert engine scans for critical risks across all 40 pipelines and creates lifecycle records (NEW → ACK → RESOLVED/DISMISSED)
- Constitutional misalignment can be queried: any record claiming a principle it failed to uphold can be flagged
- Verification chain integrity is checked via dedicated endpoint and would be the first detection of any tampering
- Daily Merkle root publishing is automated via cron — failures generate logs but don't break the system

---

## Notable Gaps and Honest Limitations

NIST RMF emphasizes documenting what the system *does not* address. Vernen's current gaps:

1. **No formal bias audit.** The verification protocol is symmetric, but the underlying Citizens have not been bias-audited for demographic parity in their findings.
2. **No human-in-the-loop checkpoint.** Skill executions are autonomous. There is no mandatory human review step before a finding becomes part of the immutable chain.
3. **Cron is not yet hardened.** The daily anchoring cron has been deployed but not yet exercised by an actual scheduled run (first scheduled execution: 2026-04-08 01:00 UTC).
4. **Constitutional principles are platform-defined, not externally certified.** The 26 principles in `constitutional-mapping.ts` are drawn from Anthropic's HHH framework and professional ethics codes, but no external standards body has reviewed or certified them.
5. **Layer 4 (Bitcoin anchoring) is designed but not deployed.** The architecture supports OpenTimestamps but the integration is not yet live.
6. **Layer 5b (true ZK proofs) is in spec only.** Pedersen commitments and SNARK integration are planned but not yet built.

These gaps are documented intentionally. NIST AI RMF requires acknowledgment of limitations — pretending otherwise would itself be a violation of the framework's transparency principle.

---

## Conclusion

The Vernen verification protocol is designed in alignment with NIST AI RMF 1.0. Every characteristic of trustworthy AI defined in the framework has a corresponding implementation in the protocol — and the gaps that remain are documented honestly. The protocol is open source, the implementation is reproducible, and the math is independently verifiable.

This document is itself a verifiable artifact. A future version should be hashed and added to the chain, making this NIST mapping cryptographically anchored alongside the records it describes.

---

**Reference:** NIST AI 100-1 *Artificial Intelligence Risk Management Framework (AI RMF 1.0)* — January 26, 2023
**Author:** Michael Hartmann + Claude (per Vernen's stated origin model)
**License:** CC0-1.0 (this document is in the public domain)
