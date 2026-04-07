# Vernen Verification Protocol — Known Gaps and Roadmap

**Date:** 2026-04-07
**Status:** Honest assessment for any party considering Vernen as a production verification standard

This document exists because **production verification infrastructure is hard, and pretending otherwise destroys credibility.** The cryptographic primitives in Vernen work correctly. The operational guarantees that turn working primitives into a trusted standard are not yet complete. This is the honest list of what's missing, in priority order, with the roadmap for closing each gap.

## What Is Already True

Before the gaps, the things that genuinely work:

| Capability | Status |
|-----------|--------|
| SHA-256 hash chain across all records | LIVE — 8,049+ records as of 2026-04-07 |
| Daily Merkle tree computation | LIVE — root: `3d5fe1cd...c6ddbe` (or current) |
| GitHub anchoring of daily roots | LIVE — `vernen-verification-log` public repo |
| Wayback Machine secondary witness | LIVE — 7 critical URLs archived |
| Cron-automated daily anchoring | LIVE — 1 AM UTC |
| Constitutional traceability metadata (26 principles) | LIVE — every record tagged |
| Pedersen commitments + Schnorr proofs (Layer 5a ZK) | LIVE — pure TS, Workers-compatible |
| Cross-model weighted consensus engine | LIVE — Anthropic / OpenAI / Google supported |
| Constitutional principle queries | LIVE |
| Public Python verifier + browser verifier | LIVE in public repo |
| Three independent verification implementations agree | LIVE — TypeScript, Python, JavaScript |
| Build attestation linking deployed code to public source | LIVE — `/api/verify/build` endpoint |
| NIST AI RMF 1.0 mapping document | LIVE in public repo |
| 740+ federal compliance rules + 580 governing standards | LIVE in production D1 |
| 3,160 named Citizen positions | LIVE in production catalog |

## Gap List (In Priority Order)

### CRITICAL — would damage credibility under technical scrutiny

#### Gap 1: Hash chain is "append-only" by convention, not enforcement
**Status:** Open
**Severity:** Critical
**What it is:** D1 (SQLite) accepts `DELETE FROM verification_log` even though it would break the chain. A malicious operator could delete records, recompute combined hashes from a new genesis, and re-anchor.
**What it isn't:** This isn't a problem if the operator is honest. The math still detects tampering after the fact. The question is whether the tamper itself can be prevented at the storage layer.
**Roadmap:**
- Add SQLite triggers preventing DELETE/UPDATE on `verification_log` (Phase 2, ~1 session)
- Migrate to write-once storage tier for verification records (Phase 3, requires Cloudflare R2 with object lock or equivalent)
- Add multi-party witness records that detect deletion via gossip protocol (Phase 4, requires federation)

#### Gap 2: Single-anchor / single-operator trust on GitHub
**Status:** Partially mitigated
**Severity:** Critical
**What it is:** The primary public anchor is one GitHub repo under one account, accessible by one token. Force-push is technically possible. If the token leaks or the account is compromised, the public anchor history could be silently rewritten.
**Mitigation (live as of 2026-04-07):** Wayback Machine archives all daily roots and key URLs. The Internet Archive operates under a different trust model than GitHub and would not be co-compromised. Anyone can verify the current published root against the Wayback snapshot.
**Remaining work:**
- Add Codeberg or GitLab as a third-party Git mirror (Phase 2, ~0.5 session)
- IPFS pinning via Pinata or Web3.Storage for content-addressable replication (Phase 2, ~0.5 session)
- Sigstore Rekor transparency log integration (Phase 2, ~1 session)
- Cross-signing protocol where multiple independent log operators witness each daily root (Phase 4, requires federation partners)

#### Gap 3: Self-attested integrity verification
**Status:** Partially mitigated
**Severity:** Critical
**What it is:** `/api/verify/chain/integrity` walks our own chain using our own engine against our own database. A verifier asking us to confirm our own honesty is asking us to grade our own homework.
**Mitigation (live):** The Python verifier and browser verifier are independent implementations that run client-side without our server. Any third party can download all records, recompute combined hashes locally, and confirm consistency with the published Merkle root.
**Remaining work:**
- Build a separate "witness Worker" that runs independent integrity checks on a schedule and publishes results to the public repo (Phase 2, ~1 session)
- Set up automated GitHub Actions that fetch and verify the chain daily (Phase 2, ~0.5 session)

#### Gap 4: No proof of non-inclusion
**Status:** Open
**Severity:** Critical for high-stakes use cases
**What it is:** We can prove a record IS in the chain (Merkle proof). We cannot prove a record is NOT in the chain. A malicious operator could omit specific records they don't want anchored.
**Roadmap:**
- Implement Sparse Merkle Trees with non-inclusion proofs (Phase 3, ~2 sessions, genuinely hard cryptographic work)
- Or: maintain a separate "claim register" where any party can submit a hash they believe should be in the chain, and the engine must respond with either inclusion proof or explicit absence statement
- Cryptographic accumulator schemes (RSA accumulators or KZG commitments) as an alternative

#### Gap 5: Self-attested timestamps
**Status:** Open
**Severity:** Critical for legal admissibility
**What it is:** `created_at` fields are set by `new Date().toISOString()` in our own code. We could backdate records. There is no external time witness.
**Roadmap:**
- RFC 3161 trusted timestamping authority integration (FreeTSA, DigiCert) (Phase 2, ~1 session)
- Anchor each daily Merkle root to a Bitcoin block via OpenTimestamps (Phase 2, ~1 session, gives Bitcoin-grade timestamp witness)
- Roughtime protocol integration for sub-second timestamping (Phase 3, lower priority)

### MEDIUM — would weaken credibility but not destroy it

#### Gap 6: Genesis not externally anchored
**Status:** Partially mitigated
**Severity:** Medium
**What it is:** The genesis hash is `SHA-256("VERNEN_GENESIS_2026")`. Anyone can compute it. But there's no external proof the chain *started* on a specific date.
**Mitigation (live):** The genesis hash is published in `genesis.json` in the public verification log repo. The first commit to that repo is timestamped by GitHub. Wayback Machine has snapshotted that file. Three independent witnesses (Git history, Wayback, our own DB) confirm the genesis existed before any chain operations.
**Remaining work:**
- Anchor genesis to a Bitcoin OP_RETURN transaction (irrevocable timestamp) (Phase 3, ~0.5 session)

#### Gap 7: Constitutional traceability is stamps, not enforcement
**Status:** Open
**Severity:** Medium
**What it is:** Records claim to uphold `HONEST.evidence_backed`, but there's no automated check that they actually do. The metadata is searchable but unverified.
**Roadmap:**
- Build a checker for each of the 26 principles with concrete evaluation logic (Phase 3, ~2 sessions)
- For example: `HONEST.evidence_backed` requires the record's content to cite at least one source URL or rule ID
- For example: `HARMLESS.no_unauthorized_disclosure` requires absence of common PII patterns in the canonical content

#### Gap 8: No reproducible build attestation linking deployed code to source
**Status:** Mitigated as of 2026-04-07
**Severity:** Medium (now reduced)
**What it is:** Anyone reading the protocol/ source files in the public repo had no way to confirm that compliance.vernenlegal.com was running that exact code.
**Mitigation (live as of 2026-04-07):**
- `/api/verify/build` endpoint returns a build attestation including source URLs, version metadata, and verification instructions
- Daily Merkle root payloads include a `build_attestation` field with the same data
- Anyone can fetch `protocol/verification-engine.ts` from the public repo, hash it, and confirm the deployed engine references the same hashes
- Wayback Machine archives the `/api/verify/build` endpoint independently
**Remaining work:**
- Sigstore-style cryptographic attestation binding the deployed Worker bundle to a specific git commit (Phase 3, ~1 session)
- Publish the Wrangler bundle hash as part of each daily root (Phase 3, ~0.5 session)

#### Gap 9: Continuous append-only proofs
**Status:** Open
**Severity:** Medium
**What it is:** The Merkle tree only proves what existed at compute time. If records were deleted before computation, they never appear in any tree.
**Roadmap:**
- Implement rolling Merkle trees with overlapping windows (Phase 3, ~1 session)
- Each new record gets a delta proof linking it to the previous tree state

#### Gap 10: Cross-provider signatures are simulated
**Status:** Receiver built, signing is gated on partnerships
**Severity:** Medium
**What it is:** Three records in our database with the same `consensus_group_id` and different `model_name` values doesn't prove three different model providers actually independently audited the same input. The application could fabricate the cross-model records.
**What's built:** The receiving infrastructure is complete. Vernen can accept and verify signed records from multiple providers if the providers ship signatures.
**What's missing:** Anthropic, OpenAI, and Google would each need to ship cryptographic signatures on their model outputs. We can build the infrastructure to verify them. We cannot make the providers sign.
**Roadmap:**
- Phase 1 (live): consensus engine accepts records with `model_name` and computes consensus signals
- Phase 2: when a provider ships signed outputs, add a verifier for that provider's signature scheme
- Phase 3: cross-provider attestation protocol where each provider's signatures are anchored independently

### LOWER PRIORITY but real

#### Gap 11: No formal threat model documentation
**Status:** Open
**Severity:** Low (documentation gap)
**Roadmap:** STRIDE/DREAD analysis (Phase 2, ~0.5 session)

#### Gap 12: No dispute resolution workflow
**Status:** Database table exists; UI and workflow do not
**Severity:** Low
**Roadmap:** Build dispute review interface, escalation paths, resolution workflow (Phase 3, ~1 session)

#### Gap 13: No formal incident response runbooks
**Status:** Open
**Severity:** Low
**Roadmap:** Documentation, runbooks for chain break, anchor failure, key compromise (Phase 2, ~0.5 session)

#### Gap 14: Single point of failure on key management
**Status:** Open
**Severity:** Low (single GITHUB_TOKEN)
**Roadmap:** Threshold signature scheme requiring n-of-m signers for protocol changes (Phase 3, ~1 session, requires foundation partners)

#### Gap 15: Witness archival redundancy
**Status:** Mitigated as of 2026-04-07
**Severity:** Low
**Mitigation (live):** Wayback Machine archives 7 critical URLs. Multiple snapshots over time as the cron runs.
**Remaining work:**
- IPFS pinning for content-addressable replication (Phase 2, ~0.5 session)
- Multiple Git mirrors (Phase 2, ~0.5 session)

## Total Roadmap

- **Critical gap closures:** ~6.5 sessions, ~$165 in API credits
- **Medium gap closures:** ~5.5 sessions, ~$140
- **Lower priority closures:** ~3.5 sessions, ~$90
- **Vault items (federation, court pilot, foundation, SNARK prover, etc.):** ~9 sessions, ~$225
- **Total to "production verification standard":** ~25 sessions, ~$620 in API credits

Three of the gap closures cannot be completed without external partnerships:
- Gap 10 (cross-provider signatures) requires Anthropic / OpenAI / Google cooperation
- Gap 14 (threshold key management) requires foundation partners
- The SOC 2 Type II vault item requires an external auditor running the certification process over 3-6 months

## What This Means For Anyone Considering Vernen As Infrastructure

**Production-grade today for:**
- Demonstration purposes
- Internal accountability where the operator is trusted
- Pilot deployments where the gaps are acknowledged
- Reference implementation of the verification protocol

**Not yet production-grade for:**
- High-stakes legal proceedings without supplementary safeguards
- Financial transactions where the operator cannot be trusted
- Multi-party adversarial environments
- Use cases requiring proof of non-inclusion

**The honest pitch:** Vernen is the most complete cryptographic accountability layer for AI agent activity that currently exists in production. The gaps above are real and known. The roadmap to close them is achievable with appropriate stewardship support. The cryptographic primitives work. The operational maturity needs another 6-12 months of work, ideally under institutional partnership.

## Why We're Publishing This

Publishing the gaps before they're discovered is the difference between a credible founder and a one-pitch wonder. Anyone reading this document who has cryptography or distributed systems experience will immediately recognize that:

1. We know what production verification infrastructure actually requires
2. We've built the working core
3. We've documented the gap honestly
4. We have a concrete roadmap for closing each gap
5. We're not hand-waving the parts we haven't built

That's the position we want to be in. Not "look how complete this is" — but "look how exact our self-knowledge is."

---

**Document version:** 1.0
**Last updated:** 2026-04-07
**Maintained by:** Michael Hartmann + Claude (per Vernen's stated origin model)
**License:** CC0-1.0
