# Vernen Verification Log

This repository is the **public, append-only verification log** for the
[Vernen Legal Compliance](https://compliance.vernenlegal.com) platform.

Every day at 01:00 UTC, the platform computes a **Merkle root** over every
verifiable record produced that day (skill executions, compliance reports,
audit findings) and commits the root to this repository as a single small
JSON file.

Once the commit lands, the root exists in every clone of this repo. Git's
own append-only hash chain protects it from silent rewriting. If the platform
ever tried to retroactively change a record, anyone with an earlier clone
can prove the divergence.

## What This Is

A federated verification protocol — like Certificate Transparency, but for
AI agent activity and compliance records. The math:

1. Every Citizen action is hashed and chained to the previous action
2. Daily, all that day's hashes are folded into a Merkle tree
3. The root of that tree is committed here, publicly
4. Anyone can request a Merkle proof for a single record from the platform API
5. Anyone can reconstruct the root from the proof — proving the record existed
6. No trust in Vernen required. The math is the proof.

## Repository Structure

```
vernen-verification-log/
├── README.md              ← this file
├── LICENSE                ← MIT
├── genesis.json           ← protocol constants and genesis hash
├── verify.html            ← browser-based verifier (pure JavaScript)
├── verify.py              ← standalone Python verifier (no dependencies)
├── protocol/              ← the open-source protocol implementation
│   ├── SPEC.md                          ← full architecture specification
│   ├── PROOF_DEMO.md                    ← end-to-end verification proof
│   ├── verification-engine.ts           ← core hash chain + Merkle engine
│   ├── verification-anchor.ts           ← GitHub anchoring service
│   └── migration-030-verification.sql   ← D1 schema (Cloudflare/SQLite)
└── 2026/
    └── 04/
        └── 07.json        ← daily Merkle root
```

## How to Verify a Record

**Option 1 — Browser** (no install):
1. Open `verify.html` in any modern browser
2. Get a record's proof from `https://compliance.vernenlegal.com/api/verify/proof/<id>`
3. Paste the leaf hash, leaf index, proof path, and the public root from this repo
4. Click verify

**Option 2 — Python** (no dependencies):
```bash
python verify.py <record_id>
```

**Option 3 — Run your own Vernen instance**:
The protocol is open. Anyone can deploy the verification engine on Cloudflare
Workers + D1 (or adapt it to any append-only datastore) and publish their own
daily Merkle roots to their own GitHub repo. Cross-instance verification is
trivial — every instance follows the same protocol.

## What This Proves

If a record passes verification:
- It existed at the date claimed by the daily root
- The platform has not modified it since
- The cryptographic chain from genesis to that record is unbroken

If verification fails:
- Either the record never existed, or
- It has been modified, or
- The proof is malformed

The verification works **without any cooperation from Vernen**. The math runs
in your browser or your terminal. The public root in this repo is anchored by
Git's distributed history.

## License

- This repository's data files (daily roots, README, genesis.json): **CC0-1.0**
- Protocol implementation in `protocol/` (TypeScript engine, Python verifier): **MIT**
- `verify.html`: **MIT**

You can use, fork, modify, and run this protocol for any purpose.

## Why This Matters

The Vernen platform generates compliance audits, court filings, and AI agent
activity logs that are intended to be legally accountable. Without cryptographic
verification, those records depend on trust — trust in Vernen's database, trust
in Vernen's hosting provider, trust that no one has rewritten history.

This protocol replaces that trust with **math anchored in public infrastructure**.
The same model used by Certificate Transparency to authenticate every SSL
certificate on the internet. The same Merkle tree structure used by Bitcoin.
The same Git hash chain used by every open-source project on Earth.

Anyone can verify. No one can silently rewrite. That's the standard worth
becoming.

---

**Platform:** https://compliance.vernenlegal.com
**Spec:** [`protocol/SPEC.md`](protocol/SPEC.md)
**Demo:** [`protocol/PROOF_DEMO.md`](protocol/PROOF_DEMO.md)
