# Vernen Verification Log

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

```
vernen-verification-log/
├── README.md           ← this file
├── genesis.json        ← genesis hash + protocol version
├── verify.html         ← browser-based verifier (pure JS, no backend)
└── YYYY/
    └── MM/
        └── DD.json     ← one Merkle root per day
```

## A daily file

```json
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
```

## How to verify a record

You will need four things from the platform:

1. The record's `record_id`
2. The record's `content_hash`
3. The Merkle proof path (`GET /api/verify/proof/:recordId`)
4. The leaf index from the same response

Then:

1. Open `verify.html` in any browser. It runs entirely in your browser —
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
- **Distributed by default:** Anyone can `git clone` this repo and have
  their own audit-grade copy of the entire chain.

## Genesis

See `genesis.json`. The genesis hash is
`1662b214b39d68462c60e10dedd67634b85c8db250eabf41c252e968cb05b149`,
the SHA-256 of the seed string `VERNEN_GENESIS_2026`. It is the
`prev_hash` of the first record in the platform's hash chain.

## Specification

The full architecture is documented in
[VERIFIABILITY_ARCHITECTURE.md](https://github.com/WaistMaiLieP-H/VERNEN/blob/master/docs/VERIFIABILITY_ARCHITECTURE.md).

## License

This log is published under [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/).
The hashes are facts. Facts cannot be owned.
