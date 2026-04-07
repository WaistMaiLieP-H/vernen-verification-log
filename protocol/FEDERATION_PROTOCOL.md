# Federation Protocol — Layer 8

**Status:** Implemented 2026-04-07. See `src/services/federation-protocol.ts`.
**License:** CC0-1.0

## What This Layer Asks

Layers 1–7 ask whether a single Vernen instance is internally consistent.
**Layer 8 — Federation — asks whether multiple independent Vernen instances
agree on what each one published.**

A single instance can theoretically rewrite its own daily Merkle roots
between publication and verification. The hash chain catches *internal*
inconsistency, but a sufficiently determined operator could rewrite the
chain *and* re-anchor the new root to GitHub. The integrity of the system
ultimately rests on the operator's honesty.

Federation removes that assumption. Each Vernen instance becomes a witness
to every other instance's daily roots. Once N peers have signed Instance A's
2026-04-07 root, any later attempt by A to alter that root will fail
verification against the N peer signatures, because the peer signatures are
bound to the *original* hash. The integrity floor moves from "trust the
operator" to "trust that no peer ever cosigns a forged root."

## Identity

Each Vernen instance has a long-lived **Ed25519-equivalent signing key**.

This implementation uses **ECDSA P-256** because Cloudflare Workers'
`crypto.subtle` natively supports P-256 sign/verify without external
dependencies. The functional properties are equivalent for our purposes:

- 256-bit curve, ~128-bit security
- Deterministic public key derivation
- JWK serialization for distribution
- Native Web Crypto support

The keypair is generated once on first call to `getOrCreateKeypair()` and
stored in the singleton `federation_keypair` table. The private key never
leaves the instance. The public key is published at:

```
GET /api/federation/key
```

## Manifest

Each instance publishes a self-describing manifest at:

```
GET /api/federation/manifest
```

The manifest contains:

```json
{
  "instance_id": "vernen-prod-2026",
  "name": "Vernen Legal Compliance — Production",
  "domain": "compliance.vernenlegal.com",
  "public_key": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." },
  "key_id": "sha256-prefix",
  "endpoints": {
    "merkle_root": "GET /api/verify/anchor/list",
    "attest": "POST /api/federation/attest/:date",
    "witnesses": "GET /api/federation/witnesses/:date",
    "manifest": "GET /api/federation/manifest"
  },
  "started_at": "2026-04-07T00:00:00Z",
  "protocol_version": 1
}
```

The manifest is unauthenticated. Federation discovery does not require
prior registration.

## Peer Registry

Peers are stored in the `federation_peers` table:

| column | meaning |
|---|---|
| `id` | local peer id (e.g. `peer_xxx`) |
| `name` | human-readable label |
| `manifest_url` | absolute URL to peer's `/api/federation/manifest` |
| `public_key_jwk` | JSON-serialized JWK fetched from manifest |
| `key_id` | sha256 prefix of canonical pubkey |
| `added_at` | timestamp |
| `status` | `ACTIVE` / `REVOKED` |

Adding a peer is authenticated:

```
POST /api/federation/peers
{ "name": "Vernen-EU", "manifest_url": "https://eu.vernen.example/api/federation/manifest" }
```

The handler fetches the manifest, validates that it returns a valid JWK,
computes a key id, and stores the row. Manifest fetching is the only
network call this protocol makes (besides attestation requests, below).

## Attestation Flow

The cross-signing flow is **request-then-store**: a peer asks this
instance to attest to one of *its own* Merkle roots, and this instance
stores the signature returned by the peer. Each side does the same.

### Step 1 — peer A asks instance B to attest A's daily root

```
POST /api/federation/attest/:date
{ "merkle_root": "0xabc...", "instance_id": "vernen-prod-eu" }
```

Instance B:

1. Looks up the calling peer in its `federation_peers` table by `instance_id`
2. Optionally re-fetches the peer's published root for `:date` from the
   peer's `/api/verify/anchor/list` endpoint and compares — refuses to
   sign if the supplied root does not match the peer's *own* publication
3. Computes the canonical attestation payload:
   ```
   sha256("federation-v1|" + peer_instance_id + "|" + date + "|" + merkle_root)
   ```
4. Signs the payload hash with its own ECDSA P-256 private key
5. Stores the attestation in its own `federation_attestations_outbound` table
6. Returns:
   ```json
   {
     "signer_instance_id": "vernen-prod-2026",
     "signer_key_id": "sha256-prefix",
     "date": "2026-04-07",
     "subject_instance_id": "vernen-prod-eu",
     "subject_merkle_root": "0xabc...",
     "signature": "...base64...",
     "signed_at": "2026-04-07T12:00:00Z"
   }
   ```

### Step 2 — peer A stores B's signature as a witness record

```
POST /api/federation/witnesses
{ ...attestation object... }
```

Instance A:

1. Verifies the signature against B's public key (looked up in its peer registry)
2. Verifies the date and root match A's own published root for that date
3. Stores the row in `federation_witnesses`

### Verification (anyone, no auth)

```
GET /api/federation/witnesses/:date
```

Returns all witness signatures for that date along with peer ids and key
ids. A third-party verifier downloads:

1. This instance's daily Merkle root for `:date` (from
   `/api/verify/anchor/list` — already public)
2. The witnesses for `:date` (from `/api/federation/witnesses/:date`)
3. Each witnessing peer's public key (from each peer's
   `/api/federation/manifest`)

…then independently re-verifies every signature. If any verification
succeeds, that signature is *evidence* that the peer saw this exact root
on or before the `signed_at` timestamp. Tampering by the local operator
after that timestamp would invalidate every existing peer signature.

## Tamper Detection

The system has three independent tamper-detection paths:

| Path | What it catches |
|---|---|
| Hash chain (Layer 1) | Modification of any historical record |
| GitHub anchor | Operator rewriting both the chain and the daily root |
| **Federation witnesses (Layer 8)** | **Operator rewriting the chain, daily root, AND the GitHub anchor — caught when peer signatures fail verification against the new root** |

For an operator to forge history through all three layers, they would
need to either (a) compromise every federation peer's signing key, or
(b) collude with every peer to issue new signatures over the falsified
root and back-date them — both of which are observable actions that
expand the attack surface from one operator to N+1 organizations.

## Tables

```sql
CREATE TABLE federation_keypair (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  instance_id TEXT NOT NULL,
  public_key_jwk TEXT NOT NULL,
  private_key_jwk TEXT NOT NULL,
  key_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE federation_peers (
  id TEXT PRIMARY KEY,
  instance_id TEXT,
  name TEXT NOT NULL,
  manifest_url TEXT NOT NULL,
  public_key_jwk TEXT NOT NULL,
  key_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'ACTIVE',
  added_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE federation_witnesses (
  id TEXT PRIMARY KEY,
  date TEXT NOT NULL,
  peer_id TEXT NOT NULL,
  signer_instance_id TEXT NOT NULL,
  signer_key_id TEXT NOT NULL,
  subject_merkle_root TEXT NOT NULL,
  signature TEXT NOT NULL,
  signed_at TEXT NOT NULL,
  stored_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE federation_attestations_outbound (
  id TEXT PRIMARY KEY,
  date TEXT NOT NULL,
  subject_instance_id TEXT NOT NULL,
  subject_merkle_root TEXT NOT NULL,
  signature TEXT NOT NULL,
  signed_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/federation/manifest` | — | Self-describing identity card |
| GET | `/api/federation/key` | — | This instance's public key (JWK) |
| GET | `/api/federation/info` | — | Layer 8 documentation |
| POST | `/api/federation/peers` | required | Register a peer by manifest URL |
| GET | `/api/federation/peers` | — | List known peers |
| POST | `/api/federation/attest/:date` | required | Sign a peer's daily root |
| POST | `/api/federation/witnesses` | required | Store an inbound attestation |
| GET | `/api/federation/witnesses/:date` | — | Public witness list for date |

## What Federation Is Not

- **Not consensus.** Layer 5c handles cross-model consensus on findings.
  Federation is consensus on *historical state*, not on conclusions.
- **Not Byzantine fault tolerance.** Federation assumes peers may be
  honest or compromised, but it does not run a BFT protocol. The
  guarantee is *attribution* — we can prove which peers signed what,
  not force agreement.
- **Not a blockchain.** No global ordering, no proof-of-work, no
  consensus rounds. Just bilateral cosigning of independently-published
  Merkle roots.
- **Not a replacement for the GitHub anchor.** It is an *additional*
  witness layer.

## Bootstrap

The first Vernen instance to deploy this protocol has zero peers. The
federation table starts empty. Self-attestation is meaningless and
disabled. The protocol activates as soon as the second instance comes
online and the two register each other.

For the production instance at `compliance.vernenlegal.com`, the federation
manifest is live but the peer set is empty. Future Vernen deployments
(other jurisdictions, partner instances, academic mirrors) will register
through the standard flow above.

## Security Notes

- Private keys are stored in D1. This is acceptable for the bootstrap
  phase but should migrate to Cloudflare Workers Secrets or KMS once
  the instance count exceeds 1.
- Manifest fetching uses HTTPS only. HTTP manifests are rejected.
- Signature verification is done in-Worker via `crypto.subtle.verify`.
- The protocol version is `1`. Manifests advertising a different version
  are rejected by `addPeer`.

---

**License:** CC0-1.0
**Spec version:** 1
**Implementation:** `src/services/federation-protocol.ts`
