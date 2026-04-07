/**
 * Layer 8 — Federation Protocol
 *
 * Cross-instance witnessing of daily Merkle roots. Each Vernen instance
 * holds an ECDSA P-256 keypair and can sign other instances' published
 * roots. Once N peers have witnessed instance A's root for date X, any
 * later attempt by A to alter that root will fail verification against
 * the existing peer signatures.
 *
 * The integrity floor moves from "trust the operator" to
 * "trust that no peer ever cosigns a forged root."
 *
 * Spec: docs/FEDERATION_PROTOCOL.md
 * License: CC0-1.0
 */

import type { Env } from "../index.js";

// ─── Types ───────────────────────────────────────────────────────────────

export interface FederationManifest {
  instance_id: string;
  name: string;
  domain: string;
  public_key: JsonWebKey;
  key_id: string;
  endpoints: {
    merkle_root: string;
    attest: string;
    witnesses: string;
    manifest: string;
  };
  started_at: string;
  protocol_version: number;
}

export interface PeerRecord {
  id: string;
  instance_id: string | null;
  name: string;
  manifest_url: string;
  public_key_jwk: string;       // Stored as JSON string
  key_id: string;
  status: "ACTIVE" | "REVOKED";
  added_at: string;
}

export interface Attestation {
  signer_instance_id: string;
  signer_key_id: string;
  date: string;                  // YYYY-MM-DD
  subject_instance_id: string;
  subject_merkle_root: string;
  signature: string;             // base64
  signed_at: string;
}

export interface WitnessRecord {
  id: string;
  date: string;
  peer_id: string;
  signer_instance_id: string;
  signer_key_id: string;
  subject_merkle_root: string;
  signature: string;
  signed_at: string;
  stored_at: string;
}

// ─── Constants ───────────────────────────────────────────────────────────

const PROTOCOL_VERSION = 1;
const ATTESTATION_PREFIX = "federation-v1|";

// ─── Engine ──────────────────────────────────────────────────────────────

export class FederationProtocol {
  constructor(private env: Env) {}

  // ─── Schema ──────────────────────────────────────────────────────────

  async ensureTables(): Promise<void> {
    const db = this.env.DB;
    await db.batch([
      db.prepare(`CREATE TABLE IF NOT EXISTS federation_keypair (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        instance_id TEXT NOT NULL,
        public_key_jwk TEXT NOT NULL,
        private_key_jwk TEXT NOT NULL,
        key_id TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS federation_peers (
        id TEXT PRIMARY KEY,
        instance_id TEXT,
        name TEXT NOT NULL,
        manifest_url TEXT NOT NULL,
        public_key_jwk TEXT NOT NULL,
        key_id TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'ACTIVE',
        added_at TEXT NOT NULL DEFAULT (datetime('now'))
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS federation_witnesses (
        id TEXT PRIMARY KEY,
        date TEXT NOT NULL,
        peer_id TEXT NOT NULL,
        signer_instance_id TEXT NOT NULL,
        signer_key_id TEXT NOT NULL,
        subject_merkle_root TEXT NOT NULL,
        signature TEXT NOT NULL,
        signed_at TEXT NOT NULL,
        stored_at TEXT NOT NULL DEFAULT (datetime('now'))
      )`),
      db.prepare(`CREATE INDEX IF NOT EXISTS idx_witnesses_date ON federation_witnesses(date DESC)`),
      db.prepare(`CREATE TABLE IF NOT EXISTS federation_attestations_outbound (
        id TEXT PRIMARY KEY,
        date TEXT NOT NULL,
        subject_instance_id TEXT NOT NULL,
        subject_merkle_root TEXT NOT NULL,
        signature TEXT NOT NULL,
        signed_at TEXT NOT NULL DEFAULT (datetime('now'))
      )`),
      db.prepare(`CREATE INDEX IF NOT EXISTS idx_outbound_date ON federation_attestations_outbound(date DESC)`),
    ]);
  }

  // ─── Keypair ─────────────────────────────────────────────────────────

  /**
   * Get or create this instance's signing keypair. Generates a P-256 pair
   * on first call and persists it to D1. Subsequent calls return the same
   * keypair.
   */
  async getOrCreateKeypair(): Promise<{
    instanceId: string;
    publicKeyJwk: JsonWebKey;
    privateKeyJwk: JsonWebKey;
    keyId: string;
  }> {
    await this.ensureTables();
    const db = this.env.DB;

    const row = await db
      .prepare(`SELECT instance_id, public_key_jwk, private_key_jwk, key_id FROM federation_keypair WHERE id = 1`)
      .first<{
        instance_id: string;
        public_key_jwk: string;
        private_key_jwk: string;
        key_id: string;
      }>();

    if (row) {
      return {
        instanceId: row.instance_id,
        publicKeyJwk: JSON.parse(row.public_key_jwk),
        privateKeyJwk: JSON.parse(row.private_key_jwk),
        keyId: row.key_id,
      };
    }

    // Generate
    const pair = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    )) as CryptoKeyPair;
    const publicKeyJwk = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as JsonWebKey;
    const privateKeyJwk = (await crypto.subtle.exportKey("jwk", pair.privateKey)) as JsonWebKey;
    const keyId = await this.computeKeyId(publicKeyJwk);
    const instanceId = `vernen-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;

    await db
      .prepare(
        `INSERT INTO federation_keypair (id, instance_id, public_key_jwk, private_key_jwk, key_id)
         VALUES (1, ?1, ?2, ?3, ?4)`
      )
      .bind(instanceId, JSON.stringify(publicKeyJwk), JSON.stringify(privateKeyJwk), keyId)
      .run();

    return { instanceId, publicKeyJwk, privateKeyJwk, keyId };
  }

  private async computeKeyId(jwk: JsonWebKey): Promise<string> {
    // Canonical: just use x and y for P-256 EC keys
    const canonical = JSON.stringify({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y });
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
    return this.bufToHex(buf).slice(0, 16);
  }

  // ─── Manifest ────────────────────────────────────────────────────────

  async buildManifest(domain: string): Promise<FederationManifest> {
    const kp = await this.getOrCreateKeypair();
    return {
      instance_id: kp.instanceId,
      name: "Vernen Legal Compliance",
      domain,
      public_key: kp.publicKeyJwk,
      key_id: kp.keyId,
      endpoints: {
        merkle_root: "GET /api/verify/anchor/list",
        attest: "POST /api/federation/attest/:date",
        witnesses: "GET /api/federation/witnesses/:date",
        manifest: "GET /api/federation/manifest",
      },
      started_at: new Date().toISOString(),
      protocol_version: PROTOCOL_VERSION,
    };
  }

  // ─── Peer registry ───────────────────────────────────────────────────

  async addPeer(name: string, manifestUrl: string): Promise<PeerRecord> {
    await this.ensureTables();

    if (!manifestUrl.startsWith("https://")) {
      throw new Error("manifest_url must use HTTPS");
    }

    // Fetch manifest
    const res = await fetch(manifestUrl);
    if (!res.ok) {
      throw new Error(`Failed to fetch manifest: HTTP ${res.status}`);
    }
    const manifest = (await res.json()) as FederationManifest;

    if (manifest.protocol_version !== PROTOCOL_VERSION) {
      throw new Error(
        `Peer protocol version ${manifest.protocol_version} does not match local ${PROTOCOL_VERSION}`
      );
    }
    if (!manifest.public_key || !manifest.public_key.x || !manifest.public_key.y) {
      throw new Error("Peer manifest missing valid public_key");
    }

    const peerId = `peer_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
    const keyId = manifest.key_id || (await this.computeKeyId(manifest.public_key));

    await this.env.DB.prepare(
      `INSERT INTO federation_peers
        (id, instance_id, name, manifest_url, public_key_jwk, key_id)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6)`
    )
      .bind(
        peerId,
        manifest.instance_id ?? null,
        name,
        manifestUrl,
        JSON.stringify(manifest.public_key),
        keyId
      )
      .run();

    return {
      id: peerId,
      instance_id: manifest.instance_id ?? null,
      name,
      manifest_url: manifestUrl,
      public_key_jwk: JSON.stringify(manifest.public_key),
      key_id: keyId,
      status: "ACTIVE",
      added_at: new Date().toISOString(),
    };
  }

  async listPeers(): Promise<PeerRecord[]> {
    await this.ensureTables();
    const result = await this.env.DB
      .prepare(
        `SELECT id, instance_id, name, manifest_url, public_key_jwk, key_id, status, added_at
         FROM federation_peers
         ORDER BY added_at DESC`
      )
      .all<PeerRecord>();
    return result.results ?? [];
  }

  async findPeerByInstanceId(instanceId: string): Promise<PeerRecord | null> {
    await this.ensureTables();
    const row = await this.env.DB
      .prepare(
        `SELECT id, instance_id, name, manifest_url, public_key_jwk, key_id, status, added_at
         FROM federation_peers WHERE instance_id = ?1 LIMIT 1`
      )
      .bind(instanceId)
      .first<PeerRecord>();
    return row ?? null;
  }

  // ─── Attestation ─────────────────────────────────────────────────────

  /**
   * Sign an attestation that this instance witnessed the given peer's
   * Merkle root for the given date. Returns the attestation; the caller
   * is responsible for transporting it to the peer.
   */
  async attestPeerRoot(
    subjectInstanceId: string,
    date: string,
    subjectMerkleRoot: string
  ): Promise<Attestation> {
    await this.ensureTables();

    const kp = await this.getOrCreateKeypair();
    const payload = `${ATTESTATION_PREFIX}${subjectInstanceId}|${date}|${subjectMerkleRoot}`;
    const payloadBytes = new TextEncoder().encode(payload);

    const privateKey = await crypto.subtle.importKey(
      "jwk",
      kp.privateKeyJwk,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"]
    );
    const sigBuf = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      privateKey,
      payloadBytes
    );
    const signature = this.bufToB64(sigBuf);

    const attestation: Attestation = {
      signer_instance_id: kp.instanceId,
      signer_key_id: kp.keyId,
      date,
      subject_instance_id: subjectInstanceId,
      subject_merkle_root: subjectMerkleRoot,
      signature,
      signed_at: new Date().toISOString(),
    };

    // Store outbound record
    const id = `out_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    await this.env.DB.prepare(
      `INSERT INTO federation_attestations_outbound
        (id, date, subject_instance_id, subject_merkle_root, signature)
       VALUES (?1, ?2, ?3, ?4, ?5)`
    )
      .bind(id, date, subjectInstanceId, subjectMerkleRoot, signature)
      .run();

    return attestation;
  }

  /**
   * Verify a peer's attestation against the peer's stored public key,
   * then store it as a witness. Returns the stored witness record.
   */
  async storeIncomingWitness(att: Attestation): Promise<WitnessRecord> {
    await this.ensureTables();

    const peer = await this.findPeerByInstanceId(att.signer_instance_id);
    if (!peer) {
      throw new Error(
        `Unknown signer instance: ${att.signer_instance_id}. Register the peer first.`
      );
    }
    if (peer.status !== "ACTIVE") {
      throw new Error(`Peer ${peer.id} is not ACTIVE`);
    }

    // Verify signature
    const publicJwk: JsonWebKey = JSON.parse(peer.public_key_jwk);
    const publicKey = await crypto.subtle.importKey(
      "jwk",
      publicJwk,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"]
    );

    // Reconstruct payload — must include OUR instance id since the peer
    // was attesting to *our* root
    const ourKp = await this.getOrCreateKeypair();
    const payload = `${ATTESTATION_PREFIX}${ourKp.instanceId}|${att.date}|${att.subject_merkle_root}`;
    const payloadBytes = new TextEncoder().encode(payload);
    const sigBuf = this.b64ToBuf(att.signature);

    const valid = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      sigBuf,
      payloadBytes
    );
    if (!valid) {
      throw new Error("Signature verification failed");
    }

    // Optional: verify the subject_merkle_root matches our actual published root for that date
    const ourRoot = await this.env.DB
      .prepare(`SELECT merkle_root FROM verification_merkle_roots WHERE date = ?1`)
      .bind(att.date)
      .first<{ merkle_root: string }>();
    if (ourRoot && ourRoot.merkle_root !== att.subject_merkle_root) {
      throw new Error(
        `Witness root does not match our published root for ${att.date}`
      );
    }

    const id = `wit_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    await this.env.DB.prepare(
      `INSERT INTO federation_witnesses
        (id, date, peer_id, signer_instance_id, signer_key_id,
         subject_merkle_root, signature, signed_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)`
    )
      .bind(
        id,
        att.date,
        peer.id,
        att.signer_instance_id,
        att.signer_key_id,
        att.subject_merkle_root,
        att.signature,
        att.signed_at
      )
      .run();

    return {
      id,
      date: att.date,
      peer_id: peer.id,
      signer_instance_id: att.signer_instance_id,
      signer_key_id: att.signer_key_id,
      subject_merkle_root: att.subject_merkle_root,
      signature: att.signature,
      signed_at: att.signed_at,
      stored_at: new Date().toISOString(),
    };
  }

  async listWitnesses(date: string): Promise<WitnessRecord[]> {
    await this.ensureTables();
    const result = await this.env.DB
      .prepare(
        `SELECT id, date, peer_id, signer_instance_id, signer_key_id,
                subject_merkle_root, signature, signed_at, stored_at
         FROM federation_witnesses
         WHERE date = ?1
         ORDER BY stored_at ASC`
      )
      .bind(date)
      .all<WitnessRecord>();
    return result.results ?? [];
  }

  // ─── Encoding helpers ────────────────────────────────────────────────

  private bufToHex(buf: ArrayBuffer): string {
    return Array.from(new Uint8Array(buf))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  private bufToB64(buf: ArrayBuffer): string {
    let s = "";
    const bytes = new Uint8Array(buf);
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
    return btoa(s);
  }

  private b64ToBuf(b64: string): ArrayBuffer {
    const s = atob(b64);
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out.buffer;
  }
}
