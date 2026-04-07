/**
 * Conscientious Identity Framework — Layer 6 ethical core.
 *
 * Wraps every identification claim with epistemic standing metadata so the
 * system never claims more certainty than it actually has, never weaponizes
 * uncertainty into false accusation, and never hides its own reasoning from
 * the people being identified.
 *
 * This framework exists because the Ryan Mcclaran audit (March 30, 2026)
 * exposed a fundamental gap: Vernen audited 18 documents and produced 23
 * findings without verifying that the entities the documents referred to
 * actually existed. That's a methodology failure.
 *
 * But the FIX has its own failure mode: a naive "subject verification" engine
 * would create the opposite problem — false confidence in identification
 * leading to false accusations of fabrication when the entity is just hard
 * to find, privacy-protected, recently registered, or operating under a name
 * that doesn't match a known database.
 *
 * This framework makes the distinction between:
 *   - "I confirmed this entity exists" (CONFIRMED)
 *   - "I found a likely match" (LIKELY)
 *   - "I cannot find this entity" (NOT_FOUND — absence of evidence)
 *   - "This entity definitively does not exist" (CONFIRMED_NONEXISTENT)
 *   - "This entity is privacy-protected and intentionally hard to find" (SEALED)
 *   - "Insufficient data to make any claim" (UNDETERMINED)
 *
 * Every identification claim carries source, timestamp, confidence, false
 * positive risk, false negative risk, differential trust weight, privacy
 * class, and a right-to-challenge URL.
 *
 * License: CC0-1.0 (this framework is public domain and protocol-level)
 */

import type { Env } from "../index.js";

// ─────────────────────────────────────────────────────────────────────────
// Types — the epistemic vocabulary of the framework
// ─────────────────────────────────────────────────────────────────────────

export type VerificationStatus =
  | "CONFIRMED"             // Entity exists, multiple authoritative sources agree
  | "LIKELY"                // Probable match in authoritative source(s)
  | "PARTIAL_MATCH"         // Some attributes match, others don't
  | "NOT_FOUND"             // Could not find — absence of evidence, NOT evidence of absence
  | "CONFIRMED_NONEXISTENT" // Multiple authorities explicitly confirm does not exist
  | "SEALED"                // Privacy-protected entity (witness protection, sealed corp, etc.)
  | "UNDETERMINED";         // Insufficient data to make any claim

export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "UNKNOWN";

export type PrivacyClass =
  | "PUBLIC"                // Normal public entity, no privacy concerns
  | "COMMERCIAL_SENSITIVE"  // Public but commercially sensitive (e.g., private companies)
  | "PROFESSIONAL_LICENSED" // Licensed professional with bar/board record
  | "VICTIM"                // Identified victim — strict access controls
  | "WITNESS"               // Witness protection or related sensitivity
  | "SEALED_RECORD"         // Court-sealed entity or person
  | "MINOR";                // Person under 18

export type SourceTrust =
  | "GOVERNMENT_AUTHORITATIVE"  // 1.0 — state/federal registry, IRS, court
  | "GOVERNMENT_DERIVED"        // 0.85 — derivative gov data (USPS, etc.)
  | "PROFESSIONAL_REGISTRY"     // 0.85 — bar association, NPI, etc.
  | "COMMERCIAL_AUTHORITATIVE"  // 0.7 — D&B, LexisNexis
  | "COMMERCIAL_GENERAL"        // 0.5 — general commercial DB
  | "PUBLIC_AGGREGATOR"         // 0.4 — open data aggregator
  | "USER_SUBMITTED"            // 0.2 — submitted by a user, not verified
  | "UNKNOWN";                  // 0.1 — source not classified

export const SOURCE_TRUST_WEIGHTS: Record<SourceTrust, number> = {
  GOVERNMENT_AUTHORITATIVE: 1.0,
  GOVERNMENT_DERIVED: 0.85,
  PROFESSIONAL_REGISTRY: 0.85,
  COMMERCIAL_AUTHORITATIVE: 0.7,
  COMMERCIAL_GENERAL: 0.5,
  PUBLIC_AGGREGATOR: 0.4,
  USER_SUBMITTED: 0.2,
  UNKNOWN: 0.1,
};

export interface IdentificationClaim {
  // What is being identified
  subject: string;                    // Name/identifier being checked
  claimedType: string;                // What kind of entity it claims to be
  claimedAttributes?: Record<string, string>; // Address, EIN, DOT number, etc.

  // What we found
  verification: VerificationStatus;
  found?: Record<string, string>;     // What the source returned (if anything)

  // Source provenance
  source: string;                     // Human name of the source
  sourceUrl?: string;                 // URL queried (if applicable)
  sourceTrust: SourceTrust;
  queriedAt: string;                  // ISO timestamp

  // Epistemic metadata
  confidence: number;                 // 0.0 - 1.0
  falsePositiveRisk: RiskLevel;       // Risk of saying "real" when fake
  falseNegativeRisk: RiskLevel;       // Risk of saying "fake" when real
  differentialTrustWeight: number;    // Computed from sourceTrust
  reasoningNotes: string[];           // Why this verdict was reached

  // Ethical metadata
  privacyClass: PrivacyClass;
  challengeUrl: string;               // Where to submit a correction
  rightToChallenge: string;           // Plain-language explanation

  // Cryptographic provenance
  provenanceHash: string;             // SHA-256 of the verification check itself
}

export interface VerificationChallenge {
  id: string;
  identificationClaimHash: string;
  submittedBy: string;                // Email or identifier of challenger
  challengeReason: string;
  evidence: string;                   // URL or description of supporting evidence
  status: "PENDING" | "ACCEPTED" | "REJECTED" | "WITHDRAWN";
  submittedAt: string;
  resolvedAt?: string;
  resolution?: string;                // Plain-language explanation
}

// ─────────────────────────────────────────────────────────────────────────
// The Framework
// ─────────────────────────────────────────────────────────────────────────

export class ConscientiousIdentityFramework {
  constructor(private env: Env) {}

  async ensureTables(): Promise<void> {
    const db = this.env.DB;
    await db.batch([
      db.prepare(`CREATE TABLE IF NOT EXISTS identification_claims (
        id TEXT PRIMARY KEY,
        subject TEXT NOT NULL,
        claimed_type TEXT NOT NULL,
        verification_status TEXT NOT NULL,
        confidence REAL NOT NULL,
        source TEXT NOT NULL,
        source_trust TEXT NOT NULL,
        privacy_class TEXT NOT NULL,
        false_positive_risk TEXT NOT NULL,
        false_negative_risk TEXT NOT NULL,
        provenance_hash TEXT NOT NULL,
        full_claim TEXT NOT NULL,
        queried_at TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      )`),
      db.prepare(`CREATE INDEX IF NOT EXISTS idx_idclaims_subject ON identification_claims(subject)`),
      db.prepare(`CREATE INDEX IF NOT EXISTS idx_idclaims_status ON identification_claims(verification_status)`),
      db.prepare(`CREATE INDEX IF NOT EXISTS idx_idclaims_provenance ON identification_claims(provenance_hash)`),
      db.prepare(`CREATE TABLE IF NOT EXISTS verification_challenges (
        id TEXT PRIMARY KEY,
        identification_claim_hash TEXT NOT NULL,
        submitted_by TEXT NOT NULL,
        challenge_reason TEXT NOT NULL,
        evidence TEXT,
        status TEXT NOT NULL DEFAULT 'PENDING',
        submitted_at TEXT NOT NULL DEFAULT (datetime('now')),
        resolved_at TEXT,
        resolution TEXT
      )`),
      db.prepare(`CREATE INDEX IF NOT EXISTS idx_challenges_status ON verification_challenges(status)`),
      db.prepare(`CREATE INDEX IF NOT EXISTS idx_challenges_claim ON verification_challenges(identification_claim_hash)`),
    ]);
  }

  /**
   * Wrap a raw verification result with epistemic metadata and store it.
   */
  async makeIdentificationClaim(input: {
    subject: string;
    claimedType: string;
    claimedAttributes?: Record<string, string>;
    verification: VerificationStatus;
    found?: Record<string, string>;
    source: string;
    sourceUrl?: string;
    sourceTrust: SourceTrust;
    privacyClass?: PrivacyClass;
    reasoningNotes?: string[];
  }): Promise<IdentificationClaim> {
    await this.ensureTables();

    const queriedAt = new Date().toISOString();
    const trustWeight = SOURCE_TRUST_WEIGHTS[input.sourceTrust];

    // Compute confidence + risks based on status and source trust
    const { confidence, falsePositiveRisk, falseNegativeRisk } =
      this.computeEpistemicScores(input.verification, trustWeight);

    // Compute provenance hash — the verification check itself is hashable
    const provenanceContent = JSON.stringify({
      subject: input.subject,
      claimedType: input.claimedType,
      verification: input.verification,
      source: input.source,
      sourceTrust: input.sourceTrust,
      queriedAt,
    });
    const provenanceHash = await sha256Hex(provenanceContent);

    const claim: IdentificationClaim = {
      subject: input.subject,
      claimedType: input.claimedType,
      claimedAttributes: input.claimedAttributes,
      verification: input.verification,
      found: input.found,
      source: input.source,
      sourceUrl: input.sourceUrl,
      sourceTrust: input.sourceTrust,
      queriedAt,
      confidence,
      falsePositiveRisk,
      falseNegativeRisk,
      differentialTrustWeight: trustWeight,
      reasoningNotes: input.reasoningNotes ?? this.defaultReasoningNotes(input.verification, input.source),
      privacyClass: input.privacyClass ?? "PUBLIC",
      challengeUrl: `https://compliance.vernenlegal.com/api/verify/identification/challenge/${provenanceHash}`,
      rightToChallenge:
        "Any party who believes this identification claim is incorrect can submit evidence at challengeUrl. Challenges are reviewed and either confirmed (identification updated) or denied (with reasoning published). This is a public-good protocol — false claims about real entities are as harmful as missed claims about fake ones.",
      provenanceHash,
    };

    // Persist the claim
    const id = `idclaim_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    await this.env.DB.prepare(
      `INSERT INTO identification_claims
        (id, subject, claimed_type, verification_status, confidence,
         source, source_trust, privacy_class, false_positive_risk,
         false_negative_risk, provenance_hash, full_claim, queried_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)`
    )
      .bind(
        id,
        claim.subject,
        claim.claimedType,
        claim.verification,
        claim.confidence,
        claim.source,
        claim.sourceTrust,
        claim.privacyClass,
        claim.falsePositiveRisk,
        claim.falseNegativeRisk,
        claim.provenanceHash,
        JSON.stringify(claim),
        claim.queriedAt
      )
      .run();

    // Anchor the identification check to the verification chain itself
    try {
      const { VerificationEngine } = await import("./verification-engine.js");
      const engine = new VerificationEngine(this.env);
      await engine.appendRecord({
        recordId: id,
        recordType: "identification_claim",
        sourceTable: "identification_claims",
        sourceId: id,
        content: {
          subject: claim.subject,
          verification: claim.verification,
          confidence: claim.confidence,
          source: claim.source,
          provenanceHash: claim.provenanceHash,
        },
        metadata: {
          identification_layer: "Layer 6 — Conscientious Identity Framework",
          privacy_class: claim.privacyClass,
        },
      });
    } catch (err) {
      console.warn(
        "[ConscientiousIdentity] Failed to anchor claim to verification chain:",
        err instanceof Error ? err.message : err
      );
    }

    return claim;
  }

  /**
   * Compute confidence + risk levels from verification status and source trust.
   */
  private computeEpistemicScores(
    status: VerificationStatus,
    trustWeight: number
  ): {
    confidence: number;
    falsePositiveRisk: RiskLevel;
    falseNegativeRisk: RiskLevel;
  } {
    switch (status) {
      case "CONFIRMED":
        return {
          confidence: Math.min(0.95, 0.7 + trustWeight * 0.25),
          falsePositiveRisk: "LOW",
          falseNegativeRisk: "LOW",
        };
      case "LIKELY":
        return {
          confidence: Math.min(0.8, 0.5 + trustWeight * 0.3),
          falsePositiveRisk: "MEDIUM",
          falseNegativeRisk: "LOW",
        };
      case "PARTIAL_MATCH":
        return {
          confidence: Math.min(0.6, 0.3 + trustWeight * 0.3),
          falsePositiveRisk: "MEDIUM",
          falseNegativeRisk: "MEDIUM",
        };
      case "NOT_FOUND":
        // CRITICAL: NOT_FOUND has HIGH false negative risk by design.
        // Absence of evidence is NOT evidence of absence.
        return {
          confidence: 0.3,
          falsePositiveRisk: "LOW",
          falseNegativeRisk: "HIGH",
        };
      case "CONFIRMED_NONEXISTENT":
        return {
          confidence: Math.min(0.9, 0.6 + trustWeight * 0.3),
          falsePositiveRisk: "LOW",
          falseNegativeRisk: "MEDIUM", // Even confirmed-nonexistent has SOME risk
        };
      case "SEALED":
        return {
          confidence: 1.0, // We know it's sealed — that's the verification
          falsePositiveRisk: "LOW",
          falseNegativeRisk: "LOW",
        };
      case "UNDETERMINED":
        return {
          confidence: 0.0,
          falsePositiveRisk: "UNKNOWN",
          falseNegativeRisk: "UNKNOWN",
        };
    }
  }

  /**
   * Default reasoning notes for each verification status — explains the
   * epistemic standing in plain language.
   */
  private defaultReasoningNotes(status: VerificationStatus, source: string): string[] {
    switch (status) {
      case "CONFIRMED":
        return [
          `${source} returned a definitive match for the queried subject.`,
          "Confidence is high but not absolute — even authoritative sources can have data entry errors.",
        ];
      case "LIKELY":
        return [
          `${source} returned a probable match.`,
          "The match is plausible but not definitive. Treat findings as provisional pending corroboration from a second source.",
        ];
      case "PARTIAL_MATCH":
        return [
          `${source} returned partial information that matches some claimed attributes but not all.`,
          "This could indicate a legitimate entity with stale data, or it could indicate a fabrication using a real entity's name.",
        ];
      case "NOT_FOUND":
        return [
          `${source} returned no results for the queried subject.`,
          "CRITICAL: Absence of evidence is NOT evidence of absence. This subject may legitimately exist but be: (a) recently registered and not yet indexed, (b) operating under a different legal name, (c) registered in a jurisdiction not searched, (d) privacy-protected, or (e) genuinely fabricated.",
          "Do not use this NOT_FOUND result to assert fabrication without corroborating evidence from other sources.",
        ];
      case "CONFIRMED_NONEXISTENT":
        return [
          `Multiple authoritative sources explicitly confirm this subject does not exist.`,
          "This is a stronger claim than NOT_FOUND — at least two independent sources searched and returned definitive non-existence.",
          "Even so, retain a small margin for source error.",
        ];
      case "SEALED":
        return [
          "This subject exists but is intentionally privacy-protected.",
          "Sealed corporations, witness protection records, and certain trust structures are deliberately hard to verify by design.",
          "Treat this as confirmed-existing with limited public access.",
        ];
      case "UNDETERMINED":
        return [
          "Insufficient data to make any verification claim about this subject.",
          "No authoritative source has been successfully queried.",
          "DO NOT report this as fabrication or as confirmed — it is simply unknown.",
        ];
    }
  }

  /**
   * Submit a challenge to a previously-made identification claim.
   */
  async submitChallenge(input: {
    identificationClaimHash: string;
    submittedBy: string;
    challengeReason: string;
    evidence: string;
  }): Promise<VerificationChallenge> {
    await this.ensureTables();

    const challenge: VerificationChallenge = {
      id: `challenge_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      identificationClaimHash: input.identificationClaimHash,
      submittedBy: input.submittedBy,
      challengeReason: input.challengeReason,
      evidence: input.evidence,
      status: "PENDING",
      submittedAt: new Date().toISOString(),
    };

    await this.env.DB.prepare(
      `INSERT INTO verification_challenges
        (id, identification_claim_hash, submitted_by, challenge_reason,
         evidence, status, submitted_at)
       VALUES (?1, ?2, ?3, ?4, ?5, 'PENDING', ?6)`
    )
      .bind(
        challenge.id,
        challenge.identificationClaimHash,
        challenge.submittedBy,
        challenge.challengeReason,
        challenge.evidence,
        challenge.submittedAt
      )
      .run();

    return challenge;
  }

  /**
   * Look up a claim by its provenance hash.
   */
  async getClaimByHash(provenanceHash: string): Promise<IdentificationClaim | null> {
    await this.ensureTables();
    const row = await this.env.DB.prepare(
      `SELECT full_claim FROM identification_claims WHERE provenance_hash = ?1 LIMIT 1`
    )
      .bind(provenanceHash)
      .first<{ full_claim: string }>();
    if (!row) return null;
    try {
      return JSON.parse(row.full_claim) as IdentificationClaim;
    } catch {
      return null;
    }
  }

  /**
   * List all claims for a subject across all sources.
   */
  async getClaimsForSubject(subject: string): Promise<IdentificationClaim[]> {
    await this.ensureTables();
    const rows = await this.env.DB.prepare(
      `SELECT full_claim FROM identification_claims WHERE subject = ?1 ORDER BY queried_at DESC`
    )
      .bind(subject)
      .all<{ full_claim: string }>();
    const results: IdentificationClaim[] = [];
    for (const r of rows.results ?? []) {
      try {
        results.push(JSON.parse(r.full_claim) as IdentificationClaim);
      } catch {
        // skip malformed
      }
    }
    return results;
  }
}

// ─────────────────────────────────────────────────────────────────────────
// SHA-256 helper (Web Crypto)
// ─────────────────────────────────────────────────────────────────────────

async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const buf = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
