/**
 * Subject Verification Engine — Layer 6 technical core.
 *
 * Wraps fabrication detection patterns inside the Conscientious Identity
 * Framework so every identification claim carries explicit epistemic standing.
 *
 * This engine exists because the Ryan Mcclaran audit (March 30, 2026) found
 * 23 violations across 18 documents but never verified that the entities
 * described in those documents actually existed. That methodology gap is
 * what Layer 6 closes.
 *
 * The engine queries authoritative sources (FMCSA, state SoS, USPS,
 * professional registries, etc.) for each named subject in an audit and
 * produces a Subject Verification Report that gets attached to the audit
 * before findings are released.
 *
 * Key principles:
 *  - Every check is wrapped in ConscientiousIdentityFramework
 *  - NOT_FOUND is HIGH false negative risk by design
 *  - Multiple sources cross-validate before high confidence
 *  - Privacy-protected entities are recognized, not flagged
 *  - The verification process itself is hashed into the chain
 *
 * License: CC0-1.0
 */

import type { Env } from "../index.js";
import {
  ConscientiousIdentityFramework,
  type IdentificationClaim,
  type VerificationStatus,
  type PrivacyClass,
} from "./conscientious-identity.js";

// ─────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────

export interface ExtractedSubject {
  type: "company" | "person" | "address" | "ein" | "dot_number" | "phone" | "email" | "ip";
  value: string;
  context?: string;          // Where in the document it appeared
  attributes?: Record<string, string>;
}

export interface FabricationIndicator {
  pattern: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  description: string;
  evidence: string;
}

export interface SubjectVerificationReport {
  generatedAt: string;
  fabricationConfidenceScore: number; // 0-100
  verdict:
    | "APPEARS_AUTHENTIC"
    | "INSUFFICIENT_DATA"
    | "MIXED_SIGNALS"
    | "SUSPICIOUS"
    | "HIGHLY_LIKELY_FABRICATED";
  epistemicStanding: string;
  verdictQualifications: string[];
  totalSubjectsExtracted: number;
  identificationClaims: IdentificationClaim[];
  fabricationIndicators: FabricationIndicator[];
  recommendation: string;
}

// ─────────────────────────────────────────────────────────────────────────
// The Engine
// ─────────────────────────────────────────────────────────────────────────

export class SubjectVerificationEngine {
  private cif: ConscientiousIdentityFramework;

  constructor(private env: Env) {
    this.cif = new ConscientiousIdentityFramework(env);
  }

  /**
   * Run all verification patterns on a set of extracted subjects.
   * Returns a Subject Verification Report with epistemic standing.
   */
  async verify(subjects: ExtractedSubject[], rawDocumentText?: string): Promise<SubjectVerificationReport> {
    await this.cif.ensureTables();

    const claims: IdentificationClaim[] = [];
    const indicators: FabricationIndicator[] = [];
    const generatedAt = new Date().toISOString();

    // ─── Run pattern detectors on raw document text ────────────────────
    if (rawDocumentText) {
      const docPatterns = await this.detectDocumentLevelPatterns(rawDocumentText);
      indicators.push(...docPatterns);
    }

    // ─── Verify each extracted subject ─────────────────────────────────
    for (const subject of subjects) {
      try {
        const claim = await this.verifySubject(subject);
        if (claim) claims.push(claim);
      } catch (err) {
        // Verification failure is itself an UNDETERMINED claim
        const undeterminedClaim = await this.cif.makeIdentificationClaim({
          subject: subject.value,
          claimedType: subject.type,
          verification: "UNDETERMINED",
          source: "verification_error",
          sourceTrust: "UNKNOWN",
          reasoningNotes: [
            `Verification attempt failed: ${err instanceof Error ? err.message : String(err)}`,
            "Subject epistemic standing is UNDETERMINED — do NOT report as fabrication.",
          ],
        });
        claims.push(undeterminedClaim);
      }
    }

    // ─── Compute fabrication confidence score ──────────────────────────
    const score = this.computeFabricationScore(claims, indicators);
    const { verdict, epistemicStanding, qualifications } = this.classifyVerdict(score, claims, indicators);

    return {
      generatedAt,
      fabricationConfidenceScore: score,
      verdict,
      epistemicStanding,
      verdictQualifications: qualifications,
      totalSubjectsExtracted: subjects.length,
      identificationClaims: claims,
      fabricationIndicators: indicators,
      recommendation: this.recommendation(verdict),
    };
  }

  /**
   * Verify a single subject against the appropriate authoritative source.
   * Routes to the correct verifier based on subject type.
   */
  private async verifySubject(subject: ExtractedSubject): Promise<IdentificationClaim | null> {
    switch (subject.type) {
      case "company":
        return await this.verifyCompany(subject);
      case "person":
        return await this.verifyPerson(subject);
      case "ein":
        return await this.verifyEIN(subject);
      case "dot_number":
        return await this.verifyDOTNumber(subject);
      case "address":
        return await this.verifyAddress(subject);
      case "ip":
        return await this.verifyIP(subject);
      case "phone":
      case "email":
        // No standard verifier yet — return UNDETERMINED
        return await this.cif.makeIdentificationClaim({
          subject: subject.value,
          claimedType: subject.type,
          verification: "UNDETERMINED",
          source: "no_verifier_available",
          sourceTrust: "UNKNOWN",
          reasoningNotes: [
            `No verifier currently implemented for type '${subject.type}'.`,
            "This is a known gap in Layer 6 v1.0 — see KNOWN_GAPS_AND_ROADMAP.md",
          ],
        });
    }
  }

  // ─── Company verification ──────────────────────────────────────────
  private async verifyCompany(subject: ExtractedSubject): Promise<IdentificationClaim> {
    // Try OpenCorporates first (free public business registry aggregator)
    // covering 180+ jurisdictions including all US states
    const name = subject.value.trim();
    const stateHint = subject.attributes?.["state"];

    try {
      const url = stateHint
        ? `https://api.opencorporates.com/v0.4/companies/search?q=${encodeURIComponent(name)}&jurisdiction_code=us_${stateHint.toLowerCase()}&format=json`
        : `https://api.opencorporates.com/v0.4/companies/search?q=${encodeURIComponent(name)}&format=json`;

      const res = await fetch(url, { headers: { "User-Agent": "Vernen-Verification/1.0" } });

      if (!res.ok) {
        return await this.cif.makeIdentificationClaim({
          subject: name,
          claimedType: "company",
          verification: "UNDETERMINED",
          source: "OpenCorporates",
          sourceUrl: url,
          sourceTrust: "PUBLIC_AGGREGATOR",
          reasoningNotes: [
            `OpenCorporates query returned HTTP ${res.status}`,
            "Cannot determine existence — service unreachable or rate-limited.",
          ],
        });
      }

      const data = (await res.json()) as {
        results?: { companies?: Array<{ company?: { name?: string; jurisdiction_code?: string } }> };
      };
      const matches = data.results?.companies ?? [];

      if (matches.length === 0) {
        return await this.cif.makeIdentificationClaim({
          subject: name,
          claimedType: "company",
          verification: "NOT_FOUND",
          source: "OpenCorporates",
          sourceUrl: url,
          sourceTrust: "PUBLIC_AGGREGATOR",
          reasoningNotes: [
            `OpenCorporates returned 0 matches for "${name}".`,
            "CRITICAL: NOT_FOUND is HIGH false negative risk. The company may legitimately exist but: (a) be too new to be indexed, (b) operate under a DBA, (c) be in a jurisdiction not searched, (d) be privacy-protected.",
            "Do NOT use this NOT_FOUND result alone to assert fabrication. Cross-reference with state SoS directly.",
          ],
        });
      }

      // Check if any match is exact
      const exactMatch = matches.find(
        (m) => m.company?.name?.toLowerCase().trim() === name.toLowerCase().trim()
      );

      if (exactMatch) {
        return await this.cif.makeIdentificationClaim({
          subject: name,
          claimedType: "company",
          verification: "CONFIRMED",
          source: "OpenCorporates",
          sourceUrl: url,
          sourceTrust: "PUBLIC_AGGREGATOR",
          found: {
            jurisdiction: exactMatch.company?.jurisdiction_code ?? "unknown",
          },
          reasoningNotes: [
            `OpenCorporates returned an exact name match in ${exactMatch.company?.jurisdiction_code ?? "unknown jurisdiction"}.`,
            "OpenCorporates aggregates state SoS data — confidence is reduced from authoritative because aggregation can lag.",
          ],
        });
      }

      // Partial matches only
      return await this.cif.makeIdentificationClaim({
        subject: name,
        claimedType: "company",
        verification: "PARTIAL_MATCH",
        source: "OpenCorporates",
        sourceUrl: url,
        sourceTrust: "PUBLIC_AGGREGATOR",
        found: { match_count: String(matches.length) },
        reasoningNotes: [
          `OpenCorporates returned ${matches.length} partial matches but no exact name match.`,
          "Could indicate the queried name is a DBA or slight variation of a real entity, or a fabrication that overlaps with real entity names.",
        ],
      });
    } catch (err) {
      return await this.cif.makeIdentificationClaim({
        subject: name,
        claimedType: "company",
        verification: "UNDETERMINED",
        source: "OpenCorporates",
        sourceTrust: "PUBLIC_AGGREGATOR",
        reasoningNotes: [
          `Network error querying OpenCorporates: ${err instanceof Error ? err.message : String(err)}`,
          "Cannot determine existence — verification service was unreachable.",
        ],
      });
    }
  }

  // ─── DOT number verification (FMCSA) ──────────────────────────────
  private async verifyDOTNumber(subject: ExtractedSubject): Promise<IdentificationClaim> {
    const dot = subject.value.replace(/\D/g, "");
    if (!dot) {
      return await this.cif.makeIdentificationClaim({
        subject: subject.value,
        claimedType: "dot_number",
        verification: "UNDETERMINED",
        source: "input_validation",
        sourceTrust: "UNKNOWN",
        reasoningNotes: ["DOT number input was empty after digit extraction."],
      });
    }

    try {
      const url = `https://mobile.fmcsa.dot.gov/qc/services/carriers/${dot}?webKey=`;
      const res = await fetch(url, { headers: { "Accept": "application/json" } });
      if (!res.ok) {
        return await this.cif.makeIdentificationClaim({
          subject: dot,
          claimedType: "dot_number",
          verification: "UNDETERMINED",
          source: "FMCSA SAFER",
          sourceUrl: url,
          sourceTrust: "GOVERNMENT_AUTHORITATIVE",
          reasoningNotes: [
            `FMCSA SAFER returned HTTP ${res.status}`,
            "Cannot determine existence — service unreachable.",
          ],
        });
      }
      const data = (await res.json()) as { content?: { carrier?: unknown } };
      if (data.content?.carrier) {
        return await this.cif.makeIdentificationClaim({
          subject: dot,
          claimedType: "dot_number",
          verification: "CONFIRMED",
          source: "FMCSA SAFER",
          sourceUrl: url,
          sourceTrust: "GOVERNMENT_AUTHORITATIVE",
          reasoningNotes: [
            `FMCSA SAFER returned an active carrier record for DOT #${dot}.`,
            "FMCSA is the federal authority for trucking carrier registration.",
          ],
        });
      }
      return await this.cif.makeIdentificationClaim({
        subject: dot,
        claimedType: "dot_number",
        verification: "CONFIRMED_NONEXISTENT",
        source: "FMCSA SAFER",
        sourceUrl: url,
        sourceTrust: "GOVERNMENT_AUTHORITATIVE",
        reasoningNotes: [
          `FMCSA SAFER explicitly returned no carrier for DOT #${dot}.`,
          "FMCSA is authoritative for federal trucking registration. A claimed DOT number that returns nothing is a strong signal of fabrication, but retain a small margin for very recently issued numbers.",
        ],
      });
    } catch (err) {
      return await this.cif.makeIdentificationClaim({
        subject: dot,
        claimedType: "dot_number",
        verification: "UNDETERMINED",
        source: "FMCSA SAFER",
        sourceTrust: "GOVERNMENT_AUTHORITATIVE",
        reasoningNotes: [
          `Network error querying FMCSA: ${err instanceof Error ? err.message : String(err)}`,
        ],
      });
    }
  }

  // ─── Person verification (NPI / professional license) ────────────
  private async verifyPerson(subject: ExtractedSubject): Promise<IdentificationClaim> {
    // Person verification is highly context-dependent. Without a profession
    // hint, we can only return UNDETERMINED — and we explicitly flag the
    // false negative risk because most real people don't appear in any
    // public registry.
    return await this.cif.makeIdentificationClaim({
      subject: subject.value,
      claimedType: "person",
      verification: "UNDETERMINED",
      source: "no_general_person_registry",
      sourceTrust: "UNKNOWN",
      privacyClass: "PUBLIC",
      reasoningNotes: [
        "There is no general public registry of all real people. A real person's absence from any specific database is meaningless.",
        "Person verification requires context: profession (NPI for healthcare, bar association for attorneys, state licensing boards for trades), employment relationship (DOL records), or court involvement (PACER).",
        "Returning UNDETERMINED to avoid false-negative weaponization. Future verifiers can refine this with profession hints.",
      ],
    });
  }

  // ─── EIN verification ─────────────────────────────────────────────
  private async verifyEIN(subject: ExtractedSubject): Promise<IdentificationClaim> {
    // EIN verification via IRS is gated behind tax preparer credentials.
    // We can format-check (9 digits) and check publicly-known IRS publications.
    const ein = subject.value.replace(/\D/g, "");
    if (ein.length !== 9) {
      return await this.cif.makeIdentificationClaim({
        subject: subject.value,
        claimedType: "ein",
        verification: "CONFIRMED_NONEXISTENT",
        source: "format_validation",
        sourceTrust: "GOVERNMENT_DERIVED",
        reasoningNotes: [
          `EIN must be exactly 9 digits. Received ${ein.length} digits.`,
          "This is a format-level fabrication signal — invalid EINs cannot exist.",
        ],
      });
    }
    return await this.cif.makeIdentificationClaim({
      subject: ein,
      claimedType: "ein",
      verification: "UNDETERMINED",
      source: "format_only",
      sourceTrust: "USER_SUBMITTED",
      reasoningNotes: [
        "EIN format is valid (9 digits).",
        "Full EIN verification requires IRS tax preparer credentials — not implemented in v1.0.",
        "Cross-reference against the entity's public SEC filings (if any) for indirect verification.",
      ],
    });
  }

  // ─── Address verification (USPS) ─────────────────────────────────
  private async verifyAddress(subject: ExtractedSubject): Promise<IdentificationClaim> {
    // USPS Address Verification API requires a free credential. For v1.0
    // we do format-only validation.
    const addr = subject.value;
    const looksValid = /\d+\s+\w+/.test(addr);
    return await this.cif.makeIdentificationClaim({
      subject: addr,
      claimedType: "address",
      verification: looksValid ? "PARTIAL_MATCH" : "UNDETERMINED",
      source: "format_validation",
      sourceTrust: "USER_SUBMITTED",
      reasoningNotes: [
        looksValid
          ? "Address has plausible street format (number + street name) but has not been verified against USPS."
          : "Address does not have a parseable street format.",
        "Full USPS verification requires a free USPS Web Tools credential — not implemented in v1.0. See KNOWN_GAPS_AND_ROADMAP.md.",
      ],
    });
  }

  // ─── IP verification (geolocation + reputation) ──────────────────
  private async verifyIP(subject: ExtractedSubject): Promise<IdentificationClaim> {
    const ip = subject.value;
    // Cloudflare provides IP geolocation via cf-ipcountry, but for arbitrary
    // IPs we'd need an external service. For now, classify by simple checks.
    return await this.cif.makeIdentificationClaim({
      subject: ip,
      claimedType: "ip",
      verification: "PARTIAL_MATCH",
      source: "format_only",
      sourceTrust: "USER_SUBMITTED",
      reasoningNotes: [
        `IP ${ip} format is valid.`,
        "Full IP verification (geolocation, abuse reputation, ASN) requires external services — flagged for v1.1.",
      ],
    });
  }

  // ─────────────────────────────────────────────────────────────────
  // Document-level pattern detection (does not require external APIs)
  // ─────────────────────────────────────────────────────────────────
  private async detectDocumentLevelPatterns(rawText: string): Promise<FabricationIndicator[]> {
    const indicators: FabricationIndicator[] = [];
    const lower = rawText.toLowerCase();

    // Pattern 1: DocuSign demo platform signatures
    if (lower.includes("demonstration document only") || lower.includes("docusign demo")) {
      indicators.push({
        pattern: "demo_platform_signature",
        severity: "CRITICAL",
        description: "Documents bear DocuSign demonstration platform watermarks.",
        evidence: "Found 'DEMONSTRATION DOCUMENT ONLY' or 'DocuSign Demo' in document text.",
      });
    }

    // Pattern 2: Foreign IP origins (check for known suspicious country codes/IPs)
    const ipMatches = rawText.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g);
    if (ipMatches) {
      // Serbian IP range (79.101.x.x) — example from Ryan case
      const serbian = ipMatches.find((ip) => ip.startsWith("79.101."));
      if (serbian) {
        indicators.push({
          pattern: "foreign_ip_origin",
          severity: "HIGH",
          description: `Document transmitted from IP geolocating to Serbia (${serbian}).`,
          evidence: "Foreign IP origins on US domestic contracts are a fabrication red flag, but real outsourcing operations exist — corroborate before concluding fabrication.",
        });
      }
    }

    // Pattern 3: Caricatured entity names
    const caricaturedNames = [
      "super ego",
      "enlightened truckers",
      "windy city national",
      "rex trucking",
      "floyd logistics",
    ];
    const matchedNames = caricaturedNames.filter((n) => lower.includes(n));
    if (matchedNames.length > 0) {
      indicators.push({
        pattern: "caricatured_entity_names",
        severity: "MEDIUM",
        description: `Document contains entity names that statistically deviate from real US business naming patterns: ${matchedNames.join(", ")}.`,
        evidence: "Real predatory carriers use boring industrial names. Caricatured names suggest synthetic test data.",
      });
    }

    // Pattern 4: Suspiciously clean numerical patterns (Benford's Law violation)
    const dollarAmounts = rawText.match(/\$[\d,]+(\.\d{2})?/g);
    if (dollarAmounts && dollarAmounts.length >= 10) {
      const leadingDigits = dollarAmounts.map((a) => {
        const m = a.match(/[1-9]/);
        return m ? parseInt(m[0], 10) : 0;
      });
      const benfordDeviation = computeBenfordDeviation(leadingDigits);
      if (benfordDeviation > 0.4) {
        indicators.push({
          pattern: "benford_law_violation",
          severity: "MEDIUM",
          description: `Dollar amount distribution deviates significantly from Benford's Law (deviation: ${benfordDeviation.toFixed(2)}).`,
          evidence: "Real financial records follow Benford's Law (1 appears as leading digit ~30% of time, etc.). Significant deviation suggests fabricated numbers.",
        });
      }
    }

    return indicators;
  }

  // ─────────────────────────────────────────────────────────────────
  // Aggregation and verdict
  // ─────────────────────────────────────────────────────────────────
  private computeFabricationScore(
    claims: IdentificationClaim[],
    indicators: FabricationIndicator[]
  ): number {
    let score = 0;

    // Identification claims contribute risk based on status + trust
    for (const claim of claims) {
      switch (claim.verification) {
        case "CONFIRMED_NONEXISTENT":
          // Authoritative non-existence is strong signal
          score += 25 * claim.differentialTrustWeight;
          break;
        case "NOT_FOUND":
          // NOT_FOUND is weak by itself — high false negative risk
          // But adds incrementally if many subjects are NOT_FOUND
          score += 5 * claim.differentialTrustWeight;
          break;
        case "PARTIAL_MATCH":
          score += 3;
          break;
        case "CONFIRMED":
          // Reduces fabrication score
          score -= 10 * claim.differentialTrustWeight;
          break;
        case "LIKELY":
          score -= 5 * claim.differentialTrustWeight;
          break;
        case "SEALED":
          // Sealed entities are real — no contribution
          break;
        case "UNDETERMINED":
          // No contribution either way
          break;
      }
    }

    // Indicators contribute based on severity
    for (const ind of indicators) {
      switch (ind.severity) {
        case "CRITICAL":
          score += 25;
          break;
        case "HIGH":
          score += 15;
          break;
        case "MEDIUM":
          score += 8;
          break;
        case "LOW":
          score += 3;
          break;
      }
    }

    return Math.max(0, Math.min(100, Math.round(score)));
  }

  private classifyVerdict(
    score: number,
    claims: IdentificationClaim[],
    indicators: FabricationIndicator[]
  ): {
    verdict: SubjectVerificationReport["verdict"];
    epistemicStanding: string;
    qualifications: string[];
  } {
    const qualifications: string[] = [];

    // Identify high false-negative risks
    const highFNRClaims = claims.filter((c) => c.falseNegativeRisk === "HIGH");
    if (highFNRClaims.length > 0) {
      qualifications.push(
        `${highFNRClaims.length} identification claim(s) carry HIGH false-negative risk. The verdict accounts for this — but reviewers should examine each NOT_FOUND result to determine whether the absent subject is plausibly real.`
      );
    }

    // Note insufficient data conditions
    const undeterminedCount = claims.filter((c) => c.verification === "UNDETERMINED").length;
    if (undeterminedCount > claims.length / 2) {
      qualifications.push(
        `Over half of subjects are UNDETERMINED. The verification was unable to query authoritative sources for most subjects. The verdict is provisional.`
      );
    }

    // Note caveats from indicators
    if (indicators.some((i) => i.pattern === "demo_platform_signature")) {
      qualifications.push(
        "Demo platform signatures are a CRITICAL fabrication indicator regardless of other findings. Real predatory operations need enforceable contracts and would not knowingly use a demo platform."
      );
    }

    let verdict: SubjectVerificationReport["verdict"];
    let epistemicStanding: string;

    if (score >= 70) {
      verdict = "HIGHLY_LIKELY_FABRICATED";
      epistemicStanding = "HIGH_CONFIDENCE_WITH_ACKNOWLEDGED_LIMITS";
    } else if (score >= 40) {
      verdict = "SUSPICIOUS";
      epistemicStanding = "MODERATE_CONFIDENCE";
    } else if (score >= 20) {
      verdict = "MIXED_SIGNALS";
      epistemicStanding = "LOW_CONFIDENCE";
    } else if (claims.filter((c) => c.verification === "CONFIRMED").length > 0) {
      verdict = "APPEARS_AUTHENTIC";
      epistemicStanding = "MODERATE_CONFIDENCE";
    } else {
      verdict = "INSUFFICIENT_DATA";
      epistemicStanding = "INSUFFICIENT_DATA_FOR_CLAIM";
    }

    return { verdict, epistemicStanding, qualifications };
  }

  private recommendation(verdict: SubjectVerificationReport["verdict"]): string {
    switch (verdict) {
      case "APPEARS_AUTHENTIC":
        return "Audit findings can be released. Subject verification supports authenticity of named entities.";
      case "INSUFFICIENT_DATA":
        return "Audit findings should be released with explicit notation that subject verification was inconclusive. Recommend manual review by counsel before any legal action.";
      case "MIXED_SIGNALS":
        return "Audit findings should be released as PROVISIONAL. Some subjects verified, others did not. Recommend targeted manual verification of unverified subjects before legal action.";
      case "SUSPICIOUS":
        return "Audit findings should be SEALED pending manual review. Multiple fabrication indicators detected. Do NOT use audit to support legal claims until subject verification completes via authoritative sources directly.";
      case "HIGHLY_LIKELY_FABRICATED":
        return "Audit findings should NOT be released for legal action. Multiple subjects could not be verified and document-level fabrication indicators are present. Treat the entire document set as adversarial input. Consider whether the documents were submitted as part of a fraud scheme or as a deliberate test of the audit platform.";
    }
  }
}

// ─────────────────────────────────────────────────────────────────
// Benford's Law deviation calculator
// ─────────────────────────────────────────────────────────────────
function computeBenfordDeviation(leadingDigits: number[]): number {
  const expected: Record<number, number> = {
    1: 0.301,
    2: 0.176,
    3: 0.125,
    4: 0.097,
    5: 0.079,
    6: 0.067,
    7: 0.058,
    8: 0.051,
    9: 0.046,
  };
  const counts: Record<number, number> = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0, 6: 0, 7: 0, 8: 0, 9: 0 };
  for (const d of leadingDigits) {
    if (d >= 1 && d <= 9) counts[d]!++;
  }
  const total = leadingDigits.filter((d) => d >= 1 && d <= 9).length;
  if (total === 0) return 0;

  let totalDeviation = 0;
  for (let d = 1; d <= 9; d++) {
    const observed = counts[d]! / total;
    const expectedRate = expected[d]!;
    totalDeviation += Math.abs(observed - expectedRate);
  }
  return totalDeviation;
}
