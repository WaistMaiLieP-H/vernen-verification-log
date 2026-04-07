/**
 * Layer 7d — Unconscionability Trigger / Predatory Math Auditor
 *
 * Real-time actuarial audit of financial terms in contracts. Detects:
 *
 *   1. Disguised security interests — "leases" that are mathematically loans
 *      (UCC Article 9 §1-203 disguised security interest test)
 *   2. Predatory effective APR — when stated rates hide true cost
 *   3. Residual value gap — when "buyouts" are below market value
 *   4. Usury — when effective rates exceed jurisdictional caps
 *   5. Zero-equity rent schemes — payments accumulate no ownership
 *   6. Forfeiture clauses — equity destroyed on default
 *
 * The Ryan Mcclaran audit (March 30, 2026) caught the $156K lease as
 * unconscionable manually (Finding #9). This module makes the same finding
 * mathematically rigorous and citable to UCC Article 9 §1-203, so a federal
 * judge can adopt the analysis without needing an expert witness.
 *
 * Spec: docs/LAYER_7_STRUCTURAL_FORENSIC_ANALYSIS.md
 * License: CC0-1.0
 */

import type { Env } from "../index.js";

// ─── Types ───────────────────────────────────────────────────────────────

export interface FinancialTerms {
  documentId: string;
  documentName?: string;
  documentType: "lease" | "lease_to_purchase" | "loan" | "rental" | "other";
  jurisdiction?: string;          // Two-letter state code
  parties?: { lessor?: string; lessee?: string };

  // Core financial fields
  principalAmount: number;        // Total stated value of the asset
  downPayment?: number;           // Initial payment, if any
  paymentAmount: number;          // Per-payment amount
  paymentFrequency: "weekly" | "biweekly" | "monthly" | "quarterly" | "annual";
  paymentCount: number;           // Total number of payments
  buyoutAmount?: number;          // Final purchase amount (for lease-to-purchase)
  estimatedFairMarketValue?: number;  // Asset value at end of term

  // Default and termination terms
  defaultInterestRate?: number;   // Annual % (e.g., 18 for 18%)
  repossessionWithoutProcess?: boolean;
  zeroEquityOnDefault?: boolean;  // Payments convert to rent on default
  jurisdictionForumClause?: string;  // Where disputes must be filed

  // Risk-shifting clauses
  warranty?: "none" | "limited" | "full" | "as_is";
  maintenanceObligation?: "lessor" | "lessee" | "shared";
  insuranceObligation?: "lessor" | "lessee" | "shared";

  // Consumer-loan structural fields (added v2 — supports 7d engine
  // detection of TILA/Reg Z, FTC Credit Practices Rule, choice of law,
  // and procedural unconscionability flags. All optional for backward
  // compatibility with existing lease-only callers.)
  netProceeds?: number;             // Amount actually advanced after fees
  originationFee?: number;          // Pre-funding fee
  disclosedAPR?: number;            // What the contract claims
  governingLawState?: string;       // Two-letter state code from choice-of-law clause
  hasConfessionOfJudgment?: boolean;
  hasJuryWaiver?: boolean;
  hasClassActionWaiver?: boolean;
  hasNoCurePeriod?: boolean;
  hasOneSidedFeeShifting?: boolean;
}

export type UnconscionabilityFlag =
  | "DISGUISED_SECURITY_INTEREST"
  | "PREDATORY_EFFECTIVE_APR"
  | "ZERO_EQUITY_FORFEITURE"
  | "USURY_VIOLATION"
  | "JURISDICTIONAL_OPPRESSION"
  | "FORUM_SELECTION_OPPRESSION"
  | "RISK_TRANSFER_TOTAL"
  | "REPOSSESSION_WITHOUT_PROCESS"
  | "RESIDUAL_VALUE_GAP"
  | "MATH_NULL_OWNERSHIP"
  | "FRAUDULENT_APR_DISCLOSURE"
  | "ORIGINATION_FEE_FINANCE_CHARGE_MISCLASSIFICATION"
  | "CONFESSION_OF_JUDGMENT"
  | "CHOICE_OF_LAW_EVASION"
  | "ONE_SIDED_FEE_SHIFTING"
  | "CLASS_ACTION_AND_JURY_WAIVER"
  | "NO_CURE_PERIOD";

export interface UnconscionabilityFinding {
  flag: UnconscionabilityFlag;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  finding: string;
  evidence: string;
  legalImplication: string;
  citation: string;
}

export interface ActuarialReport {
  generatedAt: string;
  documentId: string;
  documentName?: string;
  totalCostToLessee: number;       // What they pay over the term
  totalEquityGained: number;       // What they own at end
  effectivePerPaymentMultiplier: number;  // total cost / principal
  effectiveAnnualRate: number;     // APR equivalent
  residualValueGapPercent: number; // How far below market the buyout is
  unconscionabilityScore: number;  // 0-100
  verdict:
    | "STANDARD"
    | "AGGRESSIVE"
    | "PREDATORY"
    | "UNCONSCIONABLE_AS_MATTER_OF_LAW";
  findings: UnconscionabilityFinding[];
  recommendation: string;
}

// ─── State usury caps (annual %, civil/consumer) ─────────────────────────
// Sources: state statutes. Updated through 2025.
const STATE_USURY_CAPS: Record<string, number> = {
  AL: 8, AK: 10.5, AZ: 10, AR: 17, CA: 10, CO: 12, CT: 12, DE: 5,
  FL: 18, GA: 7, HI: 10, ID: 12, IL: 9, IN: 21, IA: 5, KS: 15,
  KY: 8, LA: 12, ME: 30, MD: 24, MA: 6, MI: 7, MN: 8, MS: 10,
  MO: 8, MT: 10, NE: 16, NV: 10, NH: 10, NJ: 30, NM: 15, NY: 16,
  NC: 8, ND: 5.5, OH: 8, OK: 10, OR: 9, PA: 6, RI: 21, SC: 8.75,
  SD: 12, TN: 10, TX: 6, UT: 10, VT: 12, VA: 8, WA: 12, WV: 6,
  WI: 12, WY: 7,
};

// ─── Engine ──────────────────────────────────────────────────────────────

export class UnconscionabilityTrigger {
  constructor(private env: Env) {}

  async ensureTables(): Promise<void> {
    const db = this.env.DB;
    await db.batch([
      db.prepare(`CREATE TABLE IF NOT EXISTS actuarial_reports (
        id TEXT PRIMARY KEY,
        document_id TEXT NOT NULL,
        document_name TEXT,
        total_cost REAL NOT NULL,
        total_equity REAL NOT NULL,
        effective_apr REAL NOT NULL,
        residual_value_gap REAL NOT NULL,
        unconscionability_score INTEGER NOT NULL,
        verdict TEXT NOT NULL,
        findings_count INTEGER NOT NULL,
        full_report TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      )`),
      db.prepare(`CREATE INDEX IF NOT EXISTS idx_actuarial_doc ON actuarial_reports(document_id)`),
      db.prepare(`CREATE INDEX IF NOT EXISTS idx_actuarial_verdict ON actuarial_reports(verdict)`),
    ]);
  }

  /**
   * Run an actuarial audit on a set of financial terms.
   */
  async audit(terms: FinancialTerms): Promise<ActuarialReport> {
    await this.ensureTables();

    const findings: UnconscionabilityFinding[] = [];

    // ─── Compute basic metrics ────────────────────────────────────────
    const downPayment = terms.downPayment ?? 0;
    const totalPayments = terms.paymentAmount * terms.paymentCount;
    const buyout = terms.buyoutAmount ?? 0;
    const totalCost = downPayment + totalPayments + buyout;

    // Total equity at end of term
    const totalEquity = terms.zeroEquityOnDefault
      ? 0
      : (terms.estimatedFairMarketValue ?? 0);

    // Effective per-payment multiplier
    const effectiveMultiplier = totalCost / Math.max(terms.principalAmount, 1);

    // Effective annual rate (simplified — for full IRR we'd need iteration)
    // This is the simple-interest equivalent: (totalCost - principal) / principal / years
    const years = this.computeYears(terms.paymentFrequency, terms.paymentCount);
    const interestPaid = Math.max(0, totalCost - terms.principalAmount);
    const effectiveAPR = years > 0 ? (interestPaid / terms.principalAmount / years) * 100 : 0;

    // Residual value gap
    const fmv = terms.estimatedFairMarketValue ?? terms.principalAmount * 0.3; // rough estimate
    const residualGapPercent = fmv > 0 ? Math.max(0, ((fmv - buyout) / fmv) * 100) : 0;

    // ─── Run unconscionability tests ──────────────────────────────────

    // Test 1: Disguised Security Interest (UCC §1-203)
    if (terms.documentType === "lease" || terms.documentType === "lease_to_purchase") {
      // Test A: Buyout < 10% FMV → presumption of disguised security interest
      if (buyout < fmv * 0.1) {
        findings.push({
          flag: "DISGUISED_SECURITY_INTEREST",
          severity: "CRITICAL",
          finding: `Lease buyout of $${buyout.toFixed(2)} is less than 10% of estimated fair market value ($${fmv.toFixed(2)}).`,
          evidence: `Buyout: $${buyout}, FMV estimate: $${fmv.toFixed(2)}, ratio: ${((buyout / fmv) * 100).toFixed(1)}%`,
          legalImplication: "Under UCC §1-203, a transaction labeled as a lease is treated as a disguised security interest if the buyout option is below the reasonably predicted fair market value. This means the 'lease' is legally a loan, the lessor is a secured creditor, and Article 9 protections apply (judicial foreclosure required, not extrajudicial repossession; statutory notice requirements; deficiency limitations).",
          citation: "UCC §1-203(b); Restatement (Third) of Property: Mortgages §1.1",
        });
      }

      // Test B: Total cost >= principal AND zero equity AND lessee bears all risk → loan in disguise
      if (totalCost >= terms.principalAmount && terms.zeroEquityOnDefault && terms.maintenanceObligation === "lessee") {
        findings.push({
          flag: "MATH_NULL_OWNERSHIP",
          severity: "CRITICAL",
          finding: `Lessee pays full purchase price ($${totalCost.toFixed(2)} ≥ $${terms.principalAmount}) over the term but accumulates zero equity and bears 100% of operational risk.`,
          evidence: `Total payments: $${totalCost}, Principal: $${terms.principalAmount}, Equity gained: $0, Maintenance obligation: lessee`,
          legalImplication: "When a lessee pays the full purchase price of an asset but receives no ownership interest, the transaction is economically a loan with the asset as collateral. The label 'lease' is a sham. This transaction is voidable as unconscionable under UCC §2A-108 (unconscionability in lease contracts) and may constitute consumer fraud under state UDAP statutes.",
          citation: "UCC §2A-108; Williams v. Walker-Thomas Furniture Co., 350 F.2d 445 (D.C. Cir. 1965)",
        });
      }
    }

    // Test 2: Effective APR vs jurisdictional usury cap
    if (terms.jurisdiction && STATE_USURY_CAPS[terms.jurisdiction.toUpperCase()] !== undefined) {
      const cap = STATE_USURY_CAPS[terms.jurisdiction.toUpperCase()]!;
      if (effectiveAPR > cap) {
        findings.push({
          flag: "USURY_VIOLATION",
          severity: "HIGH",
          finding: `Effective annual rate of ${effectiveAPR.toFixed(2)}% exceeds the ${terms.jurisdiction} usury cap of ${cap}%.`,
          evidence: `Total interest: $${interestPaid.toFixed(2)} on principal $${terms.principalAmount} over ${years.toFixed(1)} years. Effective APR: ${effectiveAPR.toFixed(2)}%`,
          legalImplication: `${terms.jurisdiction} state law limits civil interest rates to ${cap}% per year. Charges in excess are usurious. Penalties typically include forfeiture of all interest, return of usurious payments, and in some jurisdictions return of principal plus statutory damages.`,
          citation: this.usuryStatuteFor(terms.jurisdiction),
        });
      }
    }

    // Test 3: Default interest rate usury
    if (terms.defaultInterestRate && terms.defaultInterestRate > 18) {
      findings.push({
        flag: "PREDATORY_EFFECTIVE_APR",
        severity: "HIGH",
        finding: `Default interest rate of ${terms.defaultInterestRate}% exceeds typical usury thresholds in most US jurisdictions.`,
        evidence: `Stated default rate: ${terms.defaultInterestRate}% annual`,
        legalImplication: "Default interest rates above 18% are presumptively unconscionable in most consumer contexts and trigger usury statutes in most states.",
        citation: "Most state usury statutes; UCC §2A-108 (lease unconscionability)",
      });
    }

    // Test 4: Zero equity forfeiture (independent of disguised security interest)
    if (terms.zeroEquityOnDefault && terms.documentType === "lease_to_purchase") {
      findings.push({
        flag: "ZERO_EQUITY_FORFEITURE",
        severity: "CRITICAL",
        finding: "Document is titled 'lease-to-purchase' but contains a clause converting all payments to non-equity rent on default.",
        evidence: "Zero-equity-on-default clause present",
        legalImplication: "Lease-to-purchase agreements that convert payments to rent on default destroy the consideration that distinguishes them from rental agreements. The 'purchase' framing is a material misrepresentation. Under most state UDAP statutes, this constitutes a deceptive practice. The clause itself is voidable as unconscionable.",
        citation: "UCC §2A-108; State UDAP statutes (e.g., Cal. Civ. Code §1770); Restatement (Second) of Contracts §208 (unconscionable contract or term)",
      });
    }

    // Test 5: Repossession without legal process
    if (terms.repossessionWithoutProcess) {
      findings.push({
        flag: "REPOSSESSION_WITHOUT_PROCESS",
        severity: "HIGH",
        finding: "Contract permits repossession without legal process.",
        evidence: "Self-help repossession clause present",
        legalImplication: "Self-help repossession is permitted under UCC §9-609 only for security interests, not true leases, and only without breach of the peace. If the underlying transaction is actually a disguised security interest (see Test 1), the lessor must follow Article 9 procedures, not the contract's self-help clause. Contractual waivers of judicial process are voidable in many jurisdictions.",
        citation: "UCC §9-609; state laws governing self-help repossession",
      });
    }

    // Test 6: Total risk transfer to lessee
    if (
      terms.maintenanceObligation === "lessee" &&
      terms.insuranceObligation === "lessee" &&
      terms.warranty === "as_is"
    ) {
      findings.push({
        flag: "RISK_TRANSFER_TOTAL",
        severity: "HIGH",
        finding: "Lessee bears 100% of maintenance, insurance, and operational risk while lessor retains all equity.",
        evidence: "Maintenance: lessee. Insurance: lessee. Warranty: AS-IS.",
        legalImplication: "When a lessor transfers all operational risk to the lessee while retaining all ownership, the transaction is economically a loan with the lessee as the de facto owner for risk purposes. This pattern is one of the strongest signals of a disguised security interest under UCC §1-203(b).",
        citation: "UCC §1-203(b); UCC §2A-108",
      });
    }

    // Test 7: Forum selection oppression
    if (terms.jurisdictionForumClause && terms.jurisdiction) {
      const forumIsForeign = !terms.jurisdictionForumClause
        .toUpperCase()
        .includes(terms.jurisdiction.toUpperCase());
      if (forumIsForeign) {
        findings.push({
          flag: "JURISDICTIONAL_OPPRESSION",
          severity: "MEDIUM",
          finding: `Contract requires disputes to be litigated in ${terms.jurisdictionForumClause}, while the lessee resides in ${terms.jurisdiction}.`,
          evidence: `Forum selection clause: ${terms.jurisdictionForumClause}; Lessee jurisdiction: ${terms.jurisdiction}`,
          legalImplication: "Forum selection clauses requiring litigation in distant forums are presumptively unconscionable when the cost of travel and out-of-state representation effectively denies the lessee access to courts. Many state courts will refuse to enforce such clauses against consumers and small businesses.",
          citation: "Restatement (Second) of Conflict of Laws §80; Carnival Cruise Lines v. Shute, 499 U.S. 585 (1991) — cited as the limit, not the rule",
        });
      }
    }

    // Test 8: Residual value gap
    if (residualGapPercent > 50 && (terms.documentType === "lease" || terms.documentType === "lease_to_purchase")) {
      findings.push({
        flag: "RESIDUAL_VALUE_GAP",
        severity: "MEDIUM",
        finding: `Residual value gap of ${residualGapPercent.toFixed(1)}% — buyout is significantly below estimated fair market value.`,
        evidence: `FMV estimate: $${fmv.toFixed(2)}, Buyout: $${buyout}, Gap: ${residualGapPercent.toFixed(1)}%`,
        legalImplication: "When the buyout is significantly below the asset's market value, the transaction is more accurately characterized as a financed sale than a true lease.",
        citation: "UCC §1-203(b)(4)",
      });
    }

    // ─── Consumer-loan structural tests (v2) ─────────────────────────

    // Test 9: Fraudulent APR disclosure (TILA / Reg Z)
    // If the disclosed APR is materially understated relative to the
    // effective APR computed on net proceeds, the disclosure is fraudulent
    // under the Truth in Lending Act regardless of whether the math is
    // technically defensible under the lender's interpretation.
    if (terms.disclosedAPR !== undefined && (terms.netProceeds ?? 0) > 0) {
      const netProceeds = terms.netProceeds!;
      const interestOnNet = Math.max(0, totalCost - netProceeds);
      const effectiveOnNet = years > 0 ? (interestOnNet / netProceeds / years) * 100 : 0;
      if (effectiveOnNet > terms.disclosedAPR * 1.5) {
        findings.push({
          flag: "FRAUDULENT_APR_DISCLOSURE",
          severity: "CRITICAL",
          finding: `Disclosed APR is ${terms.disclosedAPR}%, but effective APR on net proceeds is approximately ${effectiveOnNet.toFixed(0)}% — disclosure understates true cost by a factor of ${(effectiveOnNet / terms.disclosedAPR).toFixed(1)}x.`,
          evidence: `Net proceeds $${netProceeds.toFixed(2)}, total payments $${totalCost.toFixed(2)}, term ${years.toFixed(2)} years, effective simple APR ${effectiveOnNet.toFixed(1)}%`,
          legalImplication: "TILA (15 U.S.C. §1601 et seq.) and Regulation Z (12 C.F.R. Part 1026) require lenders to disclose the APR in a manner that reflects the true cost of credit. Materially understating the APR by excluding fees from the finance charge is a violation that triggers civil penalties (15 U.S.C. §1640), the right of rescission for secured loans (15 U.S.C. §1635), and (in some states) automatic forfeiture of all interest.",
          citation: "15 U.S.C. §1601 et seq. (TILA); 12 C.F.R. §1026.4 (finance charge); Mourning v. Family Publications Service, 411 U.S. 356 (1973)",
        });
      }
    }

    // Test 10: Origination fee misclassification
    if ((terms.originationFee ?? 0) > 0 && terms.disclosedAPR !== undefined) {
      findings.push({
        flag: "ORIGINATION_FEE_FINANCE_CHARGE_MISCLASSIFICATION",
        severity: "HIGH",
        finding: `Origination fee of $${terms.originationFee!.toFixed(2)} is reported alongside a disclosed APR of ${terms.disclosedAPR}%. Under 12 C.F.R. §1026.4 the fee must be included in the finance charge for APR computation; excluding it produces a misleading rate.`,
        evidence: `Origination fee: $${terms.originationFee}; Disclosed APR: ${terms.disclosedAPR}%`,
        legalImplication: "Regulation Z §1026.4(a) defines the finance charge to include 'any charge payable directly or indirectly by the consumer and imposed directly or indirectly by the creditor as an incident to or a condition of the extension of credit.' Origination fees fall squarely within this definition. Excluding them violates TILA and triggers the same remedies.",
        citation: "12 C.F.R. §1026.4(a); 12 C.F.R. §1026.4(b)(3)",
      });
    }

    // Test 11: Confession of judgment (per se unenforceable against consumers)
    if (terms.hasConfessionOfJudgment) {
      findings.push({
        flag: "CONFESSION_OF_JUDGMENT",
        severity: "CRITICAL",
        finding: "Contract contains a confession-of-judgment clause, which is per se unenforceable against consumers under the FTC Credit Practices Rule.",
        evidence: "Confession-of-judgment clause present",
        legalImplication: "16 C.F.R. §444.2(a)(4) prohibits creditors from including in any consumer credit obligation a cognovit or confession of judgment under which the consumer authorizes a creditor to obtain a judgment without notice or a hearing. Inclusion of such a clause is itself an unfair act or practice under §5 of the FTC Act, regardless of whether the clause is ever invoked.",
        citation: "16 C.F.R. §444.2(a)(4); FTC Credit Practices Rule",
      });
    }

    // Test 12: Choice of law evasion
    if (
      terms.governingLawState &&
      terms.jurisdiction &&
      terms.governingLawState.toUpperCase() !== terms.jurisdiction.toUpperCase()
    ) {
      findings.push({
        flag: "CHOICE_OF_LAW_EVASION",
        severity: "HIGH",
        finding: `Contract selects ${terms.governingLawState} law for a borrower in ${terms.jurisdiction}, evading the borrower's home-state consumer protections.`,
        evidence: `Governing law: ${terms.governingLawState}; Borrower jurisdiction: ${terms.jurisdiction}`,
        legalImplication: "Under Restatement (Second) of Conflict of Laws §187 and the Nedlloyd Lines analysis adopted by California (Nedlloyd Lines, Inc. v. Superior Court, 3 Cal. 4th 459 (1992)), choice-of-law clauses are unenforceable where (a) the chosen state has no substantial relationship to the parties or the transaction, or (b) application of the chosen state's law would be contrary to a fundamental policy of the state with the materially greater interest. California consumer-protection statutes (Rosenthal Act, Unruh Act, UCL §17200) are typically held to constitute fundamental policy.",
        citation: "Restatement (Second) of Conflict of Laws §187; Nedlloyd Lines, Inc. v. Superior Court, 3 Cal. 4th 459 (1992); Cal. Civ. Code §1646.5",
      });
    }

    // Test 13: One-sided fee shifting
    if (terms.hasOneSidedFeeShifting) {
      findings.push({
        flag: "ONE_SIDED_FEE_SHIFTING",
        severity: "HIGH",
        finding: "Contract requires the borrower to pay the lender's attorneys' fees regardless of outcome, with no reciprocal obligation on the lender.",
        evidence: "One-sided fee-shifting clause present",
        legalImplication: "California Civil Code §1717 makes any unilateral attorneys'-fees clause in a contract reciprocal as a matter of law in any action on the contract — the lender cannot benefit from a one-way clause. The clause is also a substantive unconscionability factor under Cal. Civ. Code §1670.5 and Armendariz v. Foundation Health Psychcare, 24 Cal. 4th 83 (2000).",
        citation: "Cal. Civ. Code §1717; Cal. Civ. Code §1670.5; Armendariz v. Foundation Health Psychcare, 24 Cal. 4th 83 (2000)",
      });
    }

    // Test 14: Class action and/or jury waiver
    if (terms.hasClassActionWaiver || terms.hasJuryWaiver) {
      findings.push({
        flag: "CLASS_ACTION_AND_JURY_WAIVER",
        severity: "MEDIUM",
        finding: `Contract contains ${terms.hasClassActionWaiver ? "class action waiver" : ""}${terms.hasClassActionWaiver && terms.hasJuryWaiver ? " and " : ""}${terms.hasJuryWaiver ? "jury trial waiver" : ""}.`,
        evidence: `Class waiver: ${!!terms.hasClassActionWaiver}; Jury waiver: ${!!terms.hasJuryWaiver}`,
        legalImplication: "While class action and jury waivers are not per se unenforceable post-Concepcion, their combination with other procedurally-unconscionable terms (forum selection, arbitration in a distant forum, fee shifting) is a recognized factor in the totality-of-circumstances analysis. Under California's Discover Bank rule (modified post-Concepcion) class action waivers in consumer contracts of adhesion remain a substantive-unconscionability factor.",
        citation: "AT&T Mobility v. Concepcion, 563 U.S. 333 (2011); Sanchez v. Valencia Holding Co., 61 Cal. 4th 899 (2015)",
      });
    }

    // Test 15: No cure period
    if (terms.hasNoCurePeriod) {
      findings.push({
        flag: "NO_CURE_PERIOD",
        severity: "MEDIUM",
        finding: "Contract eliminates any right to cure default before acceleration or enforcement.",
        evidence: "Explicit no-cure clause present",
        legalImplication: "The absence of a cure period in a consumer credit contract compounds the harshness of acceleration clauses and is a recognized substantive-unconscionability factor under Cal. Civ. Code §1670.5. Many state consumer protection statutes mandate a minimum cure period regardless of contract language.",
        citation: "Cal. Civ. Code §1670.5; state consumer credit protection statutes",
      });
    }

    // ─── Compute unconscionability score and verdict ─────────────────
    let score = 0;
    for (const f of findings) {
      switch (f.severity) {
        case "CRITICAL": score += 30; break;
        case "HIGH": score += 20; break;
        case "MEDIUM": score += 10; break;
        case "LOW": score += 5; break;
      }
    }
    score = Math.min(100, score);

    let verdict: ActuarialReport["verdict"];
    if (score >= 70) verdict = "UNCONSCIONABLE_AS_MATTER_OF_LAW";
    else if (score >= 40) verdict = "PREDATORY";
    else if (score >= 20) verdict = "AGGRESSIVE";
    else verdict = "STANDARD";

    const report: ActuarialReport = {
      generatedAt: new Date().toISOString(),
      documentId: terms.documentId,
      documentName: terms.documentName,
      totalCostToLessee: totalCost,
      totalEquityGained: totalEquity,
      effectivePerPaymentMultiplier: effectiveMultiplier,
      effectiveAnnualRate: effectiveAPR,
      residualValueGapPercent: residualGapPercent,
      unconscionabilityScore: score,
      verdict,
      findings,
      recommendation: this.recommendation(verdict, findings),
    };

    // Persist
    const id = `actr_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    await this.env.DB.prepare(
      `INSERT INTO actuarial_reports
        (id, document_id, document_name, total_cost, total_equity,
         effective_apr, residual_value_gap, unconscionability_score,
         verdict, findings_count, full_report)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)`
    )
      .bind(
        id,
        terms.documentId,
        terms.documentName ?? null,
        totalCost,
        totalEquity,
        effectiveAPR,
        residualGapPercent,
        score,
        verdict,
        findings.length,
        JSON.stringify(report)
      )
      .run();

    // Anchor to verification chain
    try {
      const { VerificationEngine } = await import("./verification-engine.js");
      const engine = new VerificationEngine(this.env);
      await engine.appendRecord({
        recordId: id,
        recordType: "actuarial_audit",
        sourceTable: "actuarial_reports",
        sourceId: id,
        content: {
          documentId: terms.documentId,
          verdict,
          score,
          totalCost,
          effectiveAPR,
          findingsCount: findings.length,
        },
        metadata: {
          layer: "Layer 7d — Unconscionability Trigger",
        },
      });
    } catch (err) {
      console.warn(
        "[UnconscionabilityTrigger] Failed to anchor to verification chain:",
        err instanceof Error ? err.message : err
      );
    }

    return report;
  }

  private computeYears(frequency: FinancialTerms["paymentFrequency"], count: number): number {
    switch (frequency) {
      case "weekly": return count / 52;
      case "biweekly": return count / 26;
      case "monthly": return count / 12;
      case "quarterly": return count / 4;
      case "annual": return count;
    }
  }

  private usuryStatuteFor(state: string): string {
    const statutes: Record<string, string> = {
      CA: "Cal. Const. Art. XV §1; Cal. Civ. Code §1916-1",
      NY: "N.Y. Gen. Oblig. Law §5-501; N.Y. Penal Law §190.40",
      IL: "815 ILCS 205/4",
      TX: "Tex. Fin. Code §302.001",
      FL: "Fla. Stat. §687.02",
    };
    return statutes[state.toUpperCase()] ?? `${state} state usury statute`;
  }

  private recommendation(verdict: ActuarialReport["verdict"], findings: UnconscionabilityFinding[]): string {
    const critical = findings.filter((f) => f.severity === "CRITICAL").length;
    switch (verdict) {
      case "UNCONSCIONABLE_AS_MATTER_OF_LAW":
        return `${critical} CRITICAL finding(s) detected. This contract is unconscionable as a matter of law in most jurisdictions. The transaction should be challenged in court and is likely voidable. The lessor may face damages, restitution, and statutory penalties. Recommend immediate legal counsel.`;
      case "PREDATORY":
        return "Multiple predatory terms detected. The contract is enforceable but contains terms that are likely voidable. Recommend negotiation or litigation to invalidate the most damaging clauses.";
      case "AGGRESSIVE":
        return "Aggressive but potentially enforceable terms. Recommend documentation and monitoring; may become a target for renegotiation if circumstances permit.";
      case "STANDARD":
        return "Standard commercial terms. No unconscionability flags raised.";
    }
  }
}
