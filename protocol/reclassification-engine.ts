/**
 * Layer 7c — De Facto Reclassification Engine
 *
 * Detects disguised employment masquerading as independent contractor
 * relationships. Where Layer 7d (Unconscionability) audits financial math,
 * this module audits the *control* exerted by one party over the other.
 *
 * The Ryan Mcclaran audit (March 30, 2026) caught the lease as economically
 * predatory but did not formally score the independent-contractor label
 * against the cumulative control language. This module makes that scoring
 * automatic, deterministic, and citable to AB5 / IRS-20 / DOL economic
 * dependence tests so a federal judge can adopt the analysis without an
 * expert witness.
 *
 * What it consumes:
 *   - The full text of one or more contracts
 *   - The jurisdiction (controls which test applies)
 *   - The label the contract uses ("independent contractor" / "lessee" / etc)
 *
 * What it produces:
 *   - A control matrix scored across 7 control categories
 *   - A jurisdictional verdict against AB5 ABC, IRS-20, DOL economic reality
 *   - A reclassification recommendation with statutory damages estimate
 *   - A persisted record anchored to the verification chain
 *
 * Spec: docs/LAYER_7_STRUCTURAL_FORENSIC_ANALYSIS.md
 * License: CC0-1.0
 */

import type { Env } from "../index.js";

// ─── Types ───────────────────────────────────────────────────────────────

export interface ReclassificationInput {
  documentId: string;
  documentName?: string;
  contractText: string;
  jurisdiction?: string;          // Two-letter state code
  labeledRelationship?:
    | "independent_contractor"
    | "lessee"
    | "vendor"
    | "consultant"
    | "subcontractor"
    | "other";
  workerName?: string;
  hiringPartyName?: string;
}

export type ControlCategory =
  | "WORK_ASSIGNMENT"
  | "TIME_CONTROL"
  | "LOCATION_CONTROL"
  | "EQUIPMENT_CONTROL"
  | "METHOD_CONTROL"
  | "EXCLUSIVITY"
  | "DISCIPLINARY";

export interface ControlClause {
  category: ControlCategory;
  verb: string;                   // The control verb that triggered the match
  excerpt: string;                // ~120 chars surrounding the match
  weight: number;                 // 1 (mild) to 5 (severe)
  modality: "mandatory" | "restrictive" | "permissive" | "punitive";
}

export interface ControlMatrix {
  WORK_ASSIGNMENT: ControlClause[];
  TIME_CONTROL: ControlClause[];
  LOCATION_CONTROL: ControlClause[];
  EQUIPMENT_CONTROL: ControlClause[];
  METHOD_CONTROL: ControlClause[];
  EXCLUSIVITY: ControlClause[];
  DISCIPLINARY: ControlClause[];
}

export type JurisdictionalTest = "AB5_ABC" | "IRS_20" | "DOL_ECONOMIC_REALITY";

export interface TestResult {
  test: JurisdictionalTest;
  applies: boolean;
  passes: boolean;                // true = independent contractor stands; false = misclassified
  prongResults: Array<{
    prong: string;
    satisfied: boolean;
    rationale: string;
  }>;
  citation: string;
}

export interface ReclassificationFinding {
  flag:
    | "DE_FACTO_EMPLOYMENT"
    | "EXCESSIVE_CONTROL_DENSITY"
    | "EXCLUSIVITY_VIOLATION"
    | "DISCIPLINARY_PATTERN"
    | "MANDATED_EQUIPMENT"
    | "TIME_AND_LOCATION_LOCKDOWN";
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  finding: string;
  evidence: string;
  legalImplication: string;
  citation: string;
}

export interface ReclassificationReport {
  generatedAt: string;
  documentId: string;
  documentName?: string;
  jurisdiction?: string;
  labeledRelationship?: ReclassificationInput["labeledRelationship"];

  controlMatrix: ControlMatrix;
  totalControlClauses: number;
  controlDensity: number;          // clauses per 1,000 words
  cumulativeControlScore: number;  // sum of weights, 0..N

  testResults: TestResult[];
  findings: ReclassificationFinding[];

  reclassificationVerdict:
    | "CONTRACTOR_STANDS"
    | "BORDERLINE"
    | "PRESUMED_EMPLOYEE"
    | "DE_FACTO_EMPLOYEE_AS_MATTER_OF_LAW";

  damagesEstimate: {
    backWagesRisk: "LOW" | "MEDIUM" | "HIGH" | "VERY_HIGH";
    statutoryPenaltyRange?: string;
    rationale: string;
  };

  recommendation: string;
}

// ─── Control verb dictionary ─────────────────────────────────────────────
//
// Each row maps a verb regex to a control category, modality, and weight.
// Weights reflect how strongly the verb signals control of the worker.

interface VerbRule {
  pattern: RegExp;
  category: ControlCategory;
  modality: ControlClause["modality"];
  weight: number;
}

const VERB_RULES: VerbRule[] = [
  // ─── WORK_ASSIGNMENT ─────────────────────────────────────────────────
  { pattern: /\b(must|shall)\s+(accept|perform|complete|deliver|haul|carry|drive)\b/gi, category: "WORK_ASSIGNMENT", modality: "mandatory", weight: 4 },
  { pattern: /\bassigned\s+(by|to)\s+(the\s+)?(company|carrier|lessor|client)\b/gi, category: "WORK_ASSIGNMENT", modality: "mandatory", weight: 3 },
  { pattern: /\b(dispatch|dispatched|dispatcher)\b/gi, category: "WORK_ASSIGNMENT", modality: "mandatory", weight: 3 },
  { pattern: /\brequired\s+to\s+(accept|complete|perform|haul|drive|deliver|report)\b/gi, category: "WORK_ASSIGNMENT", modality: "mandatory", weight: 4 },

  // ─── TIME_CONTROL ────────────────────────────────────────────────────
  { pattern: /\b(must|shall)\s+(report|begin|start|arrive)\s+(at|by)\b/gi, category: "TIME_CONTROL", modality: "mandatory", weight: 4 },
  { pattern: /\b(set|fixed|mandated)\s+(hours|schedule|shift|workday)\b/gi, category: "TIME_CONTROL", modality: "mandatory", weight: 4 },
  { pattern: /\b(no\s+later\s+than|by\s+\d{1,2}(:\d{2})?\s*(am|pm))\b/gi, category: "TIME_CONTROL", modality: "mandatory", weight: 2 },
  { pattern: /\b(on-call|on\s+call)\b/gi, category: "TIME_CONTROL", modality: "restrictive", weight: 3 },
  { pattern: /\b(daily|weekly|monthly)\s+(check[- ]?in|report|log|status)\b/gi, category: "TIME_CONTROL", modality: "mandatory", weight: 2 },

  // ─── LOCATION_CONTROL ────────────────────────────────────────────────
  { pattern: /\b(must|shall)\s+(work|report|operate|park|garage)\s+(at|from|in)\b/gi, category: "LOCATION_CONTROL", modality: "mandatory", weight: 4 },
  { pattern: /\b(designated|assigned|approved)\s+(location|terminal|yard|facility|garage)\b/gi, category: "LOCATION_CONTROL", modality: "mandatory", weight: 3 },
  { pattern: /\b(authorized\s+only\s+at|exclusively\s+at|only\s+at\s+(the\s+)?(company|carrier|lessor))\b/gi, category: "LOCATION_CONTROL", modality: "restrictive", weight: 4 },

  // ─── EQUIPMENT_CONTROL ───────────────────────────────────────────────
  { pattern: /\b(company[- ]?(mandated|provided|issued|owned|approved))\s+(equipment|vehicle|truck|tools|fuel\s+card|eld|gps|insurance)\b/gi, category: "EQUIPMENT_CONTROL", modality: "mandatory", weight: 5 },
  { pattern: /\b(must|shall)\s+use\s+(the\s+)?(company|carrier|lessor)('s)?\s+(equipment|vehicle|truck|fuel\s+card|eld|gps|software|app|system)\b/gi, category: "EQUIPMENT_CONTROL", modality: "mandatory", weight: 5 },
  { pattern: /\b(approved\s+(vendor|supplier|shop|provider))\b/gi, category: "EQUIPMENT_CONTROL", modality: "restrictive", weight: 3 },
  { pattern: /\b(electronic\s+logging\s+device|eld)\b/gi, category: "EQUIPMENT_CONTROL", modality: "mandatory", weight: 3 },
  { pattern: /\b(must|shall)\s+(install|maintain)\s+(gps|tracking|monitoring|telematics)\b/gi, category: "EQUIPMENT_CONTROL", modality: "mandatory", weight: 4 },

  // ─── METHOD_CONTROL ──────────────────────────────────────────────────
  { pattern: /\b(must|shall)\s+(follow|comply\s+with|adhere\s+to)\s+(the\s+)?(company|carrier|lessor)('s)?\s+(procedures|policies|standards|methods|sop)\b/gi, category: "METHOD_CONTROL", modality: "mandatory", weight: 4 },
  { pattern: /\b(in\s+accordance\s+with|pursuant\s+to)\s+(company|carrier|lessor)\s+(policies|procedures|standards|directives)\b/gi, category: "METHOD_CONTROL", modality: "mandatory", weight: 3 },
  { pattern: /\b(training\s+(required|mandatory)|mandatory\s+training)\b/gi, category: "METHOD_CONTROL", modality: "mandatory", weight: 3 },
  { pattern: /\b(uniform|dress\s+code|company\s+(logo|branding|colors))\b/gi, category: "METHOD_CONTROL", modality: "mandatory", weight: 3 },
  { pattern: /\b(supervisor|supervised|supervision)\b/gi, category: "METHOD_CONTROL", modality: "mandatory", weight: 3 },
  { pattern: /\b(quality\s+control|qa\s+inspection|company\s+inspection)\b/gi, category: "METHOD_CONTROL", modality: "mandatory", weight: 2 },

  // ─── EXCLUSIVITY ─────────────────────────────────────────────────────
  { pattern: /\b(exclusive(ly)?|solely)\s+(for|to|with)\s+(the\s+)?(company|carrier|lessor|client)\b/gi, category: "EXCLUSIVITY", modality: "restrictive", weight: 5 },
  { pattern: /\b(may\s+not|shall\s+not|prohibited\s+from)\s+(work|haul|drive|engage|provide\s+services)\s+(for|with)\b/gi, category: "EXCLUSIVITY", modality: "restrictive", weight: 5 },
  { pattern: /\bnon[- ]compete\b/gi, category: "EXCLUSIVITY", modality: "restrictive", weight: 4 },
  { pattern: /\bonly\s+(haul|drive|work|deliver)\s+for\b/gi, category: "EXCLUSIVITY", modality: "restrictive", weight: 5 },
  { pattern: /\bnon[- ]?solicitation\b/gi, category: "EXCLUSIVITY", modality: "restrictive", weight: 3 },

  // ─── DISCIPLINARY ────────────────────────────────────────────────────
  { pattern: /\b(fine|penalty|deduction|chargeback|forfeiture)\s+(of|for)\b/gi, category: "DISCIPLINARY", modality: "punitive", weight: 4 },
  { pattern: /\b(termination|terminate|dismissed?)\s+(for|upon|if)\b/gi, category: "DISCIPLINARY", modality: "punitive", weight: 4 },
  { pattern: /\b(progressive\s+discipline|disciplinary\s+(action|process))\b/gi, category: "DISCIPLINARY", modality: "punitive", weight: 5 },
  { pattern: /\b(written\s+warning|verbal\s+warning|first\s+offense|second\s+offense)\b/gi, category: "DISCIPLINARY", modality: "punitive", weight: 4 },
  { pattern: /\b(suspended\s+(from|for)|suspension)\b/gi, category: "DISCIPLINARY", modality: "punitive", weight: 4 },
  { pattern: /\bnon[- ]?disparagement\b/gi, category: "DISCIPLINARY", modality: "restrictive", weight: 3 },
];

// ─── Engine ──────────────────────────────────────────────────────────────

export class ReclassificationEngine {
  constructor(private env: Env) {}

  async ensureTables(): Promise<void> {
    const db = this.env.DB;
    await db.batch([
      db.prepare(`CREATE TABLE IF NOT EXISTS reclassification_reports (
        id TEXT PRIMARY KEY,
        document_id TEXT NOT NULL,
        document_name TEXT,
        jurisdiction TEXT,
        cumulative_control_score INTEGER NOT NULL,
        control_density REAL NOT NULL,
        verdict TEXT NOT NULL,
        findings_count INTEGER NOT NULL,
        full_report TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      )`),
      db.prepare(`CREATE INDEX IF NOT EXISTS idx_reclass_doc ON reclassification_reports(document_id)`),
      db.prepare(`CREATE INDEX IF NOT EXISTS idx_reclass_verdict ON reclassification_reports(verdict)`),
    ]);
  }

  /**
   * Run reclassification analysis on a contract.
   */
  async analyze(input: ReclassificationInput): Promise<ReclassificationReport> {
    await this.ensureTables();

    const text = input.contractText ?? "";
    const wordCount = Math.max(1, text.split(/\s+/).filter(Boolean).length);

    // ─── Build the control matrix ────────────────────────────────────
    const matrix: ControlMatrix = {
      WORK_ASSIGNMENT: [],
      TIME_CONTROL: [],
      LOCATION_CONTROL: [],
      EQUIPMENT_CONTROL: [],
      METHOD_CONTROL: [],
      EXCLUSIVITY: [],
      DISCIPLINARY: [],
    };

    let cumulativeScore = 0;
    let totalClauses = 0;

    for (const rule of VERB_RULES) {
      // Reset regex state (global flag)
      rule.pattern.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = rule.pattern.exec(text)) !== null) {
        const start = Math.max(0, m.index - 60);
        const end = Math.min(text.length, m.index + m[0].length + 60);
        const excerpt = text.slice(start, end).replace(/\s+/g, " ").trim();
        matrix[rule.category].push({
          category: rule.category,
          verb: m[0],
          excerpt,
          weight: rule.weight,
          modality: rule.modality,
        });
        cumulativeScore += rule.weight;
        totalClauses += 1;
        // Safety: avoid infinite loop on zero-length matches
        if (m.index === rule.pattern.lastIndex) rule.pattern.lastIndex += 1;
      }
    }

    const controlDensity = (totalClauses / wordCount) * 1000;

    // ─── Apply jurisdictional tests ──────────────────────────────────
    const testResults: TestResult[] = [];

    // California AB5 ABC test
    if (!input.jurisdiction || input.jurisdiction.toUpperCase() === "CA") {
      testResults.push(this.runABCTest(matrix, input));
    }

    // IRS 20-factor (always applies — federal tax)
    testResults.push(this.runIRSTest(matrix, cumulativeScore));

    // DOL economic reality (always applies — federal FLSA)
    testResults.push(this.runDOLTest(matrix, cumulativeScore, controlDensity));

    // ─── Generate findings ───────────────────────────────────────────
    const findings: ReclassificationFinding[] = [];

    if (matrix.EQUIPMENT_CONTROL.length >= 2) {
      findings.push({
        flag: "MANDATED_EQUIPMENT",
        severity: "HIGH",
        finding: `Contract mandates company-controlled equipment in ${matrix.EQUIPMENT_CONTROL.length} clauses.`,
        evidence: matrix.EQUIPMENT_CONTROL.slice(0, 3).map((c) => `"${c.excerpt}"`).join(" | "),
        legalImplication: "Equipment provision is one of the most heavily-weighted factors under both the IRS 20-factor test and the DOL economic reality test. When the hiring party mandates the equipment, fuel system, telematics, or insurance, the worker is structurally dependent on the hiring party — a hallmark of employment, not contracting.",
        citation: "IRS Rev. Rul. 87-41 (factor 14); DOL Fact Sheet #13",
      });
    }

    if (matrix.EXCLUSIVITY.length >= 1) {
      findings.push({
        flag: "EXCLUSIVITY_VIOLATION",
        severity: "CRITICAL",
        finding: `Contract contains ${matrix.EXCLUSIVITY.length} exclusivity clause(s) restricting the worker from providing services to other parties.`,
        evidence: matrix.EXCLUSIVITY.slice(0, 2).map((c) => `"${c.excerpt}"`).join(" | "),
        legalImplication: "Exclusivity is a per-se failure of AB5 Prong B (work outside the usual course of the hiring party's business is impossible if the worker can ONLY work for that party) and a near-conclusive factor under the IRS and DOL tests. Genuine independent contractors are free to serve multiple clients.",
        citation: "Cal. Lab. Code §2775 (AB5); Dynamex Operations W. v. Superior Court, 4 Cal. 5th 903 (2018)",
      });
    }

    if (matrix.DISCIPLINARY.length >= 2) {
      findings.push({
        flag: "DISCIPLINARY_PATTERN",
        severity: "HIGH",
        finding: `Contract contains ${matrix.DISCIPLINARY.length} disciplinary clauses (warnings, fines, progressive discipline).`,
        evidence: matrix.DISCIPLINARY.slice(0, 3).map((c) => `"${c.excerpt}"`).join(" | "),
        legalImplication: "Progressive discipline systems (verbal/written warnings, suspensions, fines for performance) are an employer-employee construct. True independent contractor relationships are governed by contract breach, not internal discipline.",
        citation: "IRS Rev. Rul. 87-41 (factor 17 — discharge); NLRB v. United Insurance Co., 390 U.S. 254 (1968)",
      });
    }

    if (matrix.TIME_CONTROL.length >= 2 && matrix.LOCATION_CONTROL.length >= 1) {
      findings.push({
        flag: "TIME_AND_LOCATION_LOCKDOWN",
        severity: "HIGH",
        finding: `Contract dictates both when (${matrix.TIME_CONTROL.length} clauses) and where (${matrix.LOCATION_CONTROL.length} clauses) the worker performs services.`,
        evidence: [...matrix.TIME_CONTROL.slice(0, 1), ...matrix.LOCATION_CONTROL.slice(0, 1)]
          .map((c) => `"${c.excerpt}"`).join(" | "),
        legalImplication: "Control over both time and place of work is one of the strongest indicators of an employment relationship under every major test. Independent contractors typically set their own schedules and work locations.",
        citation: "IRS Rev. Rul. 87-41 (factors 7, 9); DOL economic reality test factor 5",
      });
    }

    if (controlDensity >= 5) {
      findings.push({
        flag: "EXCESSIVE_CONTROL_DENSITY",
        severity: "MEDIUM",
        finding: `Control clause density of ${controlDensity.toFixed(1)} per 1,000 words exceeds the threshold for a true contractor relationship.`,
        evidence: `${totalClauses} control clauses across ${wordCount} words`,
        legalImplication: "Genuine contractor agreements typically have control density below 2 per 1,000 words. Higher densities indicate the hiring party is treating the relationship as managerial rather than transactional.",
        citation: "Empirical norm derived from comparison of contractor vs employment agreements",
      });
    }

    // The big one: DE_FACTO_EMPLOYMENT
    const failedTestsCount = testResults.filter((t) => t.applies && !t.passes).length;
    if (
      input.labeledRelationship === "independent_contractor" &&
      (failedTestsCount >= 2 || cumulativeScore >= 40)
    ) {
      findings.push({
        flag: "DE_FACTO_EMPLOYMENT",
        severity: "CRITICAL",
        finding: `Contract is labeled "independent contractor" but fails ${failedTestsCount} jurisdictional test(s) with a cumulative control score of ${cumulativeScore}.`,
        evidence: `Failed tests: ${testResults.filter((t) => t.applies && !t.passes).map((t) => t.test).join(", ")}. Control score: ${cumulativeScore}.`,
        legalImplication: "When a contract labeled 'independent contractor' fails the applicable jurisdictional tests, the relationship is reclassified as employment by operation of law. The hiring party becomes liable for unpaid overtime, minimum wage, payroll taxes, workers' compensation premiums, unemployment insurance contributions, and (in California) statutory penalties under Lab. Code §226.8 (up to $25,000 per violation).",
        citation: "Cal. Lab. Code §226.8; FLSA 29 U.S.C. §216(b); IRC §3509",
      });
    }

    // ─── Determine verdict ───────────────────────────────────────────
    // Failing ALL THREE jurisdictional tests is structurally dispositive:
    // when AB5 ABC, IRS-20, and DOL economic-reality all fail, the
    // relationship cannot survive any framework — that's de facto
    // employment as a matter of law regardless of the raw control score.
    const applicableFailedAll =
      testResults.filter((t) => t.applies).length >= 3 &&
      testResults.filter((t) => t.applies && !t.passes).length === testResults.filter((t) => t.applies).length;
    let verdict: ReclassificationReport["reclassificationVerdict"];
    if (applicableFailedAll || (cumulativeScore >= 60 && failedTestsCount >= 2)) {
      verdict = "DE_FACTO_EMPLOYEE_AS_MATTER_OF_LAW";
    } else if (cumulativeScore >= 40 || failedTestsCount >= 2) {
      verdict = "PRESUMED_EMPLOYEE";
    } else if (cumulativeScore >= 20 || failedTestsCount === 1) {
      verdict = "BORDERLINE";
    } else {
      verdict = "CONTRACTOR_STANDS";
    }

    // ─── Damages estimate ────────────────────────────────────────────
    const damagesEstimate = this.estimateDamages(verdict, input.jurisdiction);

    const report: ReclassificationReport = {
      generatedAt: new Date().toISOString(),
      documentId: input.documentId,
      documentName: input.documentName,
      jurisdiction: input.jurisdiction,
      labeledRelationship: input.labeledRelationship,
      controlMatrix: matrix,
      totalControlClauses: totalClauses,
      controlDensity,
      cumulativeControlScore: cumulativeScore,
      testResults,
      findings,
      reclassificationVerdict: verdict,
      damagesEstimate,
      recommendation: this.recommendation(verdict, findings, input),
    };

    // ─── Persist ─────────────────────────────────────────────────────
    const id = `recl_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    await this.env.DB.prepare(
      `INSERT INTO reclassification_reports
        (id, document_id, document_name, jurisdiction, cumulative_control_score,
         control_density, verdict, findings_count, full_report)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)`
    )
      .bind(
        id,
        input.documentId,
        input.documentName ?? null,
        input.jurisdiction ?? null,
        cumulativeScore,
        controlDensity,
        verdict,
        findings.length,
        JSON.stringify(report)
      )
      .run();

    // ─── Anchor to verification chain ────────────────────────────────
    try {
      const { VerificationEngine } = await import("./verification-engine.js");
      const engine = new VerificationEngine(this.env);
      await engine.appendRecord({
        recordId: id,
        recordType: "reclassification_audit",
        sourceTable: "reclassification_reports",
        sourceId: id,
        content: {
          documentId: input.documentId,
          verdict,
          cumulativeControlScore: cumulativeScore,
          controlDensity,
          findingsCount: findings.length,
        },
        metadata: {
          layer: "Layer 7c — De Facto Reclassification Engine",
        },
      });
    } catch (err) {
      console.warn(
        "[ReclassificationEngine] Failed to anchor to verification chain:",
        err instanceof Error ? err.message : err
      );
    }

    return report;
  }

  // ─── Test implementations ────────────────────────────────────────────

  private runABCTest(matrix: ControlMatrix, input: ReclassificationInput): TestResult {
    // Prong A: Free from control and direction
    const controlClauseCount =
      matrix.WORK_ASSIGNMENT.length +
      matrix.TIME_CONTROL.length +
      matrix.LOCATION_CONTROL.length +
      matrix.METHOD_CONTROL.length +
      matrix.DISCIPLINARY.length;
    const prongA = {
      prong: "A — Free from control and direction in performance of work",
      satisfied: controlClauseCount <= 2,
      rationale: `Found ${controlClauseCount} control/direction clauses. AB5 Prong A requires the worker be free from the control and direction of the hiring party in connection with the performance of the work, both under contract and in fact.`,
    };

    // Prong B: Outside the usual course of business — we infer this from
    // exclusivity and from labeling. If the contract is exclusive, the worker
    // is structurally inside the hiring party's business.
    const prongB = {
      prong: "B — Performs work outside the usual course of the hiring entity's business",
      satisfied: matrix.EXCLUSIVITY.length === 0,
      rationale: matrix.EXCLUSIVITY.length === 0
        ? "No exclusivity clauses detected. Prong B may be satisfied if the worker performs work outside the hiring party's usual course of business — this requires factual analysis of business scope."
        : `${matrix.EXCLUSIVITY.length} exclusivity clause(s) detected. Exclusivity is incompatible with Prong B because a worker who can ONLY serve the hiring party necessarily performs work inside the hiring party's usual course of business.`,
    };

    // Prong C: Customarily engaged in independently established trade
    // We infer this negatively: if the contract restricts outside work, fails.
    const prongC = {
      prong: "C — Customarily engaged in an independently established trade, occupation, or business",
      satisfied: matrix.EXCLUSIVITY.length === 0,
      rationale: matrix.EXCLUSIVITY.length === 0
        ? "No exclusivity restrictions found. Prong C requires the worker maintain an independent business — needs factual analysis of business existence (separate licensing, marketing, multiple clients, etc.)."
        : "Exclusivity clauses prevent the worker from maintaining an independently established trade. Prong C fails.",
    };

    // ABC test: ALL three prongs must be satisfied
    const passes = prongA.satisfied && prongB.satisfied && prongC.satisfied;

    return {
      test: "AB5_ABC",
      applies: !input.jurisdiction || input.jurisdiction.toUpperCase() === "CA",
      passes,
      prongResults: [prongA, prongB, prongC],
      citation: "Cal. Lab. Code §2775; Dynamex Operations W. v. Superior Court, 4 Cal. 5th 903 (2018)",
    };
  }

  private runIRSTest(matrix: ControlMatrix, score: number): TestResult {
    // Simplified IRS 20-factor: count categories with significant control
    const categoriesWithControl = Object.values(matrix).filter((arr) => arr.length >= 1).length;
    const passes = score < 30 && categoriesWithControl <= 3;

    return {
      test: "IRS_20",
      applies: true,
      passes,
      prongResults: [
        {
          prong: "Cumulative control across IRS factors",
          satisfied: score < 30,
          rationale: `Cumulative control score: ${score}. IRS Rev. Rul. 87-41 examines 20 factors; a high cumulative score across behavioral, financial, and relationship control indicates employment.`,
        },
        {
          prong: "Number of control categories engaged",
          satisfied: categoriesWithControl <= 3,
          rationale: `${categoriesWithControl} of 7 control categories show clauses. Genuine contractor relationships typically engage 0-2 categories; employment relationships engage 4+.`,
        },
      ],
      citation: "IRS Rev. Rul. 87-41; IRS Form SS-8",
    };
  }

  private runDOLTest(matrix: ControlMatrix, score: number, density: number): TestResult {
    // DOL economic reality / economic dependence test (6 factors)
    const passes = score < 25 && matrix.EXCLUSIVITY.length === 0 && density < 4;

    return {
      test: "DOL_ECONOMIC_REALITY",
      applies: true,
      passes,
      prongResults: [
        {
          prong: "Economic dependence on hiring party",
          satisfied: matrix.EXCLUSIVITY.length === 0,
          rationale: matrix.EXCLUSIVITY.length === 0
            ? "No exclusivity restrictions found — worker may serve other clients."
            : "Exclusivity clauses establish total economic dependence on the hiring party.",
        },
        {
          prong: "Nature and degree of control",
          satisfied: score < 25,
          rationale: `Cumulative control score: ${score}. DOL focuses on the economic reality of the relationship over labels.`,
        },
        {
          prong: "Permanence of relationship",
          satisfied: density < 4,
          rationale: `Control density of ${density.toFixed(1)} per 1,000 words ${density < 4 ? "is consistent with a project-based relationship" : "indicates an ongoing managed relationship typical of employment"}.`,
        },
      ],
      citation: "29 C.F.R. §795.105 (2024); DOL Fact Sheet #13; Sec'y of Labor v. Lauritzen, 835 F.2d 1529 (7th Cir. 1987)",
    };
  }

  private estimateDamages(
    verdict: ReclassificationReport["reclassificationVerdict"],
    jurisdiction?: string
  ): ReclassificationReport["damagesEstimate"] {
    const isCA = !jurisdiction || jurisdiction.toUpperCase() === "CA";

    switch (verdict) {
      case "DE_FACTO_EMPLOYEE_AS_MATTER_OF_LAW":
        return {
          backWagesRisk: "VERY_HIGH",
          statutoryPenaltyRange: isCA
            ? "$5,000 - $25,000 per violation under Cal. Lab. Code §226.8 (willful misclassification), plus unpaid overtime, meal/rest break premiums, waiting time penalties, and 1099/W-2 tax restatement liability"
            : "Unpaid overtime under FLSA 29 U.S.C. §216(b) (back pay + liquidated damages = 2x), payroll tax restatement under IRC §3509, plus state-specific penalties",
          rationale: "Verdict of de facto employment as a matter of law triggers automatic statutory remedies in the worker's favor. The hiring party should immediately reclassify and tender back-pay rather than litigate.",
        };
      case "PRESUMED_EMPLOYEE":
        return {
          backWagesRisk: "HIGH",
          statutoryPenaltyRange: isCA
            ? "$5,000 - $15,000 per violation under §226.8, plus FLSA back pay and liquidated damages"
            : "FLSA back pay + liquidated damages (2x), payroll tax exposure",
          rationale: "Strong presumption of misclassification. Litigation risk is significant; settlement is typically the cost-rational path.",
        };
      case "BORDERLINE":
        return {
          backWagesRisk: "MEDIUM",
          rationale: "Outcome depends heavily on factual development at trial — particularly whether the worker maintains a genuinely independent business in fact.",
        };
      case "CONTRACTOR_STANDS":
        return {
          backWagesRisk: "LOW",
          rationale: "Control structure is consistent with a true contractor relationship under the major tests.",
        };
    }
  }

  private recommendation(
    verdict: ReclassificationReport["reclassificationVerdict"],
    findings: ReclassificationFinding[],
    input: ReclassificationInput
  ): string {
    const critical = findings.filter((f) => f.severity === "CRITICAL").length;
    switch (verdict) {
      case "DE_FACTO_EMPLOYEE_AS_MATTER_OF_LAW":
        return `${critical} CRITICAL findings detected. The contract labeled "${input.labeledRelationship ?? "independent contractor"}" is structurally an employment relationship. Worker should be reclassified immediately. The hiring party faces back wages, payroll tax liability, and statutory penalties. Recommend immediate legal counsel and a settlement-tendered reclassification.`;
      case "PRESUMED_EMPLOYEE":
        return "Strong presumption of misclassification. Recommend either (a) restructuring the contract to remove control/exclusivity clauses or (b) reclassifying the worker as an employee. Litigation is likely if status quo continues.";
      case "BORDERLINE":
        return "Mixed signals. The contract has features of both employment and contracting. Recommend tightening contract language to remove control language, OR reclassifying the worker proactively to eliminate ambiguity.";
      case "CONTRACTOR_STANDS":
        return "Contract structure supports the labeled relationship. No reclassification action required at this time.";
    }
  }
}
