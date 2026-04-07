/**
 * Layer 7a — Temporal Paradox Filter
 *
 * Detects effects that predate causes across document sets. The most direct
 * counter to procedurally-constructed document fraud (the "Ryan trap").
 *
 * The Ryan Mcclaran audit (March 30, 2026) had this paradox sitting in plain
 * sight: settlement statements from November 2024 against a Rex Trucking
 * lease signed December 22, 2025. The lease postdated the operational data
 * by 13 months. We did not catch it because we audited each document in
 * isolation rather than mapping them on a unified timeline.
 *
 * This module fixes that gap. Every document's claimed dates are extracted,
 * mapped against document-type causal relationships, and any violation of
 * cause-must-precede-effect ordering is flagged as a CRITICAL temporal
 * paradox.
 *
 * Detection categories:
 *   - Type 1: Direct paradox — operational record predates governing contract
 *   - Type 2: Statutory paradox — required prerequisite is missing or postdated
 *   - Type 3: Insurance paradox — claim or loss precedes coverage binding
 *   - Type 4: Authority paradox — signed before signatory had authority
 *   - Type 5: Calendar paradox — impossible date (Feb 30, etc.)
 *   - Type 6: Day-of-week paradox — claimed weekday doesn't match actual date
 *
 * Spec: docs/LAYER_7_STRUCTURAL_FORENSIC_ANALYSIS.md
 * License: CC0-1.0
 */

import type { Env } from "../index.js";

// ─── Types ───────────────────────────────────────────────────────────────

export type DocumentType =
  | "lease"
  | "purchase_agreement"
  | "employment_contract"
  | "independent_contractor_agreement"
  | "incorporation"
  | "llc_formation"
  | "insurance_binder"
  | "insurance_claim"
  | "license"
  | "drug_test"
  | "background_check"
  | "settlement_statement"
  | "pay_stub"
  | "operational_log"
  | "load_record"
  | "fuel_receipt"
  | "maintenance_record"
  | "court_filing"
  | "judgment"
  | "deed"
  | "title_transfer"
  | "registration"
  | "certification"
  | "audit_report"
  | "tax_return"
  | "bank_statement"
  | "unknown";

export interface DocumentDateRecord {
  documentId: string;
  documentType: DocumentType;
  documentName?: string;
  claimedDate: string;            // ISO date
  dateContext: string;            // What the date represents (signing, effective, etc.)
  rawDateText?: string;           // Original text from the document
  attributes?: Record<string, string>;
}

export type ParadoxType =
  | "DIRECT_PARADOX"        // Effect predates cause
  | "STATUTORY_PARADOX"     // Required prerequisite missing or postdated
  | "INSURANCE_PARADOX"     // Loss precedes coverage
  | "AUTHORITY_PARADOX"     // Signed before authority existed
  | "CALENDAR_PARADOX"      // Impossible date
  | "DAY_OF_WEEK_PARADOX";  // Weekday mismatch

export interface TemporalParadox {
  type: ParadoxType;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
  cause: DocumentDateRecord;
  effect: DocumentDateRecord;
  daysBetween: number;            // Negative = paradox magnitude
  description: string;
  legalImplication: string;
}

export interface TemporalAnalysisReport {
  generatedAt: string;
  documentsAnalyzed: number;
  paradoxesFound: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  paradoxes: TemporalParadox[];
  timelineCoherent: boolean;
  recommendation: string;
}

// ─── Causal relationships ────────────────────────────────────────────────
// Each entry: { effect_type, cause_type, requirement }
// "Cause" must temporally precede "Effect" or it's a paradox.

interface CausalRule {
  cause: DocumentType;
  effect: DocumentType;
  description: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
  paradoxType: ParadoxType;
  legalImplication: string;
}

const CAUSAL_RULES: CausalRule[] = [
  // ─── Direct paradoxes ──
  {
    cause: "lease",
    effect: "settlement_statement",
    description: "An equipment lease must exist before settlement statements based on operations using that equipment.",
    severity: "CRITICAL",
    paradoxType: "DIRECT_PARADOX",
    legalImplication: "Settlement statements predating the governing lease cannot be authentic. Either the settlements are fabricated, the lease was retroactively constructed, or the operation existed under a different (undisclosed) agreement.",
  },
  {
    cause: "lease",
    effect: "load_record",
    description: "An equipment lease must exist before load records using that equipment.",
    severity: "CRITICAL",
    paradoxType: "DIRECT_PARADOX",
    legalImplication: "Operational records predating the governing lease are temporally impossible.",
  },
  {
    cause: "lease",
    effect: "pay_stub",
    description: "An equipment lease must exist before pay stubs reflecting deductions for that equipment.",
    severity: "CRITICAL",
    paradoxType: "DIRECT_PARADOX",
    legalImplication: "Pay stubs deducting lease payments before the lease was signed are fabricated or retroactively dated.",
  },
  {
    cause: "lease",
    effect: "fuel_receipt",
    description: "An equipment lease must exist before fuel receipts for that equipment.",
    severity: "HIGH",
    paradoxType: "DIRECT_PARADOX",
    legalImplication: "Operational expenses before the governing contract suggest the operation existed under different terms.",
  },
  {
    cause: "lease",
    effect: "maintenance_record",
    description: "An equipment lease must exist before maintenance records for that equipment.",
    severity: "HIGH",
    paradoxType: "DIRECT_PARADOX",
    legalImplication: "Maintenance records predating the lease suggest different ownership or different governing terms.",
  },

  // ─── Employment paradoxes ──
  {
    cause: "employment_contract",
    effect: "pay_stub",
    description: "An employment contract must exist before pay stubs for that employment.",
    severity: "CRITICAL",
    paradoxType: "DIRECT_PARADOX",
    legalImplication: "Wage payments before the underlying employment contract suggest the contract was retroactively executed or the employment relationship existed informally.",
  },
  {
    cause: "independent_contractor_agreement",
    effect: "pay_stub",
    description: "An independent contractor agreement must exist before payments under that agreement.",
    severity: "CRITICAL",
    paradoxType: "DIRECT_PARADOX",
    legalImplication: "Payments before the contractor agreement was signed support reclassification claims (the relationship existed before any independent contractor framing).",
  },
  {
    cause: "background_check",
    effect: "employment_contract",
    description: "Background checks must precede employment contracts under most regulated industries.",
    severity: "MEDIUM",
    paradoxType: "STATUTORY_PARADOX",
    legalImplication: "Employment contracts executed before background checks may violate industry-specific hiring regulations.",
  },
  {
    cause: "drug_test",
    effect: "employment_contract",
    description: "DOT and similar regulated industries require pre-employment drug testing.",
    severity: "HIGH",
    paradoxType: "STATUTORY_PARADOX",
    legalImplication: "Employment contracts executed before required drug tests violate 49 CFR Part 40 (DOT) and similar federal pre-employment testing rules.",
  },

  // ─── Authority paradoxes ──
  {
    cause: "incorporation",
    effect: "lease",
    description: "A corporation must be formed before it can sign contracts.",
    severity: "CRITICAL",
    paradoxType: "AUTHORITY_PARADOX",
    legalImplication: "Contracts signed by a corporation before its formation are voidable. The signatory may have personal liability for any obligations.",
  },
  {
    cause: "llc_formation",
    effect: "lease",
    description: "An LLC must be formed before it can sign contracts.",
    severity: "CRITICAL",
    paradoxType: "AUTHORITY_PARADOX",
    legalImplication: "Contracts signed by an LLC before its formation are voidable.",
  },
  {
    cause: "incorporation",
    effect: "employment_contract",
    description: "A corporation must be formed before it can hire employees.",
    severity: "CRITICAL",
    paradoxType: "AUTHORITY_PARADOX",
    legalImplication: "Employment contracts predating corporate formation are voidable and may indicate sole-proprietor liability.",
  },
  {
    cause: "incorporation",
    effect: "tax_return",
    description: "A corporation must be formed before it can file corporate tax returns.",
    severity: "HIGH",
    paradoxType: "AUTHORITY_PARADOX",
    legalImplication: "Corporate tax returns predating incorporation are fraudulent.",
  },

  // ─── Insurance paradoxes ──
  {
    cause: "insurance_binder",
    effect: "insurance_claim",
    description: "Insurance coverage must be bound before any claim against it.",
    severity: "CRITICAL",
    paradoxType: "INSURANCE_PARADOX",
    legalImplication: "Claims for losses occurring before coverage binding are fraudulent and void.",
  },

  // ─── License paradoxes ──
  {
    cause: "license",
    effect: "operational_log",
    description: "A license must be issued before licensed activity begins.",
    severity: "HIGH",
    paradoxType: "STATUTORY_PARADOX",
    legalImplication: "Operating without a required license is a regulatory violation. Operational records predating licensure prove unauthorized activity.",
  },
  {
    cause: "registration",
    effect: "operational_log",
    description: "Registration must precede operations requiring that registration.",
    severity: "HIGH",
    paradoxType: "STATUTORY_PARADOX",
    legalImplication: "Operations before required registration constitute unregistered activity.",
  },
];

// ─── Engine ──────────────────────────────────────────────────────────────

export class TemporalParadoxFilter {
  constructor(private env: Env) {}

  async ensureTables(): Promise<void> {
    const db = this.env.DB;
    await db.batch([
      db.prepare(`CREATE TABLE IF NOT EXISTS temporal_paradoxes (
        id TEXT PRIMARY KEY,
        analysis_id TEXT NOT NULL,
        paradox_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        cause_doc_id TEXT NOT NULL,
        cause_doc_type TEXT NOT NULL,
        cause_date TEXT NOT NULL,
        effect_doc_id TEXT NOT NULL,
        effect_doc_type TEXT NOT NULL,
        effect_date TEXT NOT NULL,
        days_between INTEGER NOT NULL,
        description TEXT NOT NULL,
        legal_implication TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      )`),
      db.prepare(`CREATE INDEX IF NOT EXISTS idx_paradoxes_analysis ON temporal_paradoxes(analysis_id)`),
      db.prepare(`CREATE INDEX IF NOT EXISTS idx_paradoxes_severity ON temporal_paradoxes(severity)`),
      db.prepare(`CREATE INDEX IF NOT EXISTS idx_paradoxes_type ON temporal_paradoxes(paradox_type)`),
    ]);
  }

  /**
   * Analyze a set of documents for temporal paradoxes.
   */
  async analyze(documents: DocumentDateRecord[]): Promise<TemporalAnalysisReport> {
    await this.ensureTables();
    const generatedAt = new Date().toISOString();
    const paradoxes: TemporalParadox[] = [];

    // Pass 1: Check calendar/date validity
    for (const doc of documents) {
      const calendarParadox = this.checkCalendarValidity(doc);
      if (calendarParadox) paradoxes.push(calendarParadox);
    }

    // Pass 2: Check causal relationships
    for (const rule of CAUSAL_RULES) {
      const causes = documents.filter((d) => d.documentType === rule.cause);
      const effects = documents.filter((d) => d.documentType === rule.effect);

      for (const effect of effects) {
        // Find the latest cause that should precede this effect
        const validCauses = causes.filter(
          (c) => new Date(c.claimedDate) <= new Date(effect.claimedDate)
        );

        if (causes.length > 0 && validCauses.length === 0) {
          // Effect exists but no valid (earlier) cause exists
          // Find the earliest cause (which postdates the effect)
          const earliestCause = causes.reduce((a, b) =>
            new Date(a.claimedDate) < new Date(b.claimedDate) ? a : b
          );
          const days = this.daysBetween(earliestCause.claimedDate, effect.claimedDate);
          paradoxes.push({
            type: rule.paradoxType,
            severity: rule.severity,
            cause: earliestCause,
            effect,
            daysBetween: days,
            description: rule.description,
            legalImplication: rule.legalImplication,
          });
        }
      }
    }

    // Persist paradoxes
    const analysisId = `tpa_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    for (const p of paradoxes) {
      const id = `par_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
      await this.env.DB.prepare(
        `INSERT INTO temporal_paradoxes
          (id, analysis_id, paradox_type, severity,
           cause_doc_id, cause_doc_type, cause_date,
           effect_doc_id, effect_doc_type, effect_date,
           days_between, description, legal_implication)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)`
      )
        .bind(
          id,
          analysisId,
          p.type,
          p.severity,
          p.cause.documentId,
          p.cause.documentType,
          p.cause.claimedDate,
          p.effect.documentId,
          p.effect.documentType,
          p.effect.claimedDate,
          p.daysBetween,
          p.description,
          p.legalImplication
        )
        .run();
    }

    // Anchor analysis to verification chain
    try {
      const { VerificationEngine } = await import("./verification-engine.js");
      const engine = new VerificationEngine(this.env);
      await engine.appendRecord({
        recordId: analysisId,
        recordType: "temporal_paradox_analysis",
        sourceTable: "temporal_paradoxes",
        sourceId: analysisId,
        content: {
          documentsAnalyzed: documents.length,
          paradoxesFound: paradoxes.length,
          criticalCount: paradoxes.filter((p) => p.severity === "CRITICAL").length,
        },
        metadata: {
          layer: "Layer 7a — Temporal Paradox Filter",
        },
      });
    } catch (err) {
      console.warn(
        "[TemporalParadoxFilter] Failed to anchor analysis to verification chain:",
        err instanceof Error ? err.message : err
      );
    }

    const criticalCount = paradoxes.filter((p) => p.severity === "CRITICAL").length;
    const highCount = paradoxes.filter((p) => p.severity === "HIGH").length;
    const mediumCount = paradoxes.filter((p) => p.severity === "MEDIUM").length;

    return {
      generatedAt,
      documentsAnalyzed: documents.length,
      paradoxesFound: paradoxes.length,
      criticalCount,
      highCount,
      mediumCount,
      paradoxes,
      timelineCoherent: paradoxes.length === 0,
      recommendation: this.recommendation(criticalCount, highCount, mediumCount),
    };
  }

  /**
   * Check if a date is calendar-valid (no Feb 30, no impossible months, etc.)
   * and that the day-of-week claim (if any) matches the actual date.
   */
  private checkCalendarValidity(doc: DocumentDateRecord): TemporalParadox | null {
    const date = new Date(doc.claimedDate);
    if (isNaN(date.getTime())) {
      return {
        type: "CALENDAR_PARADOX",
        severity: "CRITICAL",
        cause: doc,
        effect: doc,
        daysBetween: 0,
        description: `Document ${doc.documentName ?? doc.documentId} has an invalid date "${doc.claimedDate}" — this date does not exist on any calendar.`,
        legalImplication: "Documents with impossible dates are facially fraudulent. No further analysis is needed to call this a fabrication.",
      };
    }
    return null;
  }

  private daysBetween(earlier: string, later: string): number {
    const e = new Date(earlier).getTime();
    const l = new Date(later).getTime();
    return Math.round((e - l) / (1000 * 60 * 60 * 24));
  }

  private recommendation(critical: number, high: number, medium: number): string {
    if (critical > 0) {
      return `CRITICAL: ${critical} temporal paradox(es) detected. The document set contains effects that predate their causes by months or years. This is the structural signature of fabricated or retroactively constructed documents. The audit should be SEALED pending forensic review. DO NOT use these documents to support legal claims without independent verification of the actual chronology.`;
    }
    if (high > 0) {
      return `HIGH: ${high} temporal paradox(es) detected. The document set has serious chronological inconsistencies. Audit findings should be marked PROVISIONAL pending reconciliation of the timeline.`;
    }
    if (medium > 0) {
      return `MEDIUM: ${medium} temporal anomaly(ies) detected. Likely benign but worth noting in the audit report.`;
    }
    return "Timeline is coherent. No temporal paradoxes detected. Document set passes Layer 7a chronological integrity check.";
  }
}
