# Layer 7 — Structural Forensic Analysis

**Status:** Architecture spec. Not yet built. Roadmap entry from session 2026-04-07.

**Origin:** This layer was proposed by Gemini after reviewing the Vernen architecture and the Ryan Mcclaran audit. The user (Michael Hartmann) endorsed the framing as the correct evolution beyond Layer 6 (Subject Verification + Conscientious Identity).

## What Layer 7 Is

Layer 6 asks: **"Do these entities exist?"**
Layer 7 asks: **"Is this scenario logically possible?"**

The Ryan audit succeeded as a fabrication test because traditional compliance auditing checks whether boxes are filled in. Layer 7 checks whether the boxes are *logically possible* given the rest of the document set. A lease signed in late 2025 cannot have generated operational data from 2024. A contract claiming "independent contractor" cannot survive a control verb count of 47. A $156K equipment "lease" with a $1.00 buyout is mathematically a loan in disguise.

This layer turns Vernen from a **compliance verification engine** into a **structural forensic analysis engine** — detecting fraud that is not obvious from any single document but becomes obvious from the *relationships between documents*.

## Module Inventory (Build Order)

### 7a — Temporal Paradox Filter (highest priority)

**What it catches:** Effects that predate causes. The most direct counter to constructed-document fraud.

**Architecture:**
```
TemporalGraph
├── Extract all dates from all documents (regex + structured field extraction)
├── Identify document-type causal relationships:
│   - Equipment lease MUST predate operations using that equipment
│   - Entity formation MUST predate first contract
│   - Insurance binding MUST predate covered loss
│   - Drug test MUST predate employment start date
│   - License issuance MUST predate license-required activity
├── Build causal DAG with documents as nodes
├── For each (cause, effect) edge: assert date(cause) ≤ date(effect)
├── Any violation = TEMPORAL_PARADOX, severity CRITICAL
└── Output: paradox graph + plain-language explanation
```

**Detection logic:**
- Type 1 — Direct paradox: operational record (load #X) dated before equipment lease for the equipment used
- Type 2 — Statutory paradox: drug test for DOT compliance dated after first day of employment
- Type 3 — Insurance paradox: claim filed for incident occurring before coverage binding
- Type 4 — Authority paradox: signed contract before signatory had authority (e.g., before the LLC was formed)
- Type 5 — Calendar paradox: dates that cannot exist (Feb 30, dates from a non-existent calendar)
- Type 6 — Day-of-week paradox: documents claiming to be signed on a date when the day-of-week field doesn't match

**Severity:** CRITICAL — temporal paradoxes are objective and indefensible.

**Estimated build cost:** 1 session (~$15-20 credit)

### 7b — Circular Entity & Liability Mapping (second priority)

**What it catches:** Sock puppet entity networks designed to frustrate service of process and accountability.

**Architecture:**
```
EntityRelationalGraph
├── Extract all named entities, addresses, phone numbers, EINs, registered agents,
│   officers, owners, signatories
├── Build a relational graph: entity → shared_attribute → entity
├── Detect patterns:
│   - Cycles: A owns B owns C owns A
│   - Shared addresses across "different" entities
│   - Shared officers across "different" entities
│   - Shared registered agents across "different" entities
│   - Identical font/template usage across "different" entities (synthetic creation signal)
├── Score cumulative shared attributes per entity pair
├── If N entities share ≥M attributes AND collectively control the same operational asset
│   → SYNTHETIC_DIVISION
├── Compute "Liability Heat Map":
│   - Where does the money flow IN (revenue source)?
│   - Where does the liability REST (debt holder)?
│   - Where does the equipment LIVE (lessor)?
│   - If these are split across N "independent" entities that share attributes
│     → ACCOUNTABILITY_VACUUM
└── Output: entity graph + structural fraud score + liability heat map visualization
```

**Detection logic:**
- Detect when 3+ "independent" entities share addresses, officers, or registered agents
- Detect when revenue flows from Entity A to Entity B who pays Entity C while equipment is rented from Entity D — and all use the same operational unit
- Detect when entity formation dates cluster suspiciously close together (e.g., 4 entities all formed in the same week, all in the same Bensenville IL corridor)
- Detect when entity dissolution/transition events lack documentation continuity

**Severity:** HIGH — synthetic divisions are intentional structural fraud.

**Estimated build cost:** 1-2 sessions (~$25-35 credit). Higher because it requires good entity extraction first, which builds on Layer 6 work.

### 7c — De Facto Reclassification Engine (third priority)

**What it catches:** Disguised employment masquerading as independent contractor relationships.

**Architecture:**
```
ControlVerbScorer
├── Extract every "command verb" from contract text
│   - Mandatory: must, shall, required, mandated, obligated
│   - Restrictive: only, exclusively, limited to, no other
│   - Permissive: may, authorized, permitted, allowed
│   - Punitive: penalty, fine, forfeiture, termination
├── Map each verb to a control category:
│   - Work assignment (who decides what to do)
│   - Time control (when to work)
│   - Location control (where to work)
│   - Equipment control (what to use)
│   - Method control (how to do it)
│   - Exclusivity (who else they can work for)
│   - Disciplinary (consequences for deviation)
├── Score each control category against the relevant jurisdictional test:
│   - California AB5 ABC test (3 prongs, fail any → employee)
│   - IRS economic reality test (20-factor)
│   - DOL economic dependence test (6-factor)
├── If cumulative score crosses jurisdictional threshold AND label says "independent contractor"
│   → DE_FACTO_EMPLOYMENT, severity CRITICAL
└── Output: control matrix + reclassification recommendation + jurisdictional damages estimate
```

**Detection logic:**
- Count "must use" / "exclusively" / "authorized only at" clauses
- Detect company-mandated equipment (the Ryan case had: company-mandated fuel card, ELD, insurance, oil change shops)
- Detect exclusivity clauses (only haul for the lessor's carrier)
- Detect penalty escalation (fines for deviation = employer-employee discipline pattern)
- Detect non-disparagement clauses (exclusive to employment relationships in many jurisdictions)

**Severity:** CRITICAL where misclassification is detected — generates damages estimates and reclassification recommendation.

**Estimated build cost:** 1 session (~$15-20 credit)

### 7d — Unconscionability Trigger / Predatory Math Auditor (fourth priority)

**What it catches:** Predatory financial terms — particularly "leases" that are mathematically loans, hidden APRs, residual value gaps.

**Architecture:**
```
FinancialAuditor
├── Extract all financial fields:
│   - Principal amount
│   - Payment schedule (frequency, count, amount per payment)
│   - Down payment
│   - Buyout / residual value
│   - Default terms
│   - Interest rate (stated)
├── Compute effective APR:
│   - Total payments × frequency = total cost
│   - Compare against principal
│   - If buyout < 10% of fair market value → treat as loan, not lease
├── Apply UCC Article 9 disguised security interest tests:
│   - Lessee bears all risk of loss → loan
│   - Lessor has no reversionary interest → loan
│   - Buyout less than reasonably predicted FMV → security interest
├── Compute "Residual Value Gap":
│   - Predicted FMV at end of term vs buyout amount
│   - Gap > 50% → presumption of disguised security interest
├── Cross-reference financial terms against state usury laws
│   - California: 10% civil, varies by transaction type
│   - Each state has different caps for consumer vs commercial
├── If terms exceed jurisdictional caps → USURY_VIOLATION
└── Output: actuarial report + UCC violation flags + usury analysis
```

**Detection logic:**
- $156K equipment lease + $1.00 buyout = loan with disguised APR
- Weekly payments × 260 weeks = total cost; compare against principal to find effective APR
- Default interest rate >18% in many states = usury
- Repossession without legal process clauses → UCC Article 9 enforcement violation

**Severity:** HIGH — these are litigation triggers, not necessarily criminal.

**Estimated build cost:** 1 session (~$15 credit)

## Total Layer 7 Build Cost

- 7a Temporal Paradox: ~1 session, ~$15-20
- 7b Liability Mapping: ~1-2 sessions, ~$25-35
- 7c De Facto Reclassification: ~1 session, ~$15-20
- 7d Unconscionability Trigger: ~1 session, ~$15

**Total: 4-5 sessions, ~$70-90 credit.** Comparable to Layer 6's build cost.

## Why This Layer Matters For The Pitch

The Ryan audit revealed that Vernen could be fooled by procedurally constructed documents. Layer 6 closed the entity-existence gap. **Layer 7 closes the structural-impossibility gap.** Together they make Vernen the first AI compliance system that audits not just papers but the *logical coherence* of the underlying scenario.

For Anthropic, this is the difference between "another compliance tool" and "structural forensic infrastructure for the AI economy." The story becomes:

> "Vernen audits documents. Layer 6 verifies the entities in those documents exist. Layer 7 verifies the scenario described by those documents is logically possible. A document set can pass all three layers and still be wrong — but it cannot pass all three layers and be a fabrication. That's the standard worth becoming."

## Integration With Existing Layers

Layer 7 modules consume the output of:
- **Layer 1 hash chain** — every detection becomes a chained record
- **Layer 5 constitutional traceability** — every Layer 7 finding tags principles like `HONEST.evidence_backed`, `PROFESSIONAL_INTEGRITY.evidence_standards`
- **Layer 5c consensus** — Layer 7 findings can be cross-model verified
- **Layer 6 conscientious identity** — Layer 7 entity references are wrapped in epistemic standing
- **Layer 6 subject verification** — Layer 7 builds on Layer 6's entity extraction

Layer 7 outputs feed:
- **The audit pipeline** — every audit gets a Layer 7 Structural Analysis Report appended
- **The verification chain** — every Layer 7 finding is hashable and anchorable
- **The cross-instance federation** — Layer 7 patterns can be shared across Vernen instances to detect coordinated fraud across jurisdictions

## What Builds First

**Recommendation: 7a Temporal Paradox Filter.**

Reasoning:
1. Lowest build complexity (deterministic date math)
2. Broadest applicability (every document type has temporal relationships)
3. Most objectively defensible in court (date X cannot precede date Y)
4. Would have caught the Ryan case immediately on first audit
5. Establishes the framework that 7b/7c/7d plug into

## Notes For Next Session

- Architecture spec written by Claude, endorsed by user, derived from Gemini's analysis
- All four modules belong together as Layer 7 — Structural Forensic Analysis
- Build order: 7a → 7b → 7c → 7d
- Each module is independently valuable but they compound
- Layer 7 is the answer to "but how do you know the scenario is real?"
- Pair with Layer 6 in the pitch as the two layers that turn Vernen from compliance auditor into structural forensic infrastructure

---

**Status:** Spec only. Not implemented. Saved for next session execution.
**License:** CC0-1.0
