/**
 * Layer 7b — Circular Entity & Liability Mapping
 *
 * Builds a relational graph across all named entities in a document set
 * and detects sock-puppet networks designed to frustrate service of process
 * and accountability.
 *
 * Where Layer 6 (Subject Verification) asks "does this entity exist?",
 * Layer 7b asks "do these entities exist as *independent* parties, or do
 * they collectively constitute a single accountability-evading structure?"
 *
 * The Ryan Mcclaran case displayed this pattern: multiple "independent"
 * entities (carrier, lessor, fuel-card issuer, ELD provider, insurance
 * agent) clustered in the same Bensenville IL corridor, sharing addresses,
 * officers, and registered agents — collectively controlling the same
 * operational unit while distributing liability so no single entity could
 * be held to account.
 *
 * What it consumes:
 *   - Array of entities, each with: name, addresses, phones, EINs,
 *     registered agents, officers, formation date, role
 *   - Optional: revenue/liability/equipment-control flow data
 *
 * What it produces:
 *   - A graph of shared-attribute edges between entities
 *   - Cycle detection (A owns B owns C owns A)
 *   - Synthetic-division detection (3+ entities sharing 2+ attributes)
 *   - Accountability-vacuum detection (revenue source, debt holder,
 *     equipment owner, insurer all distributed across attribute-linked
 *     entities)
 *   - Cluster analysis (formation-date clustering, geographic clustering)
 *   - A persisted record anchored to the verification chain
 *
 * Spec: docs/LAYER_7_STRUCTURAL_FORENSIC_ANALYSIS.md
 * License: CC0-1.0
 */

import type { Env } from "../index.js";

// ─── Types ───────────────────────────────────────────────────────────────

export type EntityRole =
  | "carrier"
  | "lessor"
  | "lessee"
  | "fuel_card_issuer"
  | "eld_provider"
  | "insurer"
  | "registered_agent_of_record"
  | "fleet_owner"
  | "operating_company"
  | "holding_company"
  | "vendor"
  | "client"
  | "employer"
  | "worker_entity"
  | "other";

export interface EntityRecord {
  id: string;                       // Local identifier within the input set
  name: string;
  legalForm?: string;               // LLC, INC, LP, etc.
  jurisdiction?: string;            // State of formation
  formationDate?: string;           // ISO YYYY-MM-DD if known
  ein?: string;                     // Employer Identification Number
  addresses?: string[];             // Normalized; one entity may have several
  phones?: string[];
  emails?: string[];
  websites?: string[];
  registeredAgent?: string;
  officers?: string[];              // Names of officers/owners/managers
  parents?: string[];               // Entity ids of parent entities
  children?: string[];              // Entity ids of subsidiaries
  roles?: EntityRole[];

  // Operational role flags
  receivesRevenueFrom?: string[];   // Entity ids
  paysLiabilityTo?: string[];       // Entity ids
  ownsEquipmentUsedBy?: string[];   // Entity ids
  insures?: string[];               // Entity ids
}

export type SharedAttributeKind =
  | "ADDRESS"
  | "PHONE"
  | "EMAIL"
  | "REGISTERED_AGENT"
  | "OFFICER"
  | "EIN_PREFIX"
  | "DOMAIN"
  | "FORMATION_WEEK";

export interface SharedAttributeEdge {
  fromEntityId: string;
  toEntityId: string;
  kind: SharedAttributeKind;
  value: string;                    // The shared value itself
  weight: number;                   // 1..5 — how strongly this signals connection
}

export interface OwnershipCycle {
  entities: string[];               // Ordered list, last → first closes the cycle
  hops: number;
}

export interface SyntheticDivisionCluster {
  entityIds: string[];
  sharedAttributes: Array<{ kind: SharedAttributeKind; value: string }>;
  combinedRoles: EntityRole[];
  rationale: string;
}

export interface AccountabilityVacuum {
  operationalUnit: string;          // Description of the underlying activity
  revenueSourceEntityId?: string;
  liabilityHolderEntityId?: string;
  equipmentOwnerEntityId?: string;
  insurerEntityId?: string;
  workerEntityId?: string;
  attributeLinks: SharedAttributeEdge[];
  rationale: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
}

export type LiabilityFlag =
  | "CIRCULAR_OWNERSHIP"
  | "SYNTHETIC_DIVISION"
  | "ACCOUNTABILITY_VACUUM"
  | "FORMATION_DATE_CLUSTERING"
  | "GEOGRAPHIC_CLUSTERING"
  | "SHARED_REGISTERED_AGENT_NETWORK"
  | "OFFICER_OVERLAP"
  | "ADDRESS_REUSE";

export interface LiabilityFinding {
  flag: LiabilityFlag;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  finding: string;
  evidence: string;
  legalImplication: string;
  citation: string;
}

export interface LiabilityMapInput {
  caseId: string;
  caseName?: string;
  entities: EntityRecord[];
}

export interface LiabilityMapReport {
  generatedAt: string;
  caseId: string;
  caseName?: string;
  entityCount: number;

  edges: SharedAttributeEdge[];
  cycles: OwnershipCycle[];
  syntheticDivisions: SyntheticDivisionCluster[];
  accountabilityVacuums: AccountabilityVacuum[];
  formationClusters: Array<{ weekStart: string; entityIds: string[] }>;
  geographicClusters: Array<{ region: string; entityIds: string[] }>;

  findings: LiabilityFinding[];

  structuralFraudScore: number;     // 0..100
  verdict:
    | "INDEPENDENT_PARTIES"
    | "RELATED_BUT_DISTINCT"
    | "STRUCTURALLY_INTEGRATED"
    | "SYNTHETIC_LIABILITY_NETWORK";

  recommendation: string;
}

// ─── Engine ──────────────────────────────────────────────────────────────

export class LiabilityMapping {
  constructor(private env: Env) {}

  async ensureTables(): Promise<void> {
    const db = this.env.DB;
    await db.batch([
      db.prepare(`CREATE TABLE IF NOT EXISTS liability_map_reports (
        id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        case_name TEXT,
        entity_count INTEGER NOT NULL,
        edge_count INTEGER NOT NULL,
        cycle_count INTEGER NOT NULL,
        synthetic_division_count INTEGER NOT NULL,
        vacuum_count INTEGER NOT NULL,
        structural_fraud_score INTEGER NOT NULL,
        verdict TEXT NOT NULL,
        full_report TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      )`),
      db.prepare(`CREATE INDEX IF NOT EXISTS idx_liab_case ON liability_map_reports(case_id)`),
      db.prepare(`CREATE INDEX IF NOT EXISTS idx_liab_verdict ON liability_map_reports(verdict)`),
    ]);
  }

  /**
   * Build the liability map and analyze it.
   */
  async analyze(input: LiabilityMapInput): Promise<LiabilityMapReport> {
    await this.ensureTables();

    const entities = input.entities ?? [];
    const entityMap = new Map(entities.map((e) => [e.id, e]));

    // ─── Build shared-attribute edges ────────────────────────────────
    const edges = this.buildEdges(entities);

    // ─── Detect ownership cycles ─────────────────────────────────────
    const cycles = this.detectCycles(entities);

    // ─── Detect synthetic divisions ──────────────────────────────────
    const syntheticDivisions = this.detectSyntheticDivisions(entities, edges);

    // ─── Detect accountability vacuums ───────────────────────────────
    const accountabilityVacuums = this.detectAccountabilityVacuums(
      entities,
      edges,
      entityMap,
      syntheticDivisions
    );

    // ─── Cluster analysis ────────────────────────────────────────────
    const formationClusters = this.detectFormationClusters(entities);
    const geographicClusters = this.detectGeographicClusters(entities);

    // ─── Generate findings ───────────────────────────────────────────
    const findings: LiabilityFinding[] = [];

    if (cycles.length > 0) {
      findings.push({
        flag: "CIRCULAR_OWNERSHIP",
        severity: "CRITICAL",
        finding: `Detected ${cycles.length} circular ownership chain(s).`,
        evidence: cycles
          .slice(0, 3)
          .map((c) => c.entities.map((id) => entityMap.get(id)?.name ?? id).join(" → "))
          .join(" | "),
        legalImplication: "Circular ownership (A owns B owns C owns A) is a structural feature of accountability-evading entity networks. While not per se illegal, it is recognized in piercing-the-corporate-veil jurisprudence as one of the strongest factual indicators of an alter-ego relationship. Courts will collapse the entities into a single defendant for service and judgment purposes.",
        citation: "Restatement (Second) of Conflict of Laws §307; alter ego doctrine — see Las Palmas Associates v. Las Palmas Center Associates, 235 Cal. App. 3d 1220 (1991)",
      });
    }

    if (syntheticDivisions.length > 0) {
      findings.push({
        flag: "SYNTHETIC_DIVISION",
        severity: "CRITICAL",
        finding: `Detected ${syntheticDivisions.length} synthetic division cluster(s) — groups of nominally independent entities sharing 2+ attributes.`,
        evidence: syntheticDivisions
          .slice(0, 2)
          .map(
            (c) =>
              `[${c.entityIds.map((id) => entityMap.get(id)?.name ?? id).join(", ")}] sharing ${c.sharedAttributes
                .map((a) => `${a.kind}=${a.value}`)
                .join(", ")}`
          )
          .join(" | "),
        legalImplication: "Multiple 'independent' entities sharing addresses, officers, registered agents, or formation patterns are presumptively a single enterprise broken into pieces for liability distribution. Federal courts apply the integrated enterprise / single employer doctrine to collapse such clusters for jurisdiction, service, and damages purposes.",
        citation: "Radio & Television Broadcast Technicians v. Broadcast Service of Mobile, 380 U.S. 255 (1965); Papa v. Katy Industries, 166 F.3d 937 (7th Cir. 1999)",
      });
    }

    if (accountabilityVacuums.length > 0) {
      findings.push({
        flag: "ACCOUNTABILITY_VACUUM",
        severity: "CRITICAL",
        finding: `Detected ${accountabilityVacuums.length} accountability vacuum(s) — operational units where revenue, liability, equipment, and insurance are split across attribute-linked entities.`,
        evidence: accountabilityVacuums
          .slice(0, 2)
          .map((v) => v.rationale)
          .join(" | "),
        legalImplication: "When the four pillars of operational accountability — who earns the money, who bears the debt, who owns the equipment, and who carries the insurance — are distributed across entities that share attributes indicating common control, the result is a structure designed so that no single entity can be held to account. Courts treat this pattern as alter-ego, integrated enterprise, or fraudulent transfer, depending on jurisdiction.",
        citation: "Cal. Civ. Code §3439 (Uniform Voidable Transactions Act); alter ego doctrine; corporate veil piercing",
      });
    }

    if (formationClusters.length > 0) {
      findings.push({
        flag: "FORMATION_DATE_CLUSTERING",
        severity: "HIGH",
        finding: `Detected ${formationClusters.length} formation-date cluster(s) — groups of entities formed within the same week.`,
        evidence: formationClusters
          .slice(0, 3)
          .map((c) => `Week of ${c.weekStart}: ${c.entityIds.map((id) => entityMap.get(id)?.name ?? id).join(", ")}`)
          .join(" | "),
        legalImplication: "Entities formed within days of each other in the same jurisdiction are circumstantial evidence of coordinated structuring. Combined with shared attributes, formation-date clustering is one of the patterns courts cite when collapsing sham entity networks.",
        citation: "Various — see fraudulent transfer cases applying badges-of-fraud analysis under UVTA",
      });
    }

    if (geographicClusters.length > 0) {
      findings.push({
        flag: "GEOGRAPHIC_CLUSTERING",
        severity: "MEDIUM",
        finding: `Detected ${geographicClusters.length} geographic cluster(s) — entity addresses concentrated in narrow corridors.`,
        evidence: geographicClusters
          .slice(0, 3)
          .map((c) => `${c.region}: ${c.entityIds.map((id) => entityMap.get(id)?.name ?? id).join(", ")}`)
          .join(" | "),
        legalImplication: "Geographic clustering, especially in jurisdictions known for incorporation-mill activity, supports the inference of common control. Standing alone it is not dispositive, but combined with other attribute-sharing it strengthens the integrated-enterprise inference.",
        citation: "Pattern evidence — supporting alter-ego analysis",
      });
    }

    // Address reuse (counted separately because it can occur even without
    // a full synthetic-division cluster)
    const addressEdges = edges.filter((e) => e.kind === "ADDRESS");
    if (addressEdges.length >= 1 && !findings.some((f) => f.flag === "SYNTHETIC_DIVISION")) {
      findings.push({
        flag: "ADDRESS_REUSE",
        severity: "MEDIUM",
        finding: `${addressEdges.length} edge(s) link entities by shared physical address.`,
        evidence: addressEdges.slice(0, 3).map((e) => `${entityMap.get(e.fromEntityId)?.name} ↔ ${entityMap.get(e.toEntityId)?.name} @ ${e.value}`).join(" | "),
        legalImplication: "Shared physical address between nominally independent entities is one of the strongest individual factors in the integrated-enterprise analysis. It is not dispositive alone but materially raises the prior probability of common control.",
        citation: "Single-employer / integrated-enterprise analysis under federal labor and employment law",
      });
    }

    // Officer overlap (also counted separately)
    const officerEdges = edges.filter((e) => e.kind === "OFFICER");
    if (officerEdges.length >= 1 && !findings.some((f) => f.flag === "SYNTHETIC_DIVISION")) {
      findings.push({
        flag: "OFFICER_OVERLAP",
        severity: "HIGH",
        finding: `${officerEdges.length} edge(s) link entities by shared officer.`,
        evidence: officerEdges.slice(0, 3).map((e) => `${entityMap.get(e.fromEntityId)?.name} ↔ ${entityMap.get(e.toEntityId)?.name} via ${e.value}`).join(" | "),
        legalImplication: "Shared officers between 'independent' entities is a near-conclusive sign of common control. Courts uniformly treat overlapping management as a primary indicator of integrated enterprise.",
        citation: "Radio & Television Broadcast Technicians, 380 U.S. 255",
      });
    }

    // Shared registered agent network
    const agentEdges = edges.filter((e) => e.kind === "REGISTERED_AGENT");
    if (agentEdges.length >= 2) {
      findings.push({
        flag: "SHARED_REGISTERED_AGENT_NETWORK",
        severity: "MEDIUM",
        finding: `${agentEdges.length} edge(s) link entities by shared registered agent.`,
        evidence: agentEdges.slice(0, 3).map((e) => `${entityMap.get(e.fromEntityId)?.name} ↔ ${entityMap.get(e.toEntityId)?.name} via ${e.value}`).join(" | "),
        legalImplication: "Shared registered agents are common in legitimate cases (the agent is a service provider) but become significant when combined with other attribute sharing. The pattern indicates that service of process flows through a single point of failure — frustrating accountability.",
        citation: "Various — supporting alter-ego analysis",
      });
    }

    // ─── Score and verdict ───────────────────────────────────────────
    let score = 0;
    for (const f of findings) {
      switch (f.severity) {
        case "CRITICAL": score += 30; break;
        case "HIGH": score += 15; break;
        case "MEDIUM": score += 8; break;
        case "LOW": score += 3; break;
      }
    }
    score = Math.min(100, score);

    let verdict: LiabilityMapReport["verdict"];
    if (score >= 70) verdict = "SYNTHETIC_LIABILITY_NETWORK";
    else if (score >= 40) verdict = "STRUCTURALLY_INTEGRATED";
    else if (score >= 15) verdict = "RELATED_BUT_DISTINCT";
    else verdict = "INDEPENDENT_PARTIES";

    const report: LiabilityMapReport = {
      generatedAt: new Date().toISOString(),
      caseId: input.caseId,
      caseName: input.caseName,
      entityCount: entities.length,
      edges,
      cycles,
      syntheticDivisions,
      accountabilityVacuums,
      formationClusters,
      geographicClusters,
      findings,
      structuralFraudScore: score,
      verdict,
      recommendation: this.recommendation(verdict, findings),
    };

    // ─── Persist ─────────────────────────────────────────────────────
    const id = `liab_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    await this.env.DB.prepare(
      `INSERT INTO liability_map_reports
        (id, case_id, case_name, entity_count, edge_count,
         cycle_count, synthetic_division_count, vacuum_count,
         structural_fraud_score, verdict, full_report)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)`
    )
      .bind(
        id,
        input.caseId,
        input.caseName ?? null,
        entities.length,
        edges.length,
        cycles.length,
        syntheticDivisions.length,
        accountabilityVacuums.length,
        score,
        verdict,
        JSON.stringify(report)
      )
      .run();

    // ─── Anchor to verification chain ────────────────────────────────
    try {
      const { VerificationEngine } = await import("./verification-engine.js");
      const engine = new VerificationEngine(this.env);
      await engine.appendRecord({
        recordId: id,
        recordType: "liability_map",
        sourceTable: "liability_map_reports",
        sourceId: id,
        content: {
          caseId: input.caseId,
          verdict,
          score,
          entityCount: entities.length,
          edgeCount: edges.length,
          findingsCount: findings.length,
        },
        metadata: {
          layer: "Layer 7b — Circular Entity & Liability Mapping",
        },
      });
    } catch (err) {
      console.warn(
        "[LiabilityMapping] Failed to anchor to verification chain:",
        err instanceof Error ? err.message : err
      );
    }

    return report;
  }

  // ─── Helpers ─────────────────────────────────────────────────────────

  private normalize(s: string | undefined): string {
    return (s ?? "").toLowerCase().replace(/[\s,.\-#]+/g, " ").trim();
  }

  private buildEdges(entities: EntityRecord[]): SharedAttributeEdge[] {
    const edges: SharedAttributeEdge[] = [];

    // Build inverted indices
    const byAddress = new Map<string, string[]>();
    const byPhone = new Map<string, string[]>();
    const byEmail = new Map<string, string[]>();
    const byAgent = new Map<string, string[]>();
    const byOfficer = new Map<string, string[]>();
    const byEinPrefix = new Map<string, string[]>();
    const byDomain = new Map<string, string[]>();

    for (const e of entities) {
      for (const a of e.addresses ?? []) {
        const k = this.normalize(a);
        if (!k) continue;
        (byAddress.get(k) ?? byAddress.set(k, []).get(k)!).push(e.id);
      }
      for (const p of e.phones ?? []) {
        const k = (p ?? "").replace(/\D/g, "");
        if (k.length < 7) continue;
        (byPhone.get(k) ?? byPhone.set(k, []).get(k)!).push(e.id);
      }
      for (const m of e.emails ?? []) {
        const k = this.normalize(m);
        if (!k) continue;
        (byEmail.get(k) ?? byEmail.set(k, []).get(k)!).push(e.id);
        const domain = k.split("@")[1];
        if (domain) {
          (byDomain.get(domain) ?? byDomain.set(domain, []).get(domain)!).push(e.id);
        }
      }
      for (const w of e.websites ?? []) {
        const k = this.normalize(w).replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0];
        if (!k) continue;
        (byDomain.get(k) ?? byDomain.set(k, []).get(k)!).push(e.id);
      }
      if (e.registeredAgent) {
        const k = this.normalize(e.registeredAgent);
        if (k) (byAgent.get(k) ?? byAgent.set(k, []).get(k)!).push(e.id);
      }
      for (const o of e.officers ?? []) {
        const k = this.normalize(o);
        if (!k) continue;
        (byOfficer.get(k) ?? byOfficer.set(k, []).get(k)!).push(e.id);
      }
      if (e.ein && e.ein.length >= 2) {
        const prefix = e.ein.replace(/\D/g, "").slice(0, 2);
        if (prefix.length === 2) {
          (byEinPrefix.get(prefix) ?? byEinPrefix.set(prefix, []).get(prefix)!).push(e.id);
        }
      }
    }

    const emit = (
      index: Map<string, string[]>,
      kind: SharedAttributeKind,
      weight: number
    ) => {
      for (const [value, ids] of index.entries()) {
        const unique = Array.from(new Set(ids));
        if (unique.length < 2) continue;
        for (let i = 0; i < unique.length; i++) {
          for (let j = i + 1; j < unique.length; j++) {
            edges.push({
              fromEntityId: unique[i]!,
              toEntityId: unique[j]!,
              kind,
              value,
              weight,
            });
          }
        }
      }
    };

    emit(byAddress, "ADDRESS", 4);
    emit(byPhone, "PHONE", 3);
    emit(byEmail, "EMAIL", 4);
    emit(byAgent, "REGISTERED_AGENT", 2);
    emit(byOfficer, "OFFICER", 5);
    emit(byEinPrefix, "EIN_PREFIX", 1);
    emit(byDomain, "DOMAIN", 3);

    return edges;
  }

  private detectCycles(entities: EntityRecord[]): OwnershipCycle[] {
    // Build directed graph from parents/children
    const graph = new Map<string, Set<string>>();
    for (const e of entities) {
      graph.set(e.id, new Set());
    }
    for (const e of entities) {
      for (const childId of e.children ?? []) {
        graph.get(e.id)?.add(childId);
      }
      for (const parentId of e.parents ?? []) {
        graph.get(parentId)?.add(e.id);
      }
    }

    const cycles: OwnershipCycle[] = [];
    const seenCycles = new Set<string>();

    const dfs = (start: string, current: string, path: string[]) => {
      if (path.length > 8) return;  // cap depth
      const next = graph.get(current);
      if (!next) return;
      for (const n of next) {
        if (n === start && path.length >= 1) {
          const cycle = [...path, current];
          // Canonicalize: rotate so smallest id comes first
          const sorted = cycle.slice().sort();
          const minId = sorted[0]!;
          const minIdx = cycle.indexOf(minId);
          const canon = [...cycle.slice(minIdx), ...cycle.slice(0, minIdx)].join(">");
          if (!seenCycles.has(canon)) {
            seenCycles.add(canon);
            cycles.push({ entities: cycle, hops: cycle.length });
          }
        } else if (!path.includes(n)) {
          dfs(start, n, [...path, current]);
        }
      }
    };

    for (const e of entities) {
      dfs(e.id, e.id, []);
    }

    return cycles;
  }

  private detectSyntheticDivisions(
    entities: EntityRecord[],
    edges: SharedAttributeEdge[]
  ): SyntheticDivisionCluster[] {
    // Group edges by entity pair
    const pairAttributes = new Map<string, Array<{ kind: SharedAttributeKind; value: string }>>();
    for (const e of edges) {
      const key = [e.fromEntityId, e.toEntityId].sort().join("|");
      const arr = pairAttributes.get(key) ?? [];
      arr.push({ kind: e.kind, value: e.value });
      pairAttributes.set(key, arr);
    }

    // Find pairs that share 2+ different attribute kinds
    const stronglyLinked = new Map<string, Set<string>>();
    for (const [key, attrs] of pairAttributes.entries()) {
      const kinds = new Set(attrs.map((a) => a.kind));
      if (kinds.size >= 2) {
        const parts = key.split("|");
        const a = parts[0]!;
        const b = parts[1]!;
        (stronglyLinked.get(a) ?? stronglyLinked.set(a, new Set()).get(a)!).add(b);
        (stronglyLinked.get(b) ?? stronglyLinked.set(b, new Set()).get(b)!).add(a);
      }
    }

    // Find connected components in the strongly-linked graph
    const visited = new Set<string>();
    const clusters: SyntheticDivisionCluster[] = [];
    const entityMap = new Map(entities.map((e) => [e.id, e]));

    for (const e of entities) {
      if (visited.has(e.id)) continue;
      const component: string[] = [];
      const queue = [e.id];
      while (queue.length) {
        const cur = queue.shift()!;
        if (visited.has(cur)) continue;
        visited.add(cur);
        component.push(cur);
        for (const neighbor of stronglyLinked.get(cur) ?? []) {
          if (!visited.has(neighbor)) queue.push(neighbor);
        }
      }
      if (component.length >= 3) {
        // Collect the shared attributes across all pairs in this cluster
        const sharedAttrs: Array<{ kind: SharedAttributeKind; value: string }> = [];
        const seenAttrs = new Set<string>();
        for (let i = 0; i < component.length; i++) {
          for (let j = i + 1; j < component.length; j++) {
            const k = [component[i], component[j]].sort().join("|");
            for (const attr of pairAttributes.get(k) ?? []) {
              const sig = `${attr.kind}:${attr.value}`;
              if (!seenAttrs.has(sig)) {
                seenAttrs.add(sig);
                sharedAttrs.push(attr);
              }
            }
          }
        }
        const combinedRoles = Array.from(
          new Set(component.flatMap((id) => entityMap.get(id)?.roles ?? []))
        );
        clusters.push({
          entityIds: component,
          sharedAttributes: sharedAttrs,
          combinedRoles,
          rationale: `${component.length} entities are linked by ${sharedAttrs.length} shared attribute(s) across ${new Set(sharedAttrs.map((a) => a.kind)).size} attribute kinds, collectively spanning roles: ${combinedRoles.join(", ") || "(unspecified)"}`,
        });
      }
    }

    return clusters;
  }

  private detectAccountabilityVacuums(
    entities: EntityRecord[],
    edges: SharedAttributeEdge[],
    entityMap: Map<string, EntityRecord>,
    syntheticDivisions: SyntheticDivisionCluster[] = []
  ): AccountabilityVacuum[] {
    const vacuums: AccountabilityVacuum[] = [];

    // For each worker_entity, check whether the four pillars are split
    // across attribute-linked entities
    const workerEntities = entities.filter((e) =>
      (e.roles ?? []).includes("worker_entity") || (e.roles ?? []).includes("lessee")
    );

    // Build attribute link map
    const linked = new Set<string>();
    for (const e of edges) {
      linked.add([e.fromEntityId, e.toEntityId].sort().join("|"));
    }
    const isLinked = (a: string, b: string) =>
      a !== b && linked.has([a, b].sort().join("|"));

    for (const worker of workerEntities) {
      // Find:
      //  - revenueSource: who pays the worker (worker.receivesRevenueFrom)
      //  - liabilityHolder: who the worker pays (worker.paysLiabilityTo)
      //  - equipmentOwner: who owns the equipment used (worker.parents or via roles)
      //  - insurer: who insures (find entity with role=insurer linked to worker)
      const revenueSource = (worker.receivesRevenueFrom ?? [])[0];
      const liabilityHolder = (worker.paysLiabilityTo ?? [])[0];
      const equipmentOwner = entities.find(
        (e) => (e.roles ?? []).includes("lessor") && (e.ownsEquipmentUsedBy ?? []).includes(worker.id)
      )?.id;
      const insurer = entities.find(
        (e) => (e.roles ?? []).includes("insurer") && (e.insures ?? []).includes(worker.id)
      )?.id;

      const pillars = [revenueSource, liabilityHolder, equipmentOwner, insurer].filter(Boolean) as string[];
      if (pillars.length < 2) continue;

      // Check whether pillars are linked to each other (or to a common third entity)
      const links: SharedAttributeEdge[] = [];
      for (const e of edges) {
        if (
          (pillars.includes(e.fromEntityId) || pillars.includes(e.toEntityId)) &&
          (pillars.includes(e.fromEntityId) || pillars.includes(e.toEntityId))
        ) {
          if (pillars.includes(e.fromEntityId) && pillars.includes(e.toEntityId)) {
            links.push(e);
          }
        }
      }

      // If 2+ of the pillars are linked AND the entities are nominally distinct
      const distinctIds = new Set(pillars);
      if (links.length >= 1 && distinctIds.size >= 2) {
        const severity: AccountabilityVacuum["severity"] =
          links.length >= 3 ? "CRITICAL" : links.length >= 2 ? "HIGH" : "MEDIUM";
        vacuums.push({
          operationalUnit: `Operations of ${worker.name}`,
          revenueSourceEntityId: revenueSource,
          liabilityHolderEntityId: liabilityHolder,
          equipmentOwnerEntityId: equipmentOwner,
          insurerEntityId: insurer,
          workerEntityId: worker.id,
          attributeLinks: links,
          rationale: `Worker entity ${worker.name} interacts with ${distinctIds.size} 'independent' parties (${pillars.map((id) => entityMap.get(id)?.name ?? id).join(", ")}), but ${links.length} attribute link(s) connect those parties to each other — collapsing the apparent independence.`,
          severity,
        });
      }
    }

    // ─── Structural fall-through path ────────────────────────────────
    // When the per-worker flow data isn't available (common with narrative
    // documents that don't explicitly enumerate receivesRevenueFrom /
    // paysLiabilityTo / ownsEquipmentUsedBy), we can still detect the
    // accountability vacuum pattern from the synthetic-division clusters
    // alone. The pattern is: 3+ entities sharing 2+ attribute kinds AND
    // collectively spanning the operational role spread (worker_entity,
    // lessor, insurer, operating_company). When that pattern is present,
    // the integrated enterprise IS the accountability vacuum — the
    // operational pillars are distributed across linked shells.
    if (vacuums.length === 0) {
      const operationalRoles: EntityRole[] = [
        "worker_entity",
        "lessor",
        "insurer",
        "operating_company",
        "fleet_owner",
        "lessee",
      ];
      for (const cluster of syntheticDivisions) {
        if (cluster.entityIds.length < 3) continue;
        const rolesInCluster = new Set(cluster.combinedRoles);
        const operationalRolesPresent = operationalRoles.filter((r) => rolesInCluster.has(r));
        if (operationalRolesPresent.length >= 2) {
          const clusterEdges = edges.filter(
            (e) => cluster.entityIds.includes(e.fromEntityId) && cluster.entityIds.includes(e.toEntityId)
          );
          vacuums.push({
            operationalUnit: `Integrated enterprise across ${cluster.entityIds.length} attribute-linked entities`,
            workerEntityId: cluster.entityIds.find((id) => entityMap.get(id)?.roles?.includes("worker_entity")),
            equipmentOwnerEntityId: cluster.entityIds.find((id) => entityMap.get(id)?.roles?.includes("lessor")),
            insurerEntityId: cluster.entityIds.find((id) => entityMap.get(id)?.roles?.includes("insurer")),
            attributeLinks: clusterEdges,
            rationale: `${cluster.entityIds.length} attribute-linked entities (${cluster.entityIds.map((id) => entityMap.get(id)?.name ?? id).join(", ")}) collectively span operational roles ${operationalRolesPresent.join(", ")}. The synthetic-division cluster IS the accountability vacuum — revenue, labor, equipment, and indemnity are distributed across entities sharing ${cluster.sharedAttributes.length} attributes, so no single entity carries the full operational liability.`,
            severity: operationalRolesPresent.length >= 3 ? "CRITICAL" : "HIGH",
          });
        }
      }
    }

    return vacuums;
  }

  private detectFormationClusters(entities: EntityRecord[]): Array<{ weekStart: string; entityIds: string[] }> {
    const byWeek = new Map<string, string[]>();
    for (const e of entities) {
      if (!e.formationDate) continue;
      const d = new Date(e.formationDate);
      if (Number.isNaN(d.getTime())) continue;
      // Round down to Monday
      const day = d.getUTCDay();
      const diff = (day + 6) % 7;
      const monday = new Date(d.getTime() - diff * 24 * 60 * 60 * 1000);
      const weekKey = monday.toISOString().slice(0, 10);
      (byWeek.get(weekKey) ?? byWeek.set(weekKey, []).get(weekKey)!).push(e.id);
    }
    const clusters: Array<{ weekStart: string; entityIds: string[] }> = [];
    for (const [week, ids] of byWeek.entries()) {
      if (ids.length >= 3) clusters.push({ weekStart: week, entityIds: ids });
    }
    return clusters;
  }

  private detectGeographicClusters(entities: EntityRecord[]): Array<{ region: string; entityIds: string[] }> {
    // Cluster by city + state extracted from addresses
    const byRegion = new Map<string, Set<string>>();
    for (const e of entities) {
      for (const a of e.addresses ?? []) {
        // Loose city, ST extraction: last "City, ST ZIP" pattern
        const m = a.match(/([A-Za-z .'\-]+),\s*([A-Z]{2})\s*\d{5}/);
        if (!m) continue;
        const region = `${m[1]!.trim()}, ${m[2]!}`;
        (byRegion.get(region) ?? byRegion.set(region, new Set()).get(region)!).add(e.id);
      }
    }
    const clusters: Array<{ region: string; entityIds: string[] }> = [];
    for (const [region, ids] of byRegion.entries()) {
      if (ids.size >= 3) clusters.push({ region, entityIds: Array.from(ids) });
    }
    return clusters;
  }

  private recommendation(
    verdict: LiabilityMapReport["verdict"],
    findings: LiabilityFinding[]
  ): string {
    const critical = findings.filter((f) => f.severity === "CRITICAL").length;
    switch (verdict) {
      case "SYNTHETIC_LIABILITY_NETWORK":
        return `${critical} CRITICAL findings. The entities in this case do not constitute independent parties — they are a structurally integrated network designed to distribute liability across nominally separate units. Recommend (a) plead alter-ego / integrated-enterprise theory, (b) name all linked entities as defendants, (c) seek discovery on the shared-attribute structure, and (d) consider fraudulent-transfer claims under UVTA. Engage counsel familiar with veil-piercing.`;
      case "STRUCTURALLY_INTEGRATED":
        return "The entity set shows strong structural integration. Recommend pleading alter-ego in the alternative and conducting discovery on shared management, addresses, and registered agents.";
      case "RELATED_BUT_DISTINCT":
        return "The entities are related but the available signals do not yet support a single-enterprise finding. Recommend further investigation into management, control, and financial flows.";
      case "INDEPENDENT_PARTIES":
        return "The entities appear to be independent parties under standard structural analysis. No accountability-vacuum or alter-ego concerns detected.";
    }
  }
}
