# SAT-SA v2 SOTA: Supervisory Analytics Tool for SOC Assessment
## High-Impact Architecture & Forensic Analytics Specification

- **Document Version**: 2.0.0
- **Date**: 2026-09-25
- **Author**: Antigravity & SAT-SA Core Engineering Team
- **Target Agency**: National Technical Research Organisation (NTRO) / NCIIPC
- **Statutory Framework**: Information Technology Act 2000 (Section 70B), CERT-In Directions 2022
- **Environment**: 100% Air-Gapped, Zero-Cloud, Standalone Desktop (Tauri v2 + Rust + React/TypeScript)

---

## 1. Executive Summary & Objective

In supervisory oversight of Critical Sector Entities (CSEs — National Power Grid, Central Banking Core, Telecommunications Backbones, Oil & Gas), superficial compliance checks allow sophisticated operational gaming to go unnoticed. Traditional compliance audits rely on self-reported entity metrics (e.g., "99% SLA adherence", "all high alerts resolved").

**SAT-SA v2 SOTA** transforms supervisory oversight from static checklist inspection into **mathematically defensible, cryptographic forensic intelligence**. Running entirely inside an air-gapped, offline desktop application, SAT-SA v2 equips NCIIPC examiners to:
1. **Unmask Operational Gaming**: Prove ticket closure fabrication using **Benford's Law ($\chi^2$)**, detect shift-end ticket dumping via **Poisson inter-arrival windowing**, and identify analyst collusion via **MinHash Locality-Sensitive Hashing (LSH)**.
2. **Expose Negative Space Blind Spots**: Quantify telemetry suppression via **Shannon Information Entropy ($H(X)$)**, map monitoring deficits against the **MITRE ATT&CK v14 Enterprise Matrix**, and flag unmonitored core OT/SCADA and banking subnets.
3. **Audit Statutory Mandates**: Automatically verify compliance with the **CERT-In 6-Hour incident reporting mandate** under Section 70B of the IT Act.
4. **Cryptographic Chain of Custody**: Seal all ingested telemetry, intermediate findings, and executive audit reports into an immutable **SHA-256 Merkle Tree** proof ledger to withstand judicial and regulatory scrutiny.

---

## 2. System Architecture & Air-Gapped Trust Model

```
+-------------------------------------------------------------------------------------------------------+
|                                    SAT-SA v2 SOTA APPLICATION BOUNDARY                                |
|                                                                                                       |
|  +-------------------------------------------------------------------------------------------------+  |
|  |                             PRESENTATION LAYER (React 18 + TypeScript + Tailwind)               |  |
|  |  +---------------------------+  +--------------------------+  +-------------------------------+ |  |
|  |  | Executive Risk Hub        |  | Forensic Deep-Diver      |  | Regulatory & Evidentiary Vault| |  |
|  |  | - Composite Risk Index    |  | - Benford Inspector      |  | - CERT-In 6-Hr Mandate Audit  | |  |
|  |  | - MITRE ATT&CK Heatmap    |  | - MinHash Note Clusters  |  | - Cryptographic Merkle Seal   | |  |
|  |  | - Subnet Blind Spot Radar |  | - Shift Burst Dump Radar |  | - Statutory PDF/JSON Export   | |  |
|  |  +---------------------------+  +--------------------------+  +-------------------------------+ |  |
|  +-------------------------------------------------------------------------------------------------+  |
|                                                  ▲                                                    |
|                                       Tauri v2 IPC (Typed JSON)                                       |
|                                                  ▼                                                    |
|  +-------------------------------------------------------------------------------------------------+  |
|  |                                      RUST ANALYTICS CORE                                        |  |
|  |  +-------------------------+  +--------------------------+  +---------------------------------+  |  |
|  |  | Execution Gap Engine    |  | Negative Space Engine    |  | Forensic & Audit Engine         |  |  |
|  |  | - Benford's Law Chi2    |  | - Shannon Entropy H(X)   |  | - CERT-In 6-Hr SLA Verifier     |  |  |
|  |  | - MinHash LSH Text Sim  |  | - MITRE ATT&CK v14 Matrix|  | - SHA-256 Merkle Tree Root      |  |  |
|  |  | - Shift Burst Dump Det  |  | - Subnet Reachability    |  | - Peer Benchmarking (Z-Score)   |  |  |
|  |  +-------------------------+  +--------------------------+  +---------------------------------+  |  |
|  +-------------------------------------------------------------------------------------------------+  |
|                                                  ▲                                                    |
|                                        rusqlite (Embedded C)                                          |
|                                                  ▼                                                    |
|  +-------------------------------------------------------------------------------------------------+  |
|  |                                  AIR-GAPPED STORAGE LAYER                                       |  |
|  |  - Embedded SQLite (satsa_tauri.db) with WAL mode, memory-mapped I/O, synchronous=NORMAL         |  |
|  |  - Ingestion: CSV, JSON, CEF batches with strict schema validation & streaming parsing          |  |
|  |  - Merkle Audit Ledger: Append-only hash chain of batches and findings                          |  |
|  +-------------------------------------------------------------------------------------------------+  |
+-------------------------------------------------------------------------------------------------------+
```

### Security & Air-Gap Guarantees:
- **Zero Sockets**: Application listens on no external network interfaces, opens zero outbound sockets, and contains no external analytics/telemetry SDKs.
- **Deterministic Evaluation**: Given the same ingested batch, the Rust analytics engine produces identical findings, scores, and Merkle tree root hashes.
- **Embedded Storage**: Relies solely on `rusqlite` embedded in the process space.

---

## 3. Mathematical & Algorithmic Specifications

### 3.1. Execution Gap 1: Benford's Law & $\chi^2$ Goodness-of-Fit on Investigation Durations
* **Principle**: True human-investigated incident durations (seconds or minutes) naturally span orders of magnitude and follow Benford's Law for first-digit significant distribution:
  $$P(d) = \log_{10}\left(1 + \frac{1}{d}\right) \quad \text{for } d \in \{1, 2, \dots, 9\}$$
* **Gaming Hypothesis**: When SOC analysts artificially fabricate resolution times or batch-close tickets with automated script delays, the first digits deviate markedly from logarithmic distribution toward uniform or clustered distributions.
* **Algorithm**:
  1. Extract positive ticket durations $T_i = t_{\text{closed}} - t_{\text{created}}$ in seconds for all closed cases.
  2. Extract first significant digit $D_i \in \{1..9\}$.
  3. Calculate observed frequency $O_d$ and expected frequency $E_d = N \times \log_{10}(1 + 1/d)$.
  4. Compute Pearson's chi-square test statistic:
     $$\chi^2 = \sum_{d=1}^{9} \frac{(O_d - E_d)^2}{E_d}, \quad \text{degrees of freedom } \nu = 8$$
  5. Calculate $p$-value using the regularized upper incomplete gamma function. If $\chi^2 > 20.09$ ($p < 0.01$), reject the null hypothesis and flag **Systemic Case Duration Tampering/Fabrication**.

### 3.2. Execution Gap 2: MinHash + Jaccard Locality-Sensitive Hashing (LSH) for Template Collusion
* **Principle**: To meet SLA quotas, analysts frequently copy-paste canned resolution text across cases or share templates. Basic string matching fails when minor words, whitespace, or punctuation change.
* **Algorithm**:
  1. Tokenize resolution notes into lowercase character 3-grams (shingles).
  2. Apply $K = 64$ linear hash functions $h_k(x) = (a_k \cdot x + b_k) \pmod p$.
  3. Compute 64-dimensional MinHash signature vector $S(n)$ for each note:
     $$S_k(n) = \min_{s \in \text{shingles}(n)} h_k(s)$$
  4. Estimate pairwise Jaccard similarity:
     $$J(A, B) \approx \frac{1}{K} \sum_{k=1}^{K} \mathbb{I}[S_k(A) = S_k(B)]$$
  5. Cluster notes where $J \ge 0.80$. If $\ge 25\%$ of notes reside in duplicate clusters, generate a High/Critical finding with the identified template text and involved investigator IDs.

### 3.3. Execution Gap 3: Shift-End Burst Closure & Ticket Dumping (Inter-Arrival Windowing)
* **Principle**: Analysts close tickets in rapid succession at the end of their shift or before SLA report deadlines ("cherry-picking and dumping").
* **Algorithm**:
  1. Partition closed cases by `investigator_id` and sort chronologically by $t_{\text{closed}}$.
  2. Compute rolling 5-minute sliding window ticket closure velocity $V(t) = \text{count}(t \le t_{\text{closed}} < t + 300\text{s})$.
  3. Identify burst anomalies where closure velocity $V(t) \ge 10$ tickets in 5 minutes with average duration $< 90\text{s}$.
  4. Calculate the entity's **Shift-End Dumping Ratio**; if $>20\%$ of tickets are closed in burst windows, flag **SLA Metric Gaming via Shift-End Ticket Dumping**.

### 3.4. Negative Space 1: Shannon Telemetry Information Entropy $H(X)$
* **Principle**: In an enterprise SOC, incoming security alerts across categories (Authentication, Network, Endpoint, Privilege Escalation, Malware) form an information distribution. Suppression of alerts via over-aggressive whitelist rules or SIEM collection failures causes entropy collapse.
* **Algorithm**:
  1. Given a time window $W$, count occurrences of alerts per category $C_1, \dots, C_k$ with total alerts $N$.
  2. Compute probability $p_i = \frac{n_i}{N}$.
  3. Calculate Shannon Entropy:
     $$H(X) = -\sum_{i=1}^{k} p_i \log_2(p_i)$$
  4. Maximum theoretical entropy is $H_{\max} = \log_2(k)$. Compute Normalized Entropy $\hat{H} = \frac{H(X)}{H_{\max}}$.
  5. An entropy collapse where $\hat{H} < 0.35$ or $H(X) < 1.0$ indicates **Severe Alert Suppression / Pipeline Blind Spot**.

### 3.5. Negative Space 2: MITRE ATT&CK v14 Enterprise Tactical Matrix Coverage
* **Principle**: Comprehensive SOC telemetry must cover the attack chain. An entity showing zero telemetry for core tactics while reporting high overall volume has structural detection blind spots.
* **Tactical Coverage Vector**:
  Evaluate 11 core MITRE tactics:
  1. Initial Access (`TA0001`)
  2. Execution (`TA0002`)
  3. Persistence (`TA0003`)
  4. Privilege Escalation (`TA0004`)
  5. Defense Evasion (`TA0005`)
  6. Credential Access (`TA0006`)
  7. Discovery (`TA0007`)
  8. Lateral Movement (`TA0008`)
  9. Collection (`TA0009`)
  10. Exfiltration (`TA0010`)
  11. Impact (`TA0040`)
* **Scoring**: Compute Coverage Density $C = \frac{|\{TA \mid \text{count}(TA) > 0\}|}{11}$. If $C < 0.50$ (less than 6 tactics covered), flag a **Critical MITRE ATT&CK Coverage Blind Spot**.

### 3.6. Negative Space 3: Core OT/SCADA & Banking Subnet Isolation
* **Principle**: Critical entity assets reside in dedicated operational subnets (e.g., Core Banking `10.100.0.0/16`, SCADA telemetry `10.200.0.0/16`, SWIFT DMZ `192.168.50.0/24`).
* **Algorithm**: Parse source/target IP subnets from alert telemetry. Match against the entity's registered critical CIDR blocks. If a registered core operational subnet generates zero alerts over the audit window, flag **Critical Infrastructure Segment Telemetry Blackout**.

### 3.7. Regulatory Compliance: CERT-In 6-Hour Statutory Breach SLA
* **Requirement**: Indian Computer Emergency Response Team (CERT-In) Cyber Security Directions 2022 mandate mandatory incident reporting to CERT-In within **6 hours** of becoming aware.
* **Algorithm**:
  For all alerts with severity `HIGH` or `CRITICAL` that culminated in confirmed security incidents:
  $$\Delta t_{\text{report}} = t_{\text{escalated/reported}} - t_{\text{detected}}$$
  If $\Delta t_{\text{report}} > 21,600\text{ seconds}$ (6 hours), record a **Statutory SLA Breach Finding** with non-compliance latency, affected asset, and legal citation under Section 70B(6).

### 3.8. Forensic Integrity: Cryptographic Merkle Audit Tree
* **Principle**: To prevent post-audit tampering by entities or compromised examiners, all telemetry events and findings are sealed into a cryptographic Merkle tree.
* **Specification**:
  * Leaf node $L_i = \text{SHA-256}(\text{record\_id} \parallel \text{timestamp} \parallel \text{payload\_digest})$.
  * Parent node $P = \text{SHA-256}(L_{\text{left}} \parallel L_{\text{right}})$.
  * Root hash $R = \text{MerkleRoot}$ is recorded in the `audit_ledger` alongside timestamp and total leaf count.
  * Every generated finding includes a cryptographic verification proof string ensuring audit trail immutability.

---

## 4. Data Models & SQLite Schema Enhancements

The SQLite database (`satsa_tauri.db`) is structured to store raw telemetry, relational metadata, and supervisory analytics results:

```sql
-- Core Entity Registry
CREATE TABLE IF NOT EXISTS entities (
    entity_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    sector TEXT NOT NULL,
    total_assets INTEGER NOT NULL,
    critical_subnets TEXT -- JSON array of CIDRs e.g. ["10.100.0.0/16", "10.200.0.0/16"]
);

-- Alert Telemetry
CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    entity_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    subnet TEXT,
    rule_name TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    mitre_tactic TEXT, -- TA0001 .. TA0040
    mitre_technique TEXT, -- T1059, etc.
    timestamp TEXT NOT NULL,
    raw_payload TEXT,
    FOREIGN KEY(entity_id) REFERENCES entities(entity_id)
);

-- Investigation Cases
CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    investigator_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    closed_at TEXT,
    duration_seconds REAL,
    status TEXT NOT NULL,
    escalated INTEGER NOT NULL DEFAULT 0,
    escalated_at TEXT,
    resolution_notes TEXT,
    disposition TEXT,
    FOREIGN KEY(alert_id) REFERENCES alerts(alert_id),
    FOREIGN KEY(entity_id) REFERENCES entities(entity_id)
);

-- Findings Registry
CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    entity_id TEXT NOT NULL,
    finding_type TEXT NOT NULL, -- 'EXECUTION_GAP' | 'NEGATIVE_SPACE' | 'REGULATORY_BREACH'
    rule_code TEXT NOT NULL, -- 'BENFORD_DURATION_ANOMALY', 'MINHASH_NOTE_COLLUSION', 'CERTIN_6HR_BREACH', etc.
    title TEXT NOT NULL,
    severity TEXT NOT NULL, -- 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL'
    confidence REAL NOT NULL,
    description TEXT NOT NULL,
    explainability_notes TEXT,
    supporting_evidence TEXT, -- JSON
    created_at TEXT NOT NULL,
    FOREIGN KEY(entity_id) REFERENCES entities(entity_id)
);

-- Merkle Audit Ledger
CREATE TABLE IF NOT EXISTS audit_ledger (
    batch_id TEXT PRIMARY KEY,
    merkle_root TEXT NOT NULL,
    leaf_count INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    sealed_by TEXT NOT NULL
);
```

---

## 5. User Interface & Examiner Experience

### 5.1. Navigation & Viewport Hierarchy
* **Top Navigation Bar**: National emblem / NCIIPC badge, entity quick-switcher, global supervisory status, air-gapped status indicator, and cryptographic Merkle verification seal.
* **Tab 1: Executive Command Center**:
  * Composite Supervisory Risk Score card (0–100) with dynamic gauge and severity badge (`LOW`, `MODERATE`, `HIGH`, `CRITICAL`).
  * Cross-CSE Peer Risk Benchmark table with normalized Z-Scores.
  * Executive Alert Distribution & Ingestion Metrics.
* **Tab 2: Execution Gap Inspector**:
  * **Benford's Law Inspector**: Visual bar chart comparing actual first-digit duration distribution against Benford's theoretical curve with $\chi^2$ statistic and $p$-value.
  * **Shift-End Dumping & Burst Radar**: Temporal scatter plot highlighting high-velocity ticket closure clusters.
  * **MinHash Note Collusion Gallery**: Interactive card deck displaying identified duplicate resolution clusters, similarity percentages, and investigator IDs.
  * **Unescalated Critical Alert Audit**: Detailed table of suppressed incidents.
* **Tab 3: Negative Space & Blind Spot Matrix**:
  * **MITRE ATT&CK Tactical Heatmap**: High-density interactive matrix showing observed alerts vs. blind spots across all 11 enterprise tactics.
  * **Shannon Entropy Gauge**: Real-time entropy indicator flagging category diversity collapse.
  * **Critical Subnet Isolation Radar**: Network CIDR visualizer showing operational subnets with zero telemetry.
* **Tab 4: Statutory Compliance & Evidentiary Vault**:
  * **CERT-In 6-Hour Reporting Compliance**: Latency histogram and violation table citing Section 70B breaches.
  * **Merkle Chain of Custody Card**: Real-time Merkle root display with one-click cryptographic verification.
  * **Export Pavilion**: One-click generation of the official NCIIPC Supervisory Audit Report (HTML/PDF) and the Statutory JSON Examination Package.

---

## 6. Verification & Quality Assurance Strategy

1. **Rust Backend Test Suite (`cargo test`)**:
   * Mathematical unit tests for Benford's Law ($\chi^2$ calculation with known synthetic uniform vs. logarithmic distributions).
   * Shannon Entropy unit tests ($H(X)$ with maximum entropy vs. zero-entropy inputs).
   * MinHash Jaccard similarity tests with known 3-gram text overlaps.
   * Merkle Tree integrity test (leaf ordering, root derivation, tampering detection).
   * CERT-In 6-hour SLA threshold validation tests.
2. **Frontend Production Build Verification**:
   * TypeScript compiler check (`tsc --noEmit`) with zero errors.
   * Vite bundle generation (`npm run build`).
3. **End-to-End Synthetic & Real-World Dataset Run**:
   * Ingest and evaluate `real_soc_data_powergrid.csv`, `real_soc_data_bank.csv`, and `real_soc_data_telecom.csv`.
   * Verify all supervisory detectors flag anticipated findings and generate the cryptographic Merkle root.

---

## 7. Delivery Milestones

1. **Phase 1: Rust Backend SOTA Analytics**:
   - Implement Benford's Law $\chi^2$ and burst-closure algorithms in `execution_gaps.rs`.
   - Implement Shannon entropy and MITRE ATT&CK matrix mapping in `negative_space.rs`.
   - Implement MinHash LSH and CERT-In 6-Hour verifier in a new `forensics.rs` / `models.rs`.
   - Implement Merkle tree generator in `reporting/exporter.rs` and `db.rs`.
2. **Phase 2: Data Models & IPC Expansion**:
   - Extend Tauri IPC commands in `commands.rs` and `models.rs` to expose Benford curves, MITRE matrix data, and Merkle proofs.
3. **Phase 3: Frontend Executive Command Center**:
   - Update `types/api.ts` and `tauriApi.ts`.
   - Build `BenfordChart.tsx`, `MitreHeatmap.tsx`, `BurstDumpRadar.tsx`, and `MerkleSeal.tsx`.
   - Revamp `ExecutionGapsPanel.tsx`, `NegativeSpacePanel.tsx`, and `PeerBenchmarkPanel.tsx`.
4. **Phase 4: Official Audit Exporters & Verification**:
   - Upgrade NCIIPC PDF/HTML report template with cryptographic verification seals and MITRE coverage diagrams.
   - Run end-to-end integration and compile tests.
