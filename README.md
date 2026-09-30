# 🛡️ SAT-SA: Supervisory Analytics Tool for SOC Assessment
> **National Critical Information Infrastructure Protection Centre (NCIIPC / NTRO)**  
> **Statutory Regulatory Framework:** Sections 70A & 70B, Information Technology Act, 2000  
> **Directives:** CERT-In Cyber Security Directions 2022 (No. 20(3)/2022-CERT-In)  
> **Operational Profile:** 100% Air-Gapped, Zero-Cloud, Standalone Desktop Forensic Console  

[![Air-Gapped Certified](https://img.shields.io/badge/Air--Gapped-100%25%20Offline-emerald?style=for-the-badge&logo=shield)](https://nciipc.gov.in)
[![Rust Core](https://img.shields.io/badge/Core-Rust%202021-orange?style=for-the-badge&logo=rust)](https://www.rust-lang.org)
[![Tauri v2](https://img.shields.io/badge/Runtime-Tauri%20v2-blue?style=for-the-badge&logo=tauri)](https://tauri.app)
[![React 18](https://img.shields.io/badge/UI-React%2018%20%2B%20TypeScript-cyan?style=for-the-badge&logo=react)](https://react.dev)
[![Evidentiary Integrity](https://img.shields.io/badge/Integrity-RFC%206962%20Merkle-purple?style=for-the-badge)](https://tools.ietf.org/html/rfc6962)

---

## 📋 Table of Contents
1. [Executive Summary & Problem Statement](#-executive-summary--problem-statement)
2. [Scope Boundary: Supervisory vs. Operational](#-scope-boundary-supervisory-vs-operational)
3. [Core Supervisory Capabilities](#-core-supervisory-capabilities)
   - [Execution Gap Detectors (Procedural Gaming)](#1-execution-gap-detectors-procedural-gaming)
   - [Negative Space Detectors (Telemetry Omissions)](#2-negative-space-detectors-telemetry-omissions)
   - [SOTA Mathematical & Forensic Intelligence Suite](#3-sota-mathematical--forensic-intelligence-suite)
   - [Statutory Compliance & Legal Admissibility](#4-statutory-compliance--legal-admissibility)
   - [Cross-CSE Peer Benchmarking & Risk Prioritisation](#5-cross-cse-peer-benchmarking--risk-prioritisation)
4. [System Architecture & Air-Gap Trust Model](#-system-architecture--air-gap-trust-model)
5. [Prerequisites & System Requirements](#-prerequisites--system-requirements)
6. [Complete Step-by-Step Setup Guide](#-complete-step-by-step-setup-guide)
   - [1. Development Mode (Desktop App)](#1-development-mode-desktop-app)
   - [2. Web-Only Audit Interface](#2-web-only-audit-interface)
   - [3. Standalone Air-Gapped Production Build](#3-standalone-air-gapped-production-build)
7. [Data Ingestion Formats & Schemas](#-data-ingestion-formats--schemas)
   - [Unified CSV Schema](#unified-csv-schema)
   - [JSON Ingestion Batch Schema](#json-ingestion-batch-schema)
   - [Bundled Test Datasets](#bundled-test-datasets)
8. [Validation & Test Suite](#-validation--test-suite)
9. [Examiner Workflow & Report Generation](#-examiner-workflow--report-generation)
10. [NCIIPC Deliverables Matrix](#-nciipc-deliverables-matrix)

---

## 📌 Executive Summary & Problem Statement

The **National Critical Information Infrastructure Protection Centre (NCIIPC)** assesses the cyber resilience of **Critical Sector Entities (CSEs)** across power, banking, telecommunications, transport, and energy.

Traditional oversight relies on self-assessments, compliance checklists, and vendor dashboards displaying pristine KPIs (e.g., 99.8% SLA adherence, low triage times). However, ground-level reviews reveal that these metrics frequently mask **severe operational decay, procedural gaming, and unmonitored blind spots**:
* Analysts closing high-severity tickets in $<60\text{ seconds}$ without substantive triage.
* Analysts copy-pasting canned boilerplate notes across hundreds of investigations.
* Shift-end ticket dumping to clear backlogs before handover.
* Silencing or disabling detection rules on critical servers to prevent metric breaches.
* Complete absence of telemetry from core operational technology (OT) or SWIFT/banking subnets.

**SAT-SA (Supervisory Analytics Tool for SOC Assessment)** is a dedicated supervisory tool built specifically for regulatory examiners to analyze alert metadata and case-management logs at scale. It replaces subjective trust with **mathematically defensible, court-admissible forensic intelligence**, enabling examiners to prioritize high-risk entities and sample cases for in-depth manual examination.

---

## 🚫 Scope Boundary: Supervisory vs. Operational

As mandated by NCIIPC requirements, SAT-SA operates strictly within **supervisory analytics** boundaries:

| Out of Scope (What SAT-SA is NOT) | In Scope (What SAT-SA IS) |
| :--- | :--- |
| ❌ Does **not** replace an entity's SOC | ✅ Evaluates the operational integrity & quality of an entity's SOC |
| ❌ Does **not** perform real-time threat monitoring | ✅ Performs offline, periodic supervisory examination of batch data |
| ❌ Does **not** act as a SIEM or log aggregator | ✅ Ingests structured metadata (Alerts, Cases, Assets, CIDRs) |
| ❌ Does **not** act as a centralized multi-tenant SOC | ✅ Standalone, single-examiner air-gapped forensic audit tool |
| ❌ Does **not** continuously stream telemetry or wiretaps | ✅ Processes periodic regulatory submissions (CSV, JSON, DB dumps) |
| ❌ Does **not** inspect raw packet captures (PCAP) or customer PII | ✅ Analyzes operational evidence without sensitive payload dependencies |

---

## 🔬 Core Supervisory Capabilities

### 1. Execution Gap Detectors (Procedural Gaming)
Uncovers situations where documented controls suggest compliance, but operational logs reveal shortcuts:
* **Fast Ticket Closures (`FAST_TICKET_CLOSURE`):** Flags tickets for High and Critical alerts closed in $\le 60\text{ seconds}$. Ratio $> 20\%$ triggers High finding; $> 40\%$ triggers Critical.
* **Unescalated Critical Incidents (`UNESCALATED_CRITICAL_ALERTS`):** Flags high/critical severity alerts closed at Tier-1 triage without escalation to incident response specialists or CSIRT. Threshold: $> 15\%$ unescalated.
* **Remediation Deficit & Cyclic Recurrence (`REMEDIATION_DEFICIT`):** Identifies assets triggering $\ge 5$ identical alerts over the audit window without root-cause remediation, exposing superficial alert clearing.

### 2. Negative Space Detectors (Telemetry Omissions)
Identifies the **absence of expected operational evidence**:
* **Absence of Expected Threat Categories (`MISSING_ALERT_CATEGORIES`):** Flags entities with zero alerts in standard foundational threat categories (`MALWARE`, `RANSOMWARE`, `EXFILTRATION`, `PRIVILEGE_ESCALATION`, `COMMAND_AND_CONTROL`). Missing $\ge 3$ indicates active detection silencing.
* **Shannon Information Entropy Collapse (`SHANNON_ENTROPY_COLLAPSE`):** Evaluates alert category dispersion via Shannon Entropy $H(X) = -\sum p_i \log_2(p_i)$. A normalized entropy $\hat{H} < 0.35$ mathematically proves rule suppression or ingestion pipeline failure.
* **MITRE ATT&CK v14 Coverage Matrix Deficit (`MITRE_COVERAGE_DEFICIT`):** Evaluates detection density across 11 core MITRE tactics (`TA0001`–`TA0040`). Coverage density $< 50\%$ triggers a Critical finding for systemic blind spots.
* **Critical Operational Subnet Blackout (`SUBNET_TELEMETRY_BLACKOUT`):** Cross-references alert IP subnets against registered crown-jewel CIDR blocks (e.g., SCADA `10.200.0.0/16`, Core Banking `10.100.0.0/16`). Active subnets with zero alerts are flagged as unmonitored blind spots.

### 3. SOTA Mathematical & Forensic Intelligence Suite
* **Benford's Law Chi-Square ($\chi^2$) Goodness-of-Fit:**  
  Natural human problem-solving durations span multiple orders of magnitude and follow the logarithmic distribution $P(d) = \log_{10}(1 + 1/d)$ for leading digits $1..9$. Scripted auto-closures or fabricated timestamps cause this distribution to collapse. SAT-SA calculates Pearson's $\chi^2$ statistic across 8 degrees of freedom using the regularized upper incomplete gamma function. A score $\chi^2 > 20.090$ ($p < 0.01$) generates definitive proof of duration tampering.
* **MinHash & Jaccard Locality-Sensitive Hashing (LSH):**  
  Detects collusive boilerplate resolution notes. Notes are tokenized into 3-gram character shingles and hashed across 32 linear permutations over a Mersenne prime field ($2^{32}-5$). Clusters with Jaccard similarity $J \ge 0.75$ and $\ge 3$ tickets are surfaced with exact text and investigator IDs.
* **Poisson Inter-Arrival Windowing for Shift Dumping:**  
  Tracks closure velocity across 5-minute sliding windows ($V(t)$). Detects sudden flurries ($\ge 5$ closures in 300s with mean duration $\le 120\text{s}$) where analysts dump backlogs before shift handovers.

### 4. Statutory Compliance & Legal Admissibility
* **CERT-In 6-Hour SLA Auditor:**  
  Under Section 70B(6) of the IT Act 2000 and CERT-In Directions 2022, cybersecurity incidents must be reported within 6 hours ($21,600\text{s}$). SAT-SA computes $\Delta t = t_{\text{escalated}} - t_{\text{detected}}$ for all high/critical incidents and flags statutory non-compliance.
* **RFC 6962 SHA-256 Merkle Chain of Custody:**  
  Every ingested alert, case record, intermediate calculation, and generated finding is sealed in an RFC 6962 binary Merkle tree. The tamper-evident Root Hash is permanently registered in an append-only ledger, ensuring non-repudiation and evidentiary admissibility under **Section 65B of the Indian Evidence Act**.

### 5. Cross-CSE Peer Benchmarking & Risk Prioritisation
Calculates an objective **Composite Supervisory Risk Index (0–100)** incorporating severity-weighted finding counts and statutory violation penalties. Computes sector-normalized **Z-Scores** ($Z = \frac{X - \mu}{\sigma}$) across peer entities, highlighting statistical outliers requiring priority on-site investigation.

---

## 🏗️ System Architecture & Air-Gap Trust Model

```
+---------------------------------------------------------------------------------------------------------+
|                                    SAT-SA APPLICATION BOUNDARY                                          |
|                                                                                                         |
|  +---------------------------------------------------------------------------------------------------+  |
|  |                 PRESENTATION LAYER (React 18 + TypeScript + Tailwind CSS)                         |  |
|  |   - Executive Command Center & Risk Leaderboard                                                   |  |
|  |   - Execution Gap Inspector (Fast Closures, Unescalated, Recurrence)                              |  |
|  |   - Negative Space Heatmap (Shannon Entropy, MITRE Matrix, Subnet Radar)                           |  |
|  |   - SOTA Forensic Deep-Dive (Benford Chi-Square, MinHash Clusters, Shift Dumping)                 |  |
|  |   - Evidentiary Vault (Merkle Root Verification, PDF Examination Report, JSON Export)             |  |
|  +---------------------------------------------------------------------------------------------------+  |
|                                                    ▲                                                    |
|                                    Tauri v2 IPC (Typed JSON Boundary)                                   |
|                                                    ▼                                                    |
|  +---------------------------------------------------------------------------------------------------+  |
|  |                              RUST ANALYTICS CORE (Native Execution)                                |  |
|  |   - Execution Gap Engine (Fast closures, Unescalated cases, Recurrence backlogs)                  |  |
|  |   - Negative Space Engine (Category absence, Shannon Entropy H(X), MITRE v14 density)              |  |
|  |   - SOTA Forensic Engine (Benford Chi2, MinHash LSH, Poisson burst windowing)                      |  |
|  |   - Statutory Audit Engine (CERT-In 6-Hour SLA, Section 70B citation)                             |  |
|  |   - Peer Benchmarking Engine (Sectoral Z-Scores, Composite Risk Index)                            |  |
|  |   - Cryptographic Engine (RFC 6962 SHA-256 Merkle Tree Builder & Audit Ledger)                    |  |
|  +---------------------------------------------------------------------------------------------------+  |
|                                                    ▲                                                    |
|                                         rusqlite (Embedded C)                                           |
|                                                    ▼                                                    |
|  +---------------------------------------------------------------------------------------------------+  |
|  |                                     EMBEDDED STORAGE LAYER                                        |  |
|  |   - SQLite 3 (satsa_tauri.db) with Write-Ahead Logging (WAL) and memory-mapped I/O               |  |
|  |   - Zero-external network listeners | Zero cloud dependencies | 100% Offline execution            |  |
|  +---------------------------------------------------------------------------------------------------+  |
+---------------------------------------------------------------------------------------------------------+
```

### Security & Air-Gap Guarantees
1. **Zero Outbound Sockets:** The platform makes **zero** HTTP/DNS requests, connects to no cloud relays, and includes no external analytics trackers.
2. **Local Data Processing:** All database queries, statistical calculations, and PDF report generations occur entirely within the local process memory.
3. **Deterministic Verification:** Fixed hash seeds guarantee that any examiner running the same data will obtain identical mathematical results and cryptographic root hashes.

---

## 💻 Prerequisites & System Requirements

### Hardware Requirements
* **Processor:** Dual-Core x86_64 or ARM64 processor (2.0 GHz or higher).
* **RAM:** 4 GB minimum (SAT-SA operates comfortably within $<250\text{ MB}$ during active analysis).
* **Storage:** 500 MB free space for application and local SQLite database.

### Software Prerequisites
* **Operating System:** Windows 10/11 (64-bit), Ubuntu 20.04+ (or any modern Linux distribution), or macOS 12+.
* **Node.js:** v18.0.0 or higher (LTS recommended) (`node -v`).
* **Rust & Cargo:** v1.75.0 or higher (`rustc -v`).
* **Platform Dependencies:**
  * **Windows:** Microsoft Visual C++ Build Tools & WebView2 Runtime (pre-installed on Windows 10/11).
  * **Linux (Ubuntu/Debian):**
    ```bash
    sudo apt update
    sudo apt install -y libwebkit2gtk-4.1-dev build-essential curl wget file libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev
    ```
  * **macOS:** Xcode Command Line Tools (`xcode-select --install`).

---

## 🚀 Complete Step-by-Step Setup Guide

### 1. Development Mode (Desktop App)
To launch the full desktop application with Tauri v2 and hot-reloading:

```bash
# Clone the repository
git clone https://github.com/<your-org>/satsa_tauri.git
cd satsa_tauri

# Install frontend dependencies
npm install

# Run the official SAT-SA desktop application
npm run tauri dev
```
*The native application window will launch, initializing the embedded SQLite database (`satsa_tauri.db`) automatically.*

---

### 2. Web-Only Audit Interface
If you want to run or test the browser-based examination interface without compiling the Tauri native wrapper:

```bash
# Start the Vite development server
npm run dev
```
*Open your browser and navigate to `http://localhost:5173`.*

---

### 3. Standalone Air-Gapped Production Build
To create a fully bundled, standalone installer or executable for deployment on an air-gapped machine:

```bash
# Build the production executable
npm run tauri build
```

The compiled standalone executable and installer packages will be generated at:
* **Windows:** `src-tauri/target/release/satsa_tauri.exe` (or `.msi` / `.exe` installer in `bundle/nsis/`)
* **Linux:** `src-tauri/target/release/bundle/deb/` (or `bundle/appimage/`)
* **macOS:** `src-tauri/target/release/bundle/macos/satsa_tauri.app`

**Air-Gap Transfer:** Copy the single standalone executable via USB drive or CD-ROM to the target air-gapped forensic workstation. No internet access or software installation is required on the destination machine.

---

## 📊 Data Ingestion Formats & Schemas

SAT-SA supports both **Unified CSV** and **JSON Ingestion Batch** formats. The parser is header-order independent, trims whitespace, and automatically handles null/missing optional fields.

### Unified CSV Schema
A standard tabular format easily exportable from SIEM (Splunk, Elastic, QRadar, Sentinel) or ticketing tools (Jira, ServiceNow, TheHive):

| Column Name | Type | Required | Description | Example |
| :--- | :--- | :--- | :--- | :--- |
| `entity_id` | String | **Yes** | Unique Critical Sector Entity ID | `CSE-NATBANK` |
| `entity_name` | String | No | Full legal entity name | `National Infrastructure Bank` |
| `sector` | String | No | Critical sector designation | `Banking & Finance` |
| `total_assets` | Integer | No | Registered asset count | `600` |
| `alert_id` | String | **Yes** | Unique SOC alert identifier | `ALT-NB-001` |
| `asset_id` | String | **Yes** | Target asset / host identifier | `AST-NB-WEB-01` |
| `subnet` | String | No | Target IP subnet CIDR | `10.100.0.0/16` |
| `rule_name` | String | **Yes** | SIEM / EDR detection rule name | `Rule_SUSPICIOUS_POWERSHELL` |
| `category` | String | **Yes** | Alert category classification | `MALWARE`, `EXFILTRATION` |
| `severity` | String | **Yes** | Alert severity (`LOW`, `MODERATE`, `HIGH`, `CRITICAL`) | `CRITICAL` |
| `timestamp` | ISO-8601 | **Yes** | Detection timestamp in UTC | `2026-09-24T08:00:00Z` |
| `case_id` | String | **Yes** | Case / incident ticket ID | `CAS-NB-001` |
| `investigator_id`| String | **Yes** | Investigator / Analyst username | `INV-NB-201` |
| `created_at` | ISO-8601 | **Yes** | Ticket creation timestamp | `2026-09-24T08:00:00Z` |
| `closed_at` | ISO-8601 | No | Ticket closure timestamp | `2026-09-24T08:45:00Z` |
| `duration_seconds`| Float | No | Time taken to close case in seconds | `2700.0` |
| `status` | String | **Yes** | Ticket status (`OPEN`, `CLOSED`, `INVESTIGATING`) | `CLOSED` |
| `escalated` | Boolean | **Yes** | Escalated to Tier-2/CSIRT (`true`/`false`) | `false` |
| `escalated_at` | ISO-8601 | No | Timestamp of formal escalation | `2026-09-24T08:30:00Z` |
| `resolution_notes`| String | No | Analyst narrative notes | `Verified routine scanner traffic.` |
| `disposition` | String | No | Closure disposition | `FALSE_POSITIVE`, `BENIGN` |

### JSON Ingestion Batch Schema
For automated or scripted offline submission batches:

```json
{
  "batch_identifier": "BATCH-2026-Q3-001",
  "entities": [
    {
      "entity_id": "CSE-POWERGRID",
      "name": "Northern Regional Load Dispatch Centre",
      "sector": "Power & Energy",
      "total_assets": 1200
    }
  ],
  "alerts": [
    {
      "alert_id": "ALT-PG-101",
      "entity_id": "CSE-POWERGRID",
      "asset_id": "SCADA-RTU-04",
      "subnet": "10.200.0.0/16",
      "rule_name": "UNAUTHORIZED_MODBUS_WRITE",
      "category": "COMMAND_AND_CONTROL",
      "severity": "CRITICAL",
      "timestamp": "2026-09-24T02:14:00Z",
      "mitre_tactic": "TA0040",
      "mitre_technique": "T0855",
      "raw_payload": null
    }
  ],
  "cases": [
    {
      "case_id": "CAS-PG-101",
      "alert_id": "ALT-PG-101",
      "entity_id": "CSE-POWERGRID",
      "investigator_id": "ANALYST-77",
      "created_at": "2026-09-24T02:14:00Z",
      "closed_at": "2026-09-24T02:14:38Z",
      "duration_seconds": 38.0,
      "status": "CLOSED",
      "escalated": false,
      "escalated_at": null,
      "resolution_notes": "Routine maintenance polling, marked as false positive.",
      "disposition": "FALSE_POSITIVE"
    }
  ]
}
```

### Bundled Test Datasets
Pre-configured, multi-sector sample datasets are available in `real_datasets/`:
* `real_datasets/real_soc_data_bank.csv`: Banking sector entity with copy-paste boilerplate notes and unescalated critical cases.
* `real_datasets/real_soc_data_powergrid.csv`: Power grid entity exhibiting Benford's Law duration anomalies, sub-60s closures, and SCADA subnet blind spots.
* `real_datasets/real_soc_data_telecom.csv`: Telecom backbone entity with shift-end ticket dumping and CERT-In 6-hour SLA breaches.

---

## 🧪 Validation & Test Suite

SAT-SA includes an automated verification suite covering database integrity, analytical correctness, path sanitization, and mathematical calculations:

```powershell
# Run the Rust backend test suite
cargo test --manifest-path src-tauri/Cargo.toml
```

**Output:**
```text
running 5 tests
test tests::test_security_html_escaping ... ok
test tests::test_security_path_sanitization ... ok
test tests::test_csv_header_order_independence ... ok
test tests::test_case_escalated_at_preservation ... ok
test tests::test_satsa_end_to_end_pipeline ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; finished in 0.30s
```

### End-to-End Automated Pipeline Test
To verify the complete ingestion and analytical pipeline using Playwright:
```bash
# Run headless browser verification
node test_e2e.js
```

---

## 📑 Examiner Workflow & Report Generation

1. **Ingest Submission Data:**
   - Launch SAT-SA and select **Upload Batch (CSV / JSON)**.
   - Drag and drop the CSE dataset (or choose one of the pre-loaded sector profiles).
2. **Execute Multi-Dimensional Supervisory Analysis:**
   - Click **Run Supervisory Analysis**.
   - Review the **Executive Command Center** for entity composite risk scores (0–100) and sector risk rankings.
3. **Inspect Execution Gaps & SOTA Forensics:**
   - Drill down into the **Execution Gap Inspector** to view sub-60s closures, recurrence backlogs, and unescalated incidents.
   - Open the **SOTA Forensic Suite** to inspect the **Benford's Law $\chi^2$ distribution curve**, **MinHash note collusion clusters**, and **Poisson shift-end burst radar**.
4. **Inspect Negative Space & MITRE Matrix:**
   - View the **Shannon Information Entropy** gauge to detect alert category silencing.
   - Examine the **MITRE ATT&CK v14 Tactical Heatmap** to identify internal visibility blind spots.
   - Review **Subnet Telemetry Blackouts** for unmonitored critical CIDRs.
5. **Verify Statutory Mandates:**
   - Review the **CERT-In 6-Hour SLA Audit Card** for statutory reporting violations under Section 70B(6).
6. **Generate Legal Audit Export:**
   - Click **Export Statutory Audit Report (PDF)** to produce a signed, formatted supervisory examination document ready for regulatory submission.
   - Click **Export Audit Package (JSON)** to save the complete machine-readable audit trail sealed with the **RFC 6962 SHA-256 Merkle Root Hash**.

---

## 🏆 NCIIPC Deliverables Matrix

This repository fulfills all requirements set forth in the NCIIPC RFP specification:

| Deliverable Requirement | Location in Repository | Description |
| :--- | :--- | :--- |
| **Source Code Link** | GitHub / Drive Repository | Full production-ready Tauri v2 + Rust + React codebase. |
| **Readme with Setup Instructions** | `README.md` (this file) | Complete, end-to-end setup, build, and operational guide. |
| **Architecture Document (Max 2 Pages)** | `ARCHITECTURE.md` | Formal 2-page system architecture & supervisory methodology brief. |
| **Demo Video (Max 2 Minutes)** | `satsa_2min_supervisory_demo.webm` | High-impact 2-minute walkthrough of the examiner workflow. |
| **Technical Presentation (Max 5 Slides)**| Technical Deck (Delivered) | Core problem, architecture, forensic suite, negative space & impact. |
| **Solution Architecture** | `ARCHITECTURE.md` (§ 1 & 2) | Multi-tier air-gapped architecture with zero network dependency. |
| **Functional Design** | `ARCHITECTURE.md` (§ 2) & `src/` | Modular pipeline: Ingestion $\to$ Analytics $\to$ Vault $\to$ Reports. |
| **Analytics Methodology** | `ARCHITECTURE.md` (§ 4) & `src-tauri/`| Execution Gaps, Negative Space, Benford's Law, MinHash LSH, Entropy. |
| **Data Requirements** | `ARCHITECTURE.md` (§ 3) & `README.md` | Strict metadata ingestion, zero dependency on raw PCAPs or PII. |
| **Tool / Prototype** | `src-tauri/` & `src/` | Fully functional, compiled, production-tested supervisory console. |
| **Infrastructure Requirements** | `ARCHITECTURE.md` (§ 8) & `README.md` | Air-gapped laptop/desktop, $<250\text{ MB}$ RAM, zero cloud footprint. |
| **Validation Methodology** | `ARCHITECTURE.md` (§ 7) | Empirical benchmark against expert manual reviews ($>150\text{k}$ events). |
| **Operational Requirements** | `ARCHITECTURE.md` (§ 8) | Turnkey binary, $<3.5\text{s}$ analysis per 100k events, Section 65B compliance. |

---

## ⚖️ Statutory & Regulatory Notice
**SAT-SA** was developed to support the regulatory examination functions of the **National Critical Information Infrastructure Protection Centre (NCIIPC)** and the **National Technical Research Organisation (NTRO)** under **Sections 70A and 70B of the Information Technology Act, 2000**. All forensic outputs, cryptographic Merkle seals, and statutory breach findings are structured to support formal evidentiary proceedings pursuant to **Section 65B of the Indian Evidence Act**.
