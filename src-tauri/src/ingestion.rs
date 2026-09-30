use crate::models::{Alert, Case, Entity, IngestionBatchRequest, IngestionResponse};
use chrono::Utc;
use rusqlite::{params, Connection, Result};

pub fn save_batch(conn: &Connection, batch: &IngestionBatchRequest) -> Result<IngestionResponse> {
    let mut total_entities = 0;
    let mut total_alerts = 0;
    let mut total_cases = 0;

    // 1. Save Entities
    for e in &batch.entities {
        conn.execute(
            "INSERT OR REPLACE INTO entities (entity_id, name, sector, total_assets) VALUES (?1, ?2, ?3, ?4)",
            params![e.entity_id, e.name, e.sector, e.total_assets],
        )?;
        total_entities += 1;
    }

    // 2. Save Alerts
    for a in &batch.alerts {
        let payload_str = a.raw_payload.as_ref().map(|v| v.to_string());
        conn.execute(
            "INSERT OR REPLACE INTO alerts (alert_id, entity_id, asset_id, subnet, rule_name, category, severity, timestamp, mitre_tactic, mitre_technique, raw_payload)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                a.alert_id,
                a.entity_id,
                a.asset_id,
                a.subnet,
                a.rule_name,
                a.category,
                a.severity,
                a.timestamp,
                a.mitre_tactic,
                a.mitre_technique,
                payload_str
            ],
        )?;
        total_alerts += 1;
    }

    // 3. Save Cases
    for c in &batch.cases {
        let escalated_int = if c.escalated { 1 } else { 0 };
        conn.execute(
            "INSERT OR REPLACE INTO cases (case_id, alert_id, entity_id, investigator_id, created_at, closed_at, duration_seconds, status, escalated, escalated_at, resolution_notes, disposition)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                c.case_id,
                c.alert_id,
                c.entity_id,
                c.investigator_id,
                c.created_at,
                c.closed_at,
                c.duration_seconds,
                c.status,
                escalated_int,
                c.escalated_at,
                c.resolution_notes,
                c.disposition
            ],
        )?;
        total_cases += 1;
    }

    Ok(IngestionResponse {
        status: "SUCCESS".to_string(),
        total_entities_ingested: total_entities,
        total_alerts_ingested: total_alerts,
        total_cases_ingested: total_cases,
        message: "Batch SOC data ingested and indexed into SQLite database successfully.".to_string(),
    })
}

pub fn ingest_csv_content(conn: &Connection, csv_data: &str) -> Result<IngestionResponse, String> {
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_reader(csv_data.as_bytes());

    // Map column header names (case-insensitive) to their column index
    let header_map: std::collections::HashMap<String, usize> = match rdr.headers() {
        Ok(headers) => headers
            .iter()
            .enumerate()
            .map(|(idx, h)| (h.trim().to_lowercase(), idx))
            .collect(),
        Err(_) => std::collections::HashMap::new(),
    };

    let get_field = |record: &csv::StringRecord, names: &[&str], fallback_idx: usize| -> Option<String> {
        for &name in names {
            if let Some(&idx) = header_map.get(name) {
                if let Some(val) = record.get(idx) {
                    let trimmed = val.trim();
                    if !trimmed.is_empty() {
                        return Some(trimmed.to_string());
                    }
                }
            }
        }
        record.get(fallback_idx).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
    };

    let mut entities_map = std::collections::HashMap::new();
    let mut alerts = Vec::new();
    let mut cases = Vec::new();

    for result in rdr.records() {
        let record = result.map_err(|e| format!("CSV Parse Error: {}", e))?;

        let entity_id = get_field(&record, &["entity_id"], 0).unwrap_or_else(|| "CSE-UNKNOWN".to_string());
        let entity_name = get_field(&record, &["entity_name", "name"], 1).unwrap_or_else(|| "Unknown Entity".to_string());
        let sector = get_field(&record, &["sector"], 2).unwrap_or_else(|| "Critical Infrastructure".to_string());
        let total_assets: u32 = get_field(&record, &["total_assets", "assets"], 3)
            .and_then(|s| s.parse().ok())
            .unwrap_or(100);

        entities_map.insert(
            entity_id.clone(),
            Entity {
                entity_id: entity_id.clone(),
                name: entity_name,
                sector,
                total_assets,
            },
        );

        let alert_id = get_field(&record, &["alert_id"], 4).unwrap_or_else(|| "ALT-000".to_string());
        let asset_id = get_field(&record, &["asset_id"], 5).unwrap_or_else(|| "AST-000".to_string());
        let subnet = get_field(&record, &["subnet"], 6);
        let rule_name = get_field(&record, &["rule_name"], 7).unwrap_or_else(|| "Generic_Rule".to_string());
        let category = get_field(&record, &["category"], 8).unwrap_or_else(|| "POLICY_VIOLATION".to_string());
        let severity = get_field(&record, &["severity"], 9).unwrap_or_else(|| "MODERATE".to_string());
        let timestamp = get_field(&record, &["timestamp", "time"], 10).unwrap_or_else(|| "2026-09-01T00:00:00Z".to_string());

        let mitre_tactic = get_field(&record, &["mitre_tactic", "tactic"], 20);
        let mitre_technique = get_field(&record, &["mitre_technique", "technique"], 21);

        alerts.push(Alert {
            alert_id: alert_id.clone(),
            entity_id: entity_id.clone(),
            asset_id,
            subnet,
            rule_name,
            category,
            severity,
            timestamp,
            mitre_tactic,
            mitre_technique,
            raw_payload: None,
        });

        if let Some(case_id) = get_field(&record, &["case_id"], 11) {
            let investigator_id = get_field(&record, &["investigator_id", "analyst_id"], 12).unwrap_or_else(|| "INV-001".to_string());
            let created_at = get_field(&record, &["created_at"], 13).unwrap_or_else(|| "2026-09-01T00:00:00Z".to_string());
            let closed_at = get_field(&record, &["closed_at"], 14);
            let duration_seconds: Option<f64> = get_field(&record, &["duration_seconds", "duration"], 15)
                .and_then(|s| s.parse().ok());
            let status = get_field(&record, &["status"], 16).unwrap_or_else(|| "CLOSED".to_string());
            let escalated_str = get_field(&record, &["escalated"], 17).unwrap_or_else(|| "false".to_string());
            let escalated = escalated_str.to_lowercase() == "true" || escalated_str == "1";
            let resolution_notes = get_field(&record, &["resolution_notes", "notes"], 18);
            let disposition = get_field(&record, &["disposition"], 19);
            let escalated_at = get_field(&record, &["escalated_at"], 22);

            cases.push(Case {
                case_id,
                alert_id,
                entity_id,
                investigator_id,
                created_at,
                closed_at,
                duration_seconds,
                status,
                escalated,
                escalated_at,
                resolution_notes,
                disposition,
            });
        }
    }

    let batch = IngestionBatchRequest {
        entities: entities_map.into_values().collect(),
        alerts,
        cases,
    };

    save_batch(conn, &batch).map_err(|e| e.to_string())
}

pub fn generate_benchmark_cses() -> IngestionBatchRequest {
    let now = Utc::now();

    let entities = vec![
        Entity {
            entity_id: "CSE-POWERGRID".to_string(),
            name: "National Power Transmission Grid Corp".to_string(),
            sector: "Energy & Power".to_string(),
            total_assets: 450,
        },
        Entity {
            entity_id: "CSE-NATBANK".to_string(),
            name: "National Financial Infrastructure Bank".to_string(),
            sector: "Banking & Finance".to_string(),
            total_assets: 600,
        },
        Entity {
            entity_id: "CSE-TELECOM".to_string(),
            name: "Bharat National Telecom Infrastructure".to_string(),
            sector: "Telecommunications".to_string(),
            total_assets: 500,
        },
    ];

    let mut alerts = Vec::new();
    let mut cases = Vec::new();

    // ---------------------------------------------------------
    // GENERATE DATA FOR CSE-POWERGRID (Execution Gaps)
    // ---------------------------------------------------------
    let copy_paste_notes = [
        "Reviewed alert details against standard SOC operating procedure. Closed as false positive with no further action required.",
        "Reviewed alert details against standard SOC operating procedure. Closed as false positive with no further action required.",
        "Alert verified by analyst. Determined to be benign network noise. Ticket closed per SOP.",
        "Reviewed alert details against standard SOC operating procedure. Closed as false positive with no further action required.",
        "Alert verified by analyst. Determined to be benign network noise. Ticket closed per SOP.",
    ];

    for i in 1..=40i64 {
        let alert_id = format!("ALT-PG-{:03}", i);
        let case_id = format!("CAS-PG-{:03}", i);
        let asset_id = format!("AST-PG-GRID-{:02}", (i % 5) + 1);
        let severity = if i % 3 == 0 { "CRITICAL" } else if i % 2 == 0 { "HIGH" } else { "MODERATE" };
        let category = if i % 4 == 0 { "MALWARE" } else if i % 3 == 0 { "UNAUTHORIZED_ACCESS" } else { "POLICY_VIOLATION" };

        let alert_time = now - chrono::Duration::hours(i * 6);
        let is_fast = i % 2 == 0;
        let is_burst = i <= 6;
        let inv_id = if is_burst {
            "INV-PG-101".to_string()
        } else {
            format!("INV-PG-10{}", (i % 3) + 1)
        };
        let duration_sec = if is_fast { 28.5 } else if is_burst { 45.0 } else { 1450.0 };
        let closed_time = if is_burst {
            now - chrono::Duration::minutes(10) + chrono::Duration::seconds(i * 30)
        } else {
            alert_time + chrono::Duration::seconds(duration_sec as i64)
        };

        let notes = if i % 3 != 0 {
            copy_paste_notes[i as usize % copy_paste_notes.len()].to_string()
        } else {
            format!("Analyst investigated alert {} on asset {} manually.", alert_id, asset_id)
        };

        let escalated = if (severity == "HIGH" || severity == "CRITICAL") && i % 2 == 0 {
            false // Execution gap: unescalated critical
        } else {
            i % 5 == 0
        };

        let escalated_at = if escalated {
            Some((alert_time + chrono::Duration::hours(8)).to_rfc3339()) // 8 hours > 6-hour CERT-In statutory SLA
        } else {
            None
        };

        alerts.push(Alert {
            alert_id: alert_id.clone(),
            entity_id: "CSE-POWERGRID".to_string(),
            asset_id,
            subnet: Some("10.10.0.0/16".to_string()),
            rule_name: format!("Rule_{}", category),
            category: category.to_string(),
            severity: severity.to_string(),
            timestamp: alert_time.to_rfc3339(),
            mitre_tactic: Some(if category == "MALWARE" { "TA0002".to_string() } else if category == "UNAUTHORIZED_ACCESS" { "TA0001".to_string() } else { "TA0005".to_string() }),
            mitre_technique: Some("T1059".to_string()),
            raw_payload: Some(serde_json::json!({"src_ip": format!("192.168.1.{}", i)})),
        });

        cases.push(Case {
            case_id,
            alert_id,
            entity_id: "CSE-POWERGRID".to_string(),
            investigator_id: inv_id,
            created_at: alert_time.to_rfc3339(),
            closed_at: Some(closed_time.to_rfc3339()),
            duration_seconds: Some(duration_sec),
            status: "CLOSED".to_string(),
            escalated,
            escalated_at,
            resolution_notes: Some(notes),
            disposition: Some(if is_fast { "FALSE_POSITIVE" } else { "RESOLVED" }.to_string()),
        });
    }

    // ---------------------------------------------------------
    // GENERATE DATA FOR CSE-NATBANK (Negative Space)
    // ---------------------------------------------------------
    for i in 1..=20i64 {
        let alert_id = format!("ALT-NB-{:03}", i);
        let case_id = format!("CAS-NB-{:03}", i);
        let asset_id = format!("AST-NB-WEB-{:02}", i);
        let severity = if i % 2 == 0 { "LOW" } else { "MODERATE" };
        let category = if i % 2 == 0 { "PHISHING" } else { "POLICY_VIOLATION" };

        let alert_time = now - chrono::Duration::hours(i * 12);
        let duration_sec = 2400.0;
        let closed_time = alert_time + chrono::Duration::seconds(duration_sec as i64);

        alerts.push(Alert {
            alert_id: alert_id.clone(),
            entity_id: "CSE-NATBANK".to_string(),
            asset_id: asset_id.clone(),
            subnet: Some("10.100.0.0/16".to_string()), // Core Subnet 10.200.0.0/16 is MISSING!
            rule_name: format!("Rule_{}", category),
            category: category.to_string(),
            severity: severity.to_string(),
            timestamp: alert_time.to_rfc3339(),
            mitre_tactic: Some("TA0001".to_string()),
            mitre_technique: Some("T1566".to_string()),
            raw_payload: Some(serde_json::json!({"src_ip": format!("172.16.2.{}", i)})),
        });

        cases.push(Case {
            case_id,
            alert_id,
            entity_id: "CSE-NATBANK".to_string(),
            investigator_id: format!("INV-NB-20{}", (i % 3) + 1),
            created_at: alert_time.to_rfc3339(),
            closed_at: Some(closed_time.to_rfc3339()),
            duration_seconds: Some(duration_sec),
            status: "CLOSED".to_string(),
            escalated: false,
            escalated_at: None,
            resolution_notes: Some(format!("Inspected web traffic log for {}. Confirmed routine scanner activity.", asset_id)),
            disposition: Some("FALSE_POSITIVE".to_string()),
        });
    }

    // ---------------------------------------------------------
    // GENERATE DATA FOR CSE-TELECOM (Baseline / Well-Governed)
    // ---------------------------------------------------------
    let tc_categories = ["MALWARE", "RANSOMWARE", "EXFILTRATION", "PRIVILEGE_ESCALATION", "COMMAND_AND_CONTROL", "CREDENTIAL_DUMP"];
    let tc_subnets = ["10.50.0.0/16", "10.51.0.0/16", "10.52.0.0/16"];

    // 45 natural durations adhering strictly to Benford's Law distribution (df=8, p > 0.90)
    let natural_durations = [
        1120.0, 1250.0, 1340.0, 1490.0, 1620.0, 1780.0, 1890.0, 1950.0, 1080.0, 1150.0, 1280.0, 1420.0, 1550.0, 1690.0,
        2100.0, 2300.0, 2450.0, 2600.0, 2750.0, 2890.0, 2920.0, 2200.0,
        3100.0, 3350.0, 3500.0, 3720.0, 3890.0, 3200.0,
        4150.0, 4300.0, 4600.0, 4850.0,
        5100.0, 5400.0, 5800.0,
        6200.0, 6500.0, 6900.0,
        7200.0, 7600.0,
        8100.0, 8500.0,
        9200.0, 9700.0, 9400.0,
    ];

    let unique_telecom_notes = [
        "Analyzed network capture from core router. Identified anomalous outbound traffic to external C2. Terminated connection and updated firewall rules.",
        "Memory dump acquired and analyzed using Volatility. Found injected DLL in explorer.exe. Quarantined infected host AST-TC-CORE-01.",
        "Host-based firewall logs reveal multiple failed SSH authentication attempts from internal subnet. Isolated source machine and reset credentials.",
        "Reviewed endpoint telemetry. PowerShell executed with encoded command line invoking WebClient. Scanned disk, removed malicious dropper payload.",
        "SIEM alert correlated with threat intelligence feed. Domain flagged as active phishing campaign. Domain blacklisted across enterprise DNS resolvers.",
        "Database audit logs inspected. Abnormal query volume detected on customer records table. Blocked source IP and initiated privileged access review.",
        "Encrypted archive created in staging directory. Confirmed unauthorized attempt to stage data. Blocked user account and notified CISO incident response team.",
        "Rootkit scanner detected hidden kernel module. Re-imaged affected server from golden master and patched Linux kernel vulnerabilities.",
        "Active Directory audit showed unauthorized addition to Domain Admins group. Reverted group membership and initiated credential revoking procedure.",
    ];

    for i in 1..=45i64 {
        let alert_id = format!("ALT-TC-{:03}", i);
        let case_id = format!("CAS-TC-{:03}", i);
        let asset_id = format!("AST-TC-CORE-{:02}", i);
        let severity = if i % 4 == 0 { "CRITICAL" } else if i % 3 == 0 { "HIGH" } else { "MODERATE" };
        let category = tc_categories[i as usize % tc_categories.len()];
        let subnet = tc_subnets[i as usize % tc_subnets.len()];

        let alert_time = now - chrono::Duration::hours(i * 5);
        let duration_sec = natural_durations[(i as usize - 1) % natural_durations.len()];
        let closed_time = alert_time + chrono::Duration::seconds(duration_sec as i64);
        let escalated = severity == "HIGH" || severity == "CRITICAL";
        let escalated_at = if escalated {
            Some((alert_time + chrono::Duration::minutes(45)).to_rfc3339()) // 45 mins well within 6-hour SLA
        } else {
            None
        };

        let tactic = match category {
            "MALWARE" => "TA0002",
            "RANSOMWARE" => "TA0040",
            "EXFILTRATION" => "TA0010",
            "PRIVILEGE_ESCALATION" => "TA0004",
            "COMMAND_AND_CONTROL" => "TA0011",
            "CREDENTIAL_DUMP" => "TA0006",
            _ => "TA0001",
        };

        alerts.push(Alert {
            alert_id: alert_id.clone(),
            entity_id: "CSE-TELECOM".to_string(),
            asset_id: asset_id.clone(),
            subnet: Some(subnet.to_string()),
            rule_name: format!("Rule_{}", category),
            category: category.to_string(),
            severity: severity.to_string(),
            timestamp: alert_time.to_rfc3339(),
            mitre_tactic: Some(tactic.to_string()),
            mitre_technique: Some("T1059.001".to_string()),
            raw_payload: Some(serde_json::json!({"src_ip": format!("10.50.1.{}", i)})),
        });

        let note = format!("{} [Case Reference: TC-{:04}]", unique_telecom_notes[(i as usize - 1) % unique_telecom_notes.len()], i);

        cases.push(Case {
            case_id,
            alert_id,
            entity_id: "CSE-TELECOM".to_string(),
            investigator_id: format!("INV-TC-30{}", (i % 4) + 1),
            created_at: alert_time.to_rfc3339(),
            closed_at: Some(closed_time.to_rfc3339()),
            duration_seconds: Some(duration_sec),
            status: "CLOSED".to_string(),
            escalated,
            escalated_at,
            resolution_notes: Some(note),
            disposition: Some(if escalated { "TRUE_POSITIVE" } else { "BENIGN" }.to_string()),
        });
    }

    IngestionBatchRequest { entities, alerts, cases }
}
