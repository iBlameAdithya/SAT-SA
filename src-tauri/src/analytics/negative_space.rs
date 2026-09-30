use crate::models::{
    Alert, CategoryFrequency, Entity, Finding, MitreAttackAnalysis, MitreTacticCoverage,
    ShannonEntropyAnalysis,
};
use chrono::Utc;
use rusqlite::{params, Connection, Result};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

pub fn analyze_negative_space(conn: &Connection, entity_id: &str) -> Result<Vec<Finding>> {
    // 1. Fetch Entity Info
    let mut stmt_ent = conn.prepare("SELECT entity_id, name, sector, total_assets FROM entities WHERE entity_id = ?1")?;
    let entity = stmt_ent.query_row(params![entity_id], |row| {
        Ok(Entity {
            entity_id: row.get(0)?,
            name: row.get(1)?,
            sector: row.get(2)?,
            total_assets: row.get(3)?,
        })
    }).ok();

    // 2. Fetch Alerts for Entity
    let mut stmt_alt = conn.prepare(
        "SELECT alert_id, entity_id, asset_id, subnet, rule_name, category, severity, timestamp, mitre_tactic, mitre_technique, raw_payload
         FROM alerts WHERE entity_id = ?1",
    )?;

    let alert_rows = stmt_alt.query_map(params![entity_id], |row| {
        let payload_str: Option<String> = row.get(10)?;
        let raw_payload = payload_str.and_then(|s| serde_json::from_str(&s).ok());
        Ok(Alert {
            alert_id: row.get(0)?,
            entity_id: row.get(1)?,
            asset_id: row.get(2)?,
            subnet: row.get(3)?,
            rule_name: row.get(4)?,
            category: row.get(5)?,
            severity: row.get(6)?,
            timestamp: row.get(7)?,
            mitre_tactic: row.get(8)?,
            mitre_technique: row.get(9)?,
            raw_payload,
        })
    })?;

    let mut alerts = Vec::new();
    for a in alert_rows {
        alerts.push(a?);
    }

    Ok(analyze_negative_space_with_data(entity_id, entity.as_ref(), &alerts, None, None))
}

pub fn analyze_negative_space_with_data(
    entity_id: &str,
    entity: Option<&Entity>,
    alerts: &[Alert],
    precomputed_entropy: Option<&ShannonEntropyAnalysis>,
    precomputed_mitre: Option<&MitreAttackAnalysis>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let total_assets = entity.map(|e| e.total_assets).unwrap_or(100);
    let alert_count = alerts.len();

    // ---------------------------------------------------------------------
    // NEGATIVE SPACE 1: Absence of Expected Alert Categories
    // ---------------------------------------------------------------------
    let expected_categories = vec![
        "MALWARE",
        "RANSOMWARE",
        "EXFILTRATION",
        "PRIVILEGE_ESCALATION",
        "COMMAND_AND_CONTROL",
        "CREDENTIAL_DUMP",
    ];

    let present_categories: HashSet<String> = alerts.iter().map(|a| a.category.to_uppercase()).collect();
    let missing_categories: Vec<String> = expected_categories
        .into_iter()
        .filter(|cat| !present_categories.contains(*cat))
        .map(|s| s.to_string())
        .collect();

    if missing_categories.len() >= 3 {
        let severity = if missing_categories.len() >= 4 { "CRITICAL" } else { "HIGH" };
        findings.push(Finding {
            finding_id: format!("FND-NEG-CAT-{}", &Uuid::new_v4().simple().to_string()[..8]),
            entity_id: entity_id.to_string(),
            finding_type: "NEGATIVE_SPACE".to_string(),
            rule_code: "MISSING_ALERT_CATEGORIES".to_string(),
            title: "Absence of Expected Core Threat Alert Categories (Detection Blind Spot)".to_string(),
            severity: severity.to_string(),
            confidence: 0.92,
            description: format!(
                "Entity {} has ZERO alerts recorded for {} expected core threat categories: {}. This indicates SIEM rule suppression or monitoring gaps.",
                entity_id, missing_categories.len(), missing_categories.join(", ")
            ),
            explainability_notes: Some(format!(
                "Supervisory Rule Tripped: Missing >= 3 mandatory threat vectors ({}). In comparable critical sector environments, these categories routinely generate security events. Total absence indicates telemetry blind spots.",
                missing_categories.join(", ")
            )),
            supporting_evidence: Some(serde_json::json!({
                "missing_categories_count": missing_categories.len(),
                "missing_categories": missing_categories,
                "present_categories": present_categories.into_iter().collect::<Vec<String>>()
            })),
            created_at: Utc::now().to_rfc3339(),
        });
    }

    // ---------------------------------------------------------------------
    // NEGATIVE SPACE 2: Shannon Telemetry Information Entropy Collapse
    // ---------------------------------------------------------------------
    let entropy_analysis_storage;
    let entropy_analysis = match precomputed_entropy {
        Some(e) => e,
        None => {
            entropy_analysis_storage = compute_shannon_entropy(entity_id, alerts);
            &entropy_analysis_storage
        }
    };

    if entropy_analysis.is_suppressed && alert_count >= 10 {
        findings.push(Finding {
            finding_id: format!("FND-NEG-ENTROPY-{}", &Uuid::new_v4().simple().to_string()[..8]),
            entity_id: entity_id.to_string(),
            finding_type: "NEGATIVE_SPACE".to_string(),
            rule_code: "SHANNON_ENTROPY_COLLAPSE".to_string(),
            title: "Telemetry Information Entropy Collapse (Active Alert Suppression)".to_string(),
            severity: if entropy_analysis.normalized_entropy < 0.25 { "CRITICAL".to_string() } else { "HIGH".to_string() },
            confidence: 0.94,
            description: format!(
                "Entity {} exhibits severe telemetry diversity collapse (Shannon Entropy: {:.2} bits, Normalized: {:.1}%). Telemetry is heavily skewed towards superficial categories.",
                entity_id, entropy_analysis.entropy, entropy_analysis.normalized_entropy * 100.0
            ),
            explainability_notes: Some(
                "Supervisory Rule Tripped: Shannon Entropy H(X) < 1.0 or Normalized Entropy < 35%. Natural critical sector SOC environments display rich category entropy. An entropy collapse demonstrates aggressive filter suppression or pipeline failure.".to_string()
            ),
            supporting_evidence: Some(serde_json::json!({
                "shannon_entropy_bits": entropy_analysis.entropy,
                "max_possible_entropy": entropy_analysis.max_possible_entropy,
                "normalized_entropy": entropy_analysis.normalized_entropy,
                "category_frequencies": entropy_analysis.category_frequencies
            })),
            created_at: Utc::now().to_rfc3339(),
        });
    }

    // ---------------------------------------------------------------------
    // NEGATIVE SPACE 3: MITRE ATT&CK Enterprise Matrix Blind Spots (v14)
    // ---------------------------------------------------------------------
    let mitre_analysis_storage;
    let mitre_analysis = match precomputed_mitre {
        Some(m) => m,
        None => {
            mitre_analysis_storage = compute_mitre_attack_analysis(entity_id, alerts);
            &mitre_analysis_storage
        }
    };

    if mitre_analysis.coverage_density < 0.55 && alert_count >= 10 {
        findings.push(Finding {
            finding_id: format!("FND-NEG-MITRE-{}", &Uuid::new_v4().simple().to_string()[..8]),
            entity_id: entity_id.to_string(),
            finding_type: "NEGATIVE_SPACE".to_string(),
            rule_code: "MITRE_ATTACK_BLIND_SPOT".to_string(),
            title: "Critical Deficit in MITRE ATT&CK Tactical Telemetry Coverage".to_string(),
            severity: if mitre_analysis.coverage_density < 0.40 { "CRITICAL".to_string() } else { "HIGH".to_string() },
            confidence: 0.93,
            description: format!(
                "Entity {} covers only {} of 11 MITRE ATT&CK enterprise tactics ({:.1}% tactical density). Critical blind spots observed in: {}.",
                entity_id, mitre_analysis.covered_tactics, mitre_analysis.coverage_density * 100.0, mitre_analysis.critical_blind_spots.join(", ")
            ),
            explainability_notes: Some(format!(
                "Supervisory Rule Tripped: MITRE ATT&CK enterprise coverage density < 55%. High overall alert volume masking severe blind spots across key kill-chain tactics ({}).",
                mitre_analysis.critical_blind_spots.join(", ")
            )),
            supporting_evidence: Some(serde_json::json!({
                "covered_tactics_count": mitre_analysis.covered_tactics,
                "total_tactics": mitre_analysis.total_tactics,
                "coverage_density": mitre_analysis.coverage_density,
                "critical_blind_spots": mitre_analysis.critical_blind_spots
            })),
            created_at: Utc::now().to_rfc3339(),
        });
    }

    // ---------------------------------------------------------------------
    // NEGATIVE SPACE 4: Subnet Monitoring Blind Spots
    // ---------------------------------------------------------------------
    let subnets_present: HashSet<String> = alerts.iter().filter_map(|a| a.subnet.clone()).collect();
    let expected_subnets = get_expected_entity_subnets(entity_id);

    let missing_subnets: Vec<String> = expected_subnets
        .into_iter()
        .filter(|s| !subnets_present.contains(*s))
        .map(|s| s.to_string())
        .collect();

    if !missing_subnets.is_empty() {
        findings.push(Finding {
            finding_id: format!("FND-NEG-SUBNET-{}", &Uuid::new_v4().simple().to_string()[..8]),
            entity_id: entity_id.to_string(),
            finding_type: "NEGATIVE_SPACE".to_string(),
            rule_code: "SUBNET_MONITORING_BLIND_SPOT".to_string(),
            title: "Missing Telemetry Coverage for Critical Subnets / Network Segments".to_string(),
            severity: if missing_subnets.len() >= 2 { "HIGH".to_string() } else { "MODERATE".to_string() },
            confidence: 0.88,
            description: format!(
                "Subnet audit identified {} critical network segments ({}) with ZERO alert coverage over the evaluation period.",
                missing_subnets.len(), missing_subnets.join(", ")
            ),
            explainability_notes: Some(format!(
                "Supervisory Rule Tripped: Expected critical subnet {} generated 0 SIEM alerts. Indicates unmonitored network segments or failed log forwarding agents.",
                missing_subnets.join(", ")
            )),
            supporting_evidence: Some(serde_json::json!({
                "missing_subnets": missing_subnets,
                "monitored_subnets": subnets_present.into_iter().collect::<Vec<String>>()
            })),
            created_at: Utc::now().to_rfc3339(),
        });
    }

    // ---------------------------------------------------------------------
    // NEGATIVE SPACE 5: Abnormally Low Activity Level (Workload Anomaly)
    // ---------------------------------------------------------------------
    let expected_min_alerts = std::cmp::max(15, (total_assets as f64 * 0.08) as usize);
    if alert_count < expected_min_alerts {
        findings.push(Finding {
            finding_id: format!("FND-NEG-LOWACT-{}", &Uuid::new_v4().simple().to_string()[..8]),
            entity_id: entity_id.to_string(),
            finding_type: "NEGATIVE_SPACE".to_string(),
            rule_code: "ABNORMALLY_LOW_ACTIVITY".to_string(),
            title: "Unexpectedly Low Alert Activity Inconsistent with Asset Density".to_string(),
            severity: if alert_count <= 20 { "HIGH".to_string() } else { "MODERATE".to_string() },
            confidence: 0.85,
            description: format!(
                "Entity {} generated only {} alerts across {} critical assets. This alert density is abnormally low compared to peer baseline expectations (min expected: {}).",
                entity_id, alert_count, total_assets, expected_min_alerts
            ),
            explainability_notes: Some(format!(
                "Supervisory Rule Tripped: Alert count ({}) < Expected threshold ({}). Low alert volume in a critical sector entity usually stems from overly permissive detection thresholds, disabled rules, or log dropouts.",
                alert_count, expected_min_alerts
            )),
            supporting_evidence: Some(serde_json::json!({
                "actual_alert_count": alert_count,
                "expected_min_alerts": expected_min_alerts,
                "total_assets": total_assets,
                "alert_to_asset_ratio": alert_count as f64 / total_assets.max(1) as f64
            })),
            created_at: Utc::now().to_rfc3339(),
        });
    }

    findings
}

/// Calculates Shannon Information Entropy H(X) = - \sum p_i log2(p_i)
pub fn compute_shannon_entropy(entity_id: &str, alerts: &[Alert]) -> ShannonEntropyAnalysis {
    let alert_count = alerts.len();
    if alert_count == 0 {
        return ShannonEntropyAnalysis {
            entity_id: entity_id.to_string(),
            entropy: 0.0,
            max_possible_entropy: 2.58, // log2(6)
            normalized_entropy: 0.0,
            alert_count: 0,
            category_frequencies: Vec::new(),
            is_suppressed: true,
        };
    }

    let mut cat_counts: HashMap<String, usize> = HashMap::new();
    for a in alerts {
        *cat_counts.entry(a.category.to_uppercase()).or_insert(0) += 1;
    }

    let mut frequencies = Vec::new();
    let mut entropy = 0.0;

    for (cat, count) in &cat_counts {
        let p = *count as f64 / alert_count as f64;
        if p > 0.0 {
            entropy -= p * p.log2();
        }
        frequencies.push(CategoryFrequency {
            category: cat.clone(),
            count: *count,
            probability: (p * 1000.0).round() / 1000.0,
        });
    }

    frequencies.sort_by(|a, b| b.count.cmp(&a.count));

    // Expected categories baseline: 6 major categories
    let max_possible = (6.0_f64).log2(); // ~2.585
    let normalized = (entropy / max_possible).min(1.0).max(0.0);
    let is_suppressed = normalized < 0.35 || entropy < 1.0;

    ShannonEntropyAnalysis {
        entity_id: entity_id.to_string(),
        entropy: (entropy * 100.0).round() / 100.0,
        max_possible_entropy: (max_possible * 100.0).round() / 100.0,
        normalized_entropy: (normalized * 1000.0).round() / 1000.0,
        alert_count,
        category_frequencies: frequencies,
        is_suppressed,
    }
}

/// Evaluates coverage across 11 core MITRE ATT&CK Enterprise Tactics
pub fn compute_mitre_attack_analysis(entity_id: &str, alerts: &[Alert]) -> MitreAttackAnalysis {
    let tactics = vec![
        ("TA0001", "Initial Access"),
        ("TA0002", "Execution"),
        ("TA0003", "Persistence"),
        ("TA0004", "Privilege Escalation"),
        ("TA0005", "Defense Evasion"),
        ("TA0006", "Credential Access"),
        ("TA0007", "Discovery"),
        ("TA0008", "Lateral Movement"),
        ("TA0009", "Collection"),
        ("TA0010", "Exfiltration"),
        ("TA0040", "Impact"),
    ];

    let mut tactic_counts: HashMap<&'static str, usize> = HashMap::new();
    for &(tid, _) in &tactics {
        tactic_counts.insert(tid, 0);
    }

    for a in alerts {
        // 1. Direct MITRE tactic match if present on alert record
        let mut matched = false;
        if let Some(ref tactic_str) = a.mitre_tactic {
            let t_upper = tactic_str.trim().to_uppercase();
            for &(tid, tname) in &tactics {
                if t_upper == tid || t_upper == tname.to_uppercase() || t_upper.starts_with(tid) {
                    *tactic_counts.get_mut(tid).unwrap() += 1;
                    matched = true;
                    break;
                }
            }
        }

        // 2. Fall back to heuristic rule and category classification if not explicitly matched
        if !matched {
            let cat = a.category.to_uppercase();
            let rule = a.rule_name.to_uppercase();

            if cat.contains("ACCESS") || rule.contains("PHISH") || rule.contains("EXPLOIT") {
                *tactic_counts.get_mut("TA0001").unwrap() += 1;
            }
            if cat.contains("MALWARE") || rule.contains("SCRIPT") || rule.contains("POWERSHELL") {
                *tactic_counts.get_mut("TA0002").unwrap() += 1;
            }
            if cat.contains("PERSISTENCE") || rule.contains("CRON") || rule.contains("SERVICE") {
                *tactic_counts.get_mut("TA0003").unwrap() += 1;
            }
            if cat.contains("PRIVILEGE") || rule.contains("SU") || rule.contains("SUDO") {
                *tactic_counts.get_mut("TA0004").unwrap() += 1;
            }
            if cat.contains("EVASION") || rule.contains("CLEAR_LOG") || rule.contains("DISABLE") {
                *tactic_counts.get_mut("TA0005").unwrap() += 1;
            }
            if cat.contains("CREDENTIAL") || rule.contains("DUMP") || rule.contains("BRUTE") || rule.contains("AUTH_FAIL") {
                *tactic_counts.get_mut("TA0006").unwrap() += 1;
            }
            if cat.contains("DISCOVERY") || rule.contains("SCAN") || rule.contains("RECON") {
                *tactic_counts.get_mut("TA0007").unwrap() += 1;
            }
            if cat.contains("LATERAL") || rule.contains("SMB") || rule.contains("RDP") || rule.contains("SSH") {
                *tactic_counts.get_mut("TA0008").unwrap() += 1;
            }
            if cat.contains("COLLECTION") || rule.contains("ARCHIVE") || rule.contains("CLIPBOARD") {
                *tactic_counts.get_mut("TA0009").unwrap() += 1;
            }
            if cat.contains("EXFILTRATION") || rule.contains("DATA_LEAK") || rule.contains("UPLOAD") {
                *tactic_counts.get_mut("TA0010").unwrap() += 1;
            }
            if cat.contains("RANSOMWARE") || cat.contains("IMPACT") || rule.contains("ENCRYPT") || rule.contains("WIPE") {
                *tactic_counts.get_mut("TA0040").unwrap() += 1;
            }
        }
    }

    let mut breakdown = Vec::new();
    let mut blind_spots = Vec::new();
    let mut covered_count = 0;

    for &(tid, tname) in &tactics {
        let count = tactic_counts[tid];
        let is_covered = count > 0;
        if is_covered {
            covered_count += 1;
        } else {
            blind_spots.push(format!("{} ({})", tname, tid));
        }

        breakdown.push(MitreTacticCoverage {
            tactic_id: tid.to_string(),
            tactic_name: tname.to_string(),
            alert_count: count,
            is_covered,
        });
    }

    let total = tactics.len();
    let density = covered_count as f64 / total as f64;

    MitreAttackAnalysis {
        entity_id: entity_id.to_string(),
        total_tactics: total,
        covered_tactics: covered_count,
        coverage_density: (density * 1000.0).round() / 1000.0,
        tactical_breakdown: breakdown,
        critical_blind_spots: blind_spots,
    }
}

fn get_expected_entity_subnets(entity_id: &str) -> Vec<&'static str> {
    let id_upper = entity_id.to_uppercase();
    if id_upper.contains("POWER") || id_upper == "CSE-POWERGRID" {
        vec!["10.10.0.0/16", "10.20.0.0/16"]
    } else if id_upper.contains("BANK") || id_upper == "CSE-NATBANK" {
        vec!["10.100.0.0/16", "10.200.0.0/16"] // 10.200.0.0 Core Subnet expected
    } else if id_upper.contains("TELECOM") || id_upper == "CSE-TELECOM" {
        vec!["10.50.0.0/16", "10.51.0.0/16", "10.52.0.0/16"]
    } else {
        // External arbitrary entities do not have predefined baseline subnets
        vec![]
    }
}
