use crate::analytics::forensics::{
    compute_benford_analysis, compute_minhash_clusters, compute_shift_dump_analysis,
};
use crate::models::{Alert, BenfordAnalysis, Case, Finding, MinHashNoteCluster, ShiftDumpAnalysis};
use chrono::Utc;
use rusqlite::{params, Connection, Result};
use std::collections::HashMap;
use uuid::Uuid;

pub fn analyze_execution_gaps(conn: &Connection, entity_id: &str) -> Result<Vec<Finding>> {
    // 1. Fetch Cases for Entity (including escalated_at)
    let mut stmt = conn.prepare(
        "SELECT case_id, alert_id, entity_id, investigator_id, created_at, closed_at, duration_seconds, status, escalated, resolution_notes, disposition, escalated_at
         FROM cases WHERE entity_id = ?1",
    )?;

    let case_rows = stmt.query_map(params![entity_id], |row| {
        Ok(Case {
            case_id: row.get(0)?,
            alert_id: row.get(1)?,
            entity_id: row.get(2)?,
            investigator_id: row.get(3)?,
            created_at: row.get(4)?,
            closed_at: row.get(5)?,
            duration_seconds: row.get(6)?,
            status: row.get(7)?,
            escalated: row.get::<_, i32>(8)? != 0,
            resolution_notes: row.get(9)?,
            disposition: row.get(10)?,
            escalated_at: row.get(11)?,
        })
    })?;

    let mut cases = Vec::new();
    for c in case_rows {
        cases.push(c?);
    }

    // 2. Fetch Alerts for Entity (including mitre tactics and payload)
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

    Ok(analyze_execution_gaps_with_data(entity_id, &cases, &alerts, None, None, None))
}

pub fn analyze_execution_gaps_with_data(
    entity_id: &str,
    cases: &[Case],
    alerts: &[Alert],
    precomputed_benford: Option<&BenfordAnalysis>,
    precomputed_shift_dump: Option<&ShiftDumpAnalysis>,
    precomputed_minhash: Option<&[MinHashNoteCluster]>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    if cases.is_empty() || alerts.is_empty() {
        return findings;
    }

    let mut alert_map = HashMap::new();
    for a in alerts {
        alert_map.insert(a.alert_id.clone(), a.clone());
    }

    // ---------------------------------------------------------------------
    // GAP 1: Fast Ticket Closures (<= 60 seconds)
    // ---------------------------------------------------------------------
    let mut fast_cases = Vec::new();
    for c in cases {
        if let Some(dur) = c.duration_seconds {
            if dur <= 60.0 {
                if let Some(a) = alert_map.get(&c.alert_id) {
                    if a.severity == "HIGH" || a.severity == "CRITICAL" || a.severity == "MODERATE" {
                        fast_cases.push(c);
                    }
                }
            }
        }
    }

    if !fast_cases.is_empty() {
        let fast_rate = (fast_cases.len() as f64 / cases.len() as f64) * 100.0;
        let severity = if fast_rate >= 40.0 {
            "CRITICAL"
        } else if fast_rate >= 20.0 {
            "HIGH"
        } else {
            "MODERATE"
        };

        let sample_ids: Vec<String> = fast_cases.iter().take(5).map(|c| c.case_id.clone()).collect();
        let sample_durations: Vec<f64> = fast_cases.iter().take(5).map(|c| c.duration_seconds.unwrap_or(0.0)).collect();

        findings.push(Finding {
            finding_id: format!("FND-GAP-FAST-{}", &Uuid::new_v4().simple().to_string()[..8]),
            entity_id: entity_id.to_string(),
            finding_type: "EXECUTION_GAP".to_string(),
            rule_code: "FAST_TICKET_CLOSURE".to_string(),
            title: "High-Severity Alerts Closed Unusually Quickly Without Investigation".to_string(),
            severity: severity.to_string(),
            confidence: 0.95,
            description: format!(
                "Entity {} closed {} out of {} cases ({:.1}%) in under 60 seconds without meaningful investigation.",
                entity_id, fast_cases.len(), cases.len(), fast_rate
            ),
            explainability_notes: Some(
                "Supervisory Rule Tripped: Cases with High/Critical alert severity closed in <= 60.0s. Indicates analysts are clicking 'Close' to satisfy SLA metrics without performing actual forensic analysis.".to_string()
            ),
            supporting_evidence: Some(serde_json::json!({
                "fast_cases_count": fast_cases.len(),
                "total_cases_count": cases.len(),
                "fast_closure_percentage": fast_rate,
                "sample_fast_case_ids": sample_ids,
                "sample_durations_seconds": sample_durations
            })),
            created_at: Utc::now().to_rfc3339(),
        });
    }

    // ---------------------------------------------------------------------
    // GAP 2: Benford's Law Chi-Square (\chi^2) Duration Distribution Anomaly
    // ---------------------------------------------------------------------
    let benford_storage;
    let benford = match precomputed_benford {
        Some(b) => b,
        None => {
            let durations: Vec<f64> = cases.iter().filter_map(|c| c.duration_seconds).collect();
            benford_storage = compute_benford_analysis(entity_id, &durations);
            &benford_storage
        }
    };

    if benford.is_tampered && benford.total_samples >= 10 {
        findings.push(Finding {
            finding_id: format!("FND-GAP-BENFORD-{}", &Uuid::new_v4().simple().to_string()[..8]),
            entity_id: entity_id.to_string(),
            finding_type: "EXECUTION_GAP".to_string(),
            rule_code: "BENFORD_DURATION_ANOMALY".to_string(),
            title: "Ticket Closure Durations Fail Benford's Law (Evidence of Data Fabrication)".to_string(),
            severity: "CRITICAL".to_string(),
            confidence: 0.97,
            description: format!(
                "Investigation durations for Entity {} severely deviate from natural logarithmic distribution (Chi-Square: {:.2}, p-value: {:.4}). Indicates artificial duration generation or automated mass closures.",
                entity_id, benford.chi_square_stat, benford.p_value
            ),
            explainability_notes: Some(
                "Supervisory Rule Tripped: Pearson's Chi-Square goodness-of-fit test statistic exceeds critical value (20.09 at p < 0.01). Natural human forensic triage durations adhere to Benford's first-digit law; severe deviation is standard forensic proof of fabricated audit records.".to_string()
            ),
            supporting_evidence: Some(serde_json::json!({
                "chi_square_stat": benford.chi_square_stat,
                "p_value": benford.p_value,
                "total_samples": benford.total_samples,
                "digit_distribution": benford.distribution
            })),
            created_at: Utc::now().to_rfc3339(),
        });
    }

    // ---------------------------------------------------------------------
    // GAP 3: Shift-End Ticket Dumping & Burst Closures (Poisson Windowing)
    // ---------------------------------------------------------------------
    let shift_dump_storage;
    let shift_dump = match precomputed_shift_dump {
        Some(s) => s,
        None => {
            shift_dump_storage = compute_shift_dump_analysis(entity_id, cases);
            &shift_dump_storage
        }
    };

    if shift_dump.burst_ratio >= 15.0 || !shift_dump.clusters.is_empty() {
        findings.push(Finding {
            finding_id: format!("FND-GAP-BURST-{}", &Uuid::new_v4().simple().to_string()[..8]),
            entity_id: entity_id.to_string(),
            finding_type: "EXECUTION_GAP".to_string(),
            rule_code: "SHIFT_END_TICKET_DUMPING".to_string(),
            title: "Systemic Shift-End Ticket Dumping (Burst Closure Gaming)".to_string(),
            severity: if shift_dump.burst_ratio >= 25.0 { "CRITICAL".to_string() } else { "HIGH".to_string() },
            confidence: 0.94,
            description: format!(
                "Entity {} analysts closed {} tickets ({:.1}% of closed queue) in rapid 5-minute bursts (avg duration <= 120s), characteristic of shift handover dumping.",
                entity_id, shift_dump.burst_closures_count, shift_dump.burst_ratio
            ),
            explainability_notes: Some(
                "Supervisory Rule Tripped: Poisson inter-arrival window detected >= 5 ticket closures within 300s by a single investigator. Demonstrates gaming of queue metrics before shift handovers.".to_string()
            ),
            supporting_evidence: Some(serde_json::json!({
                "burst_closures_count": shift_dump.burst_closures_count,
                "burst_ratio": shift_dump.burst_ratio,
                "flagged_investigators": shift_dump.flagged_investigators,
                "clusters": shift_dump.clusters
            })),
            created_at: Utc::now().to_rfc3339(),
        });
    }

    // ---------------------------------------------------------------------
    // GAP 4: MinHash LSH & TF-IDF Template Note Collusion
    // ---------------------------------------------------------------------
    let minhash_storage;
    let minhash_clusters = match precomputed_minhash {
        Some(m) => m,
        None => {
            minhash_storage = compute_minhash_clusters(cases);
            &minhash_storage
        }
    };

    if !minhash_clusters.is_empty() {
        let sample_cluster = &minhash_clusters[0];
        findings.push(Finding {
            finding_id: format!("FND-GAP-LSH-{}", &Uuid::new_v4().simple().to_string()[..8]),
            entity_id: entity_id.to_string(),
            finding_type: "EXECUTION_GAP".to_string(),
            rule_code: "MINHASH_COLLUSION_CLUSTERS".to_string(),
            title: "MinHash LSH Identified Cross-Case Template Collusion in Resolution Notes".to_string(),
            severity: "HIGH".to_string(),
            confidence: 0.93,
            description: format!(
                "MinHash Locality-Sensitive Hashing identified {} duplicate clusters spanning multiple analysts in Entity {}, proving widespread boilerplate reuse.",
                minhash_clusters.len(), entity_id
            ),
            explainability_notes: Some(
                "Supervisory Rule Tripped: MinHash 3-gram Jaccard similarity >= 0.75 across distinct case records. Distinct alerts are being closed with canned, identical text.".to_string()
            ),
            supporting_evidence: Some(serde_json::json!({
                "cluster_count": minhash_clusters.len(),
                "sample_boilerplate_note": sample_cluster.sample_note,
                "sample_case_ids": sample_cluster.case_ids,
                "involved_investigators": sample_cluster.investigator_ids
            })),
            created_at: Utc::now().to_rfc3339(),
        });
    }

    // ---------------------------------------------------------------------
    // GAP 5: Critical Alerts Closed Without Escalation
    // ---------------------------------------------------------------------
    let mut unescalated_criticals = Vec::new();
    for c in cases {
        if let Some(a) = alert_map.get(&c.alert_id) {
            if (a.severity == "HIGH" || a.severity == "CRITICAL") && !c.escalated {
                unescalated_criticals.push(c);
            }
        }
    }

    if !unescalated_criticals.is_empty() {
        let rate = (unescalated_criticals.len() as f64 / cases.len() as f64) * 100.0;
        if rate >= 15.0 {
            let sample_ids: Vec<String> = unescalated_criticals.iter().take(5).map(|c| c.case_id.clone()).collect();
            findings.push(Finding {
                finding_id: format!("FND-GAP-UNESC-{}", &Uuid::new_v4().simple().to_string()[..8]),
                entity_id: entity_id.to_string(),
                finding_type: "EXECUTION_GAP".to_string(),
                rule_code: "UNESCALATED_CRITICAL_ALERTS".to_string(),
                title: "Critical & High-Severity Alerts Closed Without Appropriate Escalation".to_string(),
                severity: if rate >= 30.0 { "HIGH".to_string() } else { "MODERATE".to_string() },
                confidence: 0.92,
                description: format!(
                    "Entity {} closed {} High/Critical severity alerts ({:.1}% of total) at L1 triage without escalating to L2/L3 or Incident Response teams.",
                    entity_id, unescalated_criticals.len(), rate
                ),
                explainability_notes: Some(
                    "Supervisory Rule Tripped: Case record has severity = HIGH/CRITICAL but escalated = False. Represents potential suppression or failure to escalate major security incidents.".to_string()
                ),
                supporting_evidence: Some(serde_json::json!({
                    "unescalated_count": unescalated_criticals.len(),
                    "unescalated_percentage": rate,
                    "sample_case_ids": sample_ids
                })),
                created_at: Utc::now().to_rfc3339(),
            });
        }
    }

    // ---------------------------------------------------------------------
    // GAP 6: Remediation Deficit (Repetitive Alerts on Same Asset)
    // ---------------------------------------------------------------------
    let mut asset_counts: HashMap<String, usize> = HashMap::new();
    for a in alerts {
        *asset_counts.entry(a.asset_id.clone()).or_insert(0) += 1;
    }

    let repetition_deficits: HashMap<String, usize> = asset_counts
        .into_iter()
        .filter(|(_, count)| *count >= 5)
        .collect();

    if !repetition_deficits.is_empty() {
        findings.push(Finding {
            finding_id: format!("FND-GAP-REMED-{}", &Uuid::new_v4().simple().to_string()[..8]),
            entity_id: entity_id.to_string(),
            finding_type: "EXECUTION_GAP".to_string(),
            rule_code: "REMEDIATION_DEFICIT".to_string(),
            title: "Repeated Alerts on Same Asset Without Evidence of Root-Cause Remediation".to_string(),
            severity: if repetition_deficits.len() >= 3 { "HIGH".to_string() } else { "MODERATE".to_string() },
            confidence: 0.88,
            description: format!(
                "Identified {} assets experiencing >= 5 repetitive alerts with zero root-cause remediation, indicating superficial symptom-treating.",
                repetition_deficits.len()
            ),
            explainability_notes: Some(
                "Supervisory Rule Tripped: Asset alert recurrence >= 5 occurrences. Indicates SOC closes tickets individually without resolving the underlying vulnerability or misconfiguration.".to_string()
            ),
            supporting_evidence: Some(serde_json::json!({
                "remedied_deficits_count": repetition_deficits.len(),
                "affected_assets": repetition_deficits
            })),
            created_at: Utc::now().to_rfc3339(),
        });
    }

    findings
}
