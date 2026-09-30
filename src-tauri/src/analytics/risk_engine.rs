use crate::analytics::execution_gaps::analyze_execution_gaps_with_data;
use crate::analytics::forensics::{
    compute_benford_analysis, compute_certin_compliance, compute_minhash_clusters,
    compute_shift_dump_analysis, generate_merkle_audit_seal,
};
use crate::analytics::negative_space::{
    analyze_negative_space_with_data, compute_mitre_attack_analysis, compute_shannon_entropy,
};
use crate::analytics::peer_benchmarking::compute_peer_benchmarks;
use crate::models::{
    Alert, Case, Entity, EntityRiskProfile, EntitySotaDetails, Finding, SupervisoryAnalysisResponse,
};
use chrono::Utc;
use rusqlite::{params, Connection, Result};
use std::collections::HashMap;
use uuid::Uuid;

pub fn run_full_supervisory_analysis(conn: &Connection) -> Result<SupervisoryAnalysisResponse> {
    // 1. Fetch Entities
    let mut stmt = conn.prepare("SELECT entity_id, name, sector, total_assets FROM entities")?;
    let entity_rows = stmt.query_map([], |row| {
        Ok(Entity {
            entity_id: row.get(0)?,
            name: row.get(1)?,
            sector: row.get(2)?,
            total_assets: row.get(3)?,
        })
    })?;

    let mut entities = Vec::new();
    for e in entity_rows {
        entities.push(e?);
    }

    if entities.is_empty() {
        let empty_seal = generate_merkle_audit_seal(&[], "EMPTY-BATCH-INIT");
        return Ok(SupervisoryAnalysisResponse {
            total_entities_analyzed: 0,
            analysis_timestamp: Utc::now().to_rfc3339(),
            entities_at_risk_count: 0,
            risk_profiles: Vec::new(),
            findings: Vec::new(),
            peer_benchmarks: Vec::new(),
            sota_details: Vec::new(),
            merkle_seal: empty_seal,
        });
    }

    // Execute analysis and findings persistence within an atomic transaction
    conn.execute_batch("BEGIN TRANSACTION; DELETE FROM findings; DELETE FROM risk_scores;")?;

    let mut all_findings: Vec<Finding> = Vec::new();
    let mut sota_details_list = Vec::new();
    let mut all_forensic_records: Vec<String> = Vec::new();

    // Run detectors and SOTA analytics for each entity
    for e in &entities {
        // Fetch cases including escalated_at for accurate CERT-In statutory compliance evaluation
        let mut stmt_cases = conn.prepare(
            "SELECT case_id, alert_id, entity_id, investigator_id, created_at, closed_at, duration_seconds, status, escalated, resolution_notes, disposition, escalated_at
             FROM cases WHERE entity_id = ?1",
        )?;
        let case_rows = stmt_cases.query_map(params![&e.entity_id], |row| {
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
            let item = c?;
            all_forensic_records.push(format!("CASE:{}:{}:{}", item.case_id, item.investigator_id, item.created_at));
            cases.push(item);
        }

        // Fetch alerts including MITRE tactics and technique mappings
        let mut stmt_alts = conn.prepare(
            "SELECT alert_id, entity_id, asset_id, subnet, rule_name, category, severity, timestamp, mitre_tactic, mitre_technique, raw_payload
             FROM alerts WHERE entity_id = ?1",
        )?;
        let alert_rows = stmt_alts.query_map(params![&e.entity_id], |row| {
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
        let mut alert_map = HashMap::new();
        for a in alert_rows {
            let item = a?;
            alert_map.insert(item.alert_id.clone(), (item.severity.clone(), item.timestamp.clone()));
            all_forensic_records.push(format!("ALERT:{}:{}:{}", item.alert_id, item.rule_name, item.timestamp));
            alerts.push(item);
        }

        // 1. SOTA Forensic Computations (Computed once, reused across modules)
        let durations: Vec<f64> = cases.iter().filter_map(|c| c.duration_seconds).collect();
        let benford = compute_benford_analysis(&e.entity_id, &durations);
        let shift_dump = compute_shift_dump_analysis(&e.entity_id, &cases);
        let minhash_clusters = compute_minhash_clusters(&cases);
        let shannon_entropy = compute_shannon_entropy(&e.entity_id, &alerts);
        let mitre_attack = compute_mitre_attack_analysis(&e.entity_id, &alerts);
        let certin_compliance = compute_certin_compliance(&e.entity_id, &cases, &alert_map);

        // 2. Execution Gaps (reusing pre-fetched data & pre-computed SOTA metrics)
        let gap_fnds = analyze_execution_gaps_with_data(
            &e.entity_id,
            &cases,
            &alerts,
            Some(&benford),
            Some(&shift_dump),
            Some(&minhash_clusters),
        );
        for f in gap_fnds {
            save_finding(conn, &f)?;
            all_findings.push(f);
        }

        // 3. Negative Space (reusing pre-fetched alerts & pre-computed entropy/MITRE analysis)
        let neg_fnds = analyze_negative_space_with_data(
            &e.entity_id,
            Some(e),
            &alerts,
            Some(&shannon_entropy),
            Some(&mitre_attack),
        );
        for f in neg_fnds {
            save_finding(conn, &f)?;
            all_findings.push(f);
        }

        // 4. CERT-In Statutory Breach Findings
        if certin_compliance.breached_incidents > 0 {
            let breach_fnd = Finding {
                finding_id: format!("FND-REG-CERTIN-{}", &Uuid::new_v4().simple().to_string()[..8]),
                entity_id: e.entity_id.clone(),
                finding_type: "REGULATORY_BREACH".to_string(),
                rule_code: "CERTIN_6HR_BREACH".to_string(),
                title: "Statutory Breach: Mandatory Cyber Incident 6-Hour Reporting SLA Violations".to_string(),
                severity: "CRITICAL".to_string(),
                confidence: 0.98,
                description: format!(
                    "Entity {} failed to report {} out of {} High/Critical security incidents ({:.1}% compliance rate) within the statutory 6-hour window mandated by CERT-In Directions 2022.",
                    e.entity_id, certin_compliance.breached_incidents, certin_compliance.total_critical_incidents, certin_compliance.compliance_rate
                ),
                explainability_notes: Some(
                    "Supervisory Rule Tripped: Incident triage/escalation latency > 21,600 seconds (6 hours). Direct violation of Section 70B(6) of the Information Technology Act 2000 and CERT-In Directions 2022.".to_string()
                ),
                supporting_evidence: Some(serde_json::json!({
                    "breached_incidents_count": certin_compliance.breached_incidents,
                    "total_critical_incidents": certin_compliance.total_critical_incidents,
                    "compliance_rate_pct": certin_compliance.compliance_rate,
                    "breaches": certin_compliance.breaches
                })),
                created_at: Utc::now().to_rfc3339(),
            };
            save_finding(conn, &breach_fnd)?;
            all_findings.push(breach_fnd);
        }

        sota_details_list.push(EntitySotaDetails {
            entity_id: e.entity_id.clone(),
            benford,
            shift_dump,
            minhash_clusters,
            shannon_entropy,
            mitre_attack,
            certin_compliance,
        });
    }

    // Run Peer Benchmarking
    let benchmarks = compute_peer_benchmarks(conn)?;
    let benchmark_map: HashMap<String, f64> = benchmarks
        .iter()
        .map(|b| (b.entity_id.clone(), b.z_score))
        .collect();

    let mut risk_profiles = Vec::new();

    for e in &entities {
        let entity_findings: Vec<&Finding> = all_findings.iter().filter(|f| f.entity_id == e.entity_id).collect();
        let gap_findings: Vec<&&Finding> = entity_findings.iter().filter(|f| f.finding_type == "EXECUTION_GAP").collect();
        let neg_findings: Vec<&&Finding> = entity_findings.iter().filter(|f| f.finding_type == "NEGATIVE_SPACE").collect();
        let reg_findings: Vec<&&Finding> = entity_findings.iter().filter(|f| f.finding_type == "REGULATORY_BREACH").collect();

        let gap_score = calculate_component_score(&gap_findings);
        let neg_score = calculate_component_score(&neg_findings);
        let reg_penalty = (reg_findings.len() as f64 * 15.0).min(30.0);

        let composite_score = (((gap_score * 0.45) + (neg_score * 0.45) + reg_penalty) * 100.0).round() / 100.0;
        let composite_score = composite_score.min(100.0);

        let risk_level = if composite_score >= 75.0 {
            "CRITICAL"
        } else if composite_score >= 50.0 {
            "HIGH"
        } else if composite_score >= 25.0 {
            "MODERATE"
        } else {
            "LOW"
        };

        let z_overall = benchmark_map.get(&e.entity_id).cloned().unwrap_or(0.0);

        let mut sev_counts = HashMap::new();
        for f in &entity_findings {
            *sev_counts.entry(f.severity.clone()).or_insert(0) += 1;
        }

        let breakdown = serde_json::json!({
            "execution_gap_score": gap_score,
            "negative_space_score": neg_score,
            "regulatory_penalty": reg_penalty,
            "execution_gap_findings_count": gap_findings.len(),
            "negative_space_findings_count": neg_findings.len(),
            "regulatory_findings_count": reg_findings.len(),
            "z_score_overall": z_overall,
        });

        // Save risk score record
        conn.execute(
            "INSERT INTO risk_scores (entity_id, execution_gap_score, negative_space_score, composite_risk_score, risk_level, z_score_overall, breakdown_json, assessed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                e.entity_id,
                gap_score,
                neg_score,
                composite_score,
                risk_level,
                z_overall,
                breakdown.to_string(),
                Utc::now().to_rfc3339()
            ],
        )?;

        risk_profiles.push(EntityRiskProfile {
            entity_id: e.entity_id.clone(),
            entity_name: e.name.clone(),
            sector: e.sector.clone(),
            execution_gap_score: gap_score,
            negative_space_score: neg_score,
            composite_risk_score: composite_score,
            risk_level: risk_level.to_string(),
            z_score_overall: z_overall,
            findings_count: entity_findings.len(),
            findings_by_severity: sev_counts,
            breakdown_json: breakdown,
        });
    }

    // Commit findings and risk scores transaction
    conn.execute_batch("COMMIT;")?;

    risk_profiles.sort_by(|a, b| b.composite_risk_score.partial_cmp(&a.composite_risk_score).unwrap_or(std::cmp::Ordering::Equal));
    let at_risk_count = risk_profiles.iter().filter(|p| p.risk_level == "HIGH" || p.risk_level == "CRITICAL").count();

    // 5. Generate Cryptographic Merkle Audit Seal over all evaluated telemetry and findings
    for f in &all_findings {
        all_forensic_records.push(format!("FINDING:{}:{}:{}:{}", f.finding_id, f.entity_id, f.rule_code, f.severity));
    }
    let merkle_seal = generate_merkle_audit_seal(&all_forensic_records, "NCIIPC-BATCH-AUDIT-2026");

    Ok(SupervisoryAnalysisResponse {
        total_entities_analyzed: entities.len(),
        analysis_timestamp: Utc::now().to_rfc3339(),
        entities_at_risk_count: at_risk_count,
        risk_profiles,
        findings: all_findings,
        peer_benchmarks: benchmarks,
        sota_details: sota_details_list,
        merkle_seal,
    })
}

fn save_finding(conn: &Connection, f: &Finding) -> Result<()> {
    let ev_str = f.supporting_evidence.as_ref().map(|v| v.to_string());
    conn.execute(
        "INSERT OR REPLACE INTO findings (finding_id, entity_id, finding_type, rule_code, title, severity, confidence, description, explainability_notes, supporting_evidence, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            f.finding_id,
            f.entity_id,
            f.finding_type,
            f.rule_code,
            f.title,
            f.severity,
            f.confidence,
            f.description,
            f.explainability_notes,
            ev_str,
            f.created_at
        ],
    )?;
    Ok(())
}

fn calculate_component_score(findings: &[&&Finding]) -> f64 {
    if findings.is_empty() {
        return 0.0;
    }
    let mut total: f64 = 0.0;
    for f in findings {
        total += match f.severity.as_str() {
            "CRITICAL" => 35.0,
            "HIGH" => 25.0,
            "MODERATE" => 15.0,
            _ => 5.0,
        };
    }
    total.min(100.0)
}
