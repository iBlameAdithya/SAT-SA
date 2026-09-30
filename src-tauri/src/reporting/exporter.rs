use crate::models::SupervisoryAnalysisResponse;
use chrono::Utc;
use std::fs;
use std::path::{Component, Path, PathBuf};

/// Validates and sanitizes file paths to prevent directory traversal vulnerabilities (CWE-22)
pub fn sanitize_export_path(output_path: &str) -> Result<PathBuf, String> {
    let trimmed = output_path.trim();
    if trimmed.is_empty() {
        return Err("Export path cannot be empty.".to_string());
    }

    let path = Path::new(trimmed);

    // Reject path traversal attempts containing ParentDir (..)
    for component in path.components() {
        if let Component::ParentDir = component {
            return Err("Security Violation: Path traversal ('..') is strictly prohibited in export paths.".to_string());
        }
    }

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| format!("Failed to create export directory: {}", e))?;
        }
    }

    Ok(path.to_path_buf())
}

/// Encodes HTML special characters to prevent Stored Cross-Site Scripting (XSS / CWE-79) in reports
pub fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

pub fn export_json_package(
    output_path: &str,
    analysis_data: &SupervisoryAnalysisResponse,
) -> Result<String, String> {
    let sanitized_path = sanitize_export_path(output_path)?;

    let package = serde_json::json!({
        "metadata": {
            "system": "SAT-SA: Supervisory Analytics Tool for SOC Assessment",
            "version": "1.0.0",
            "authority": "National Technical Research Organisation (NTRO) / NCIIPC",
            "statutory_act": "Section 70A & Section 70B, Information Technology Act, 2000",
            "export_timestamp": Utc::now().to_rfc3339(),
            "air_gapped_deployment": true,
            "notice": "CONFIDENTIAL SUPERVISORY EXAMINATION PACKAGE: STATUTORY AUDIT USE ONLY"
        },
        "merkle_audit_seal": analysis_data.merkle_seal,
        "assessment_summary": {
            "total_entities_analyzed": analysis_data.total_entities_analyzed,
            "entities_at_risk_count": analysis_data.entities_at_risk_count,
            "analysis_timestamp": analysis_data.analysis_timestamp,
        },
        "risk_profiles": analysis_data.risk_profiles,
        "sota_forensic_details": analysis_data.sota_details,
        "findings": analysis_data.findings,
        "peer_benchmarks": analysis_data.peer_benchmarks,
    });

    let json_str = serde_json::to_string_pretty(&package).map_err(|e| e.to_string())?;
    fs::write(&sanitized_path, json_str).map_err(|e| e.to_string())?;

    Ok(sanitized_path.to_string_lossy().to_string())
}

pub fn export_html_pdf_report(
    output_path: &str,
    analysis_data: &SupervisoryAnalysisResponse,
) -> Result<String, String> {
    let sanitized_path = sanitize_export_path(output_path)?;

    let timestamp_str = Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();

    let mut profiles_html = String::new();
    for p in &analysis_data.risk_profiles {
        let badge_class = match p.risk_level.as_str() {
            "CRITICAL" => "badge-critical",
            "HIGH" => "badge-high",
            "MODERATE" => "badge-moderate",
            _ => "badge-low",
        };
        profiles_html.push_str(&format!(
            "<tr>
                <td><strong>{}</strong></td>
                <td>{}</td>
                <td>{}</td>
                <td>{:.1}</td>
                <td>{:.1}</td>
                <td><strong>{:.1}</strong></td>
                <td><span class='badge {}'>{}</span></td>
            </tr>",
            escape_html(&p.entity_id),
            escape_html(&p.entity_name),
            escape_html(&p.sector),
            p.execution_gap_score,
            p.negative_space_score,
            p.composite_risk_score,
            badge_class,
            escape_html(&p.risk_level)
        ));
    }

    let mut sota_html = String::new();
    for sota in &analysis_data.sota_details {
        let benford_status = if sota.benford.is_tampered {
            "<span class='badge badge-critical'>ANOMALY (p &lt; 0.01)</span>"
        } else {
            "<span class='badge badge-low'>NATURAL</span>"
        };

        let certin_status = if sota.certin_compliance.breached_incidents > 0 {
            format!("<span class='badge badge-critical'>{} BREACHES</span>", sota.certin_compliance.breached_incidents)
        } else {
            "<span class='badge badge-low'>100% COMPLIANT</span>".to_string()
        };

        let entropy_status = if sota.shannon_entropy.is_suppressed {
            "<span class='badge badge-critical'>SUPPRESSION</span>"
        } else {
            "<span class='badge badge-low'>HEALTHY DIVERSITY</span>"
        };

        let blind_spots_str = if sota.mitre_attack.critical_blind_spots.is_empty() {
            "None".to_string()
        } else {
            sota.mitre_attack.critical_blind_spots.join(", ")
        };

        sota_html.push_str(&format!(
            "<div class='sota-card'>
                <div class='sota-header'>
                    <strong>Entity: {}</strong>
                </div>
                <div class='sota-grid'>
                    <div class='metric-box'>
                        <span class='metric-label'>Benford Chi-Square (df=8)</span>
                        <span class='metric-val'>{:.2} (p={:.4}) {}</span>
                    </div>
                    <div class='metric-box'>
                        <span class='metric-label'>CERT-In 6-Hr SLA</span>
                        <span class='metric-val'>{:.1}% Compliance {}</span>
                    </div>
                    <div class='metric-box'>
                        <span class='metric-label'>Shannon Entropy H(X)</span>
                        <span class='metric-val'>{:.2} bits ({:.0}%) {}</span>
                    </div>
                    <div class='metric-box'>
                        <span class='metric-label'>MinHash Collusion Clusters</span>
                        <span class='metric-val'>{} Clusters (J &ge; 0.75)</span>
                    </div>
                    <div class='metric-box'>
                        <span class='metric-label'>Poisson Burst Closures</span>
                        <span class='metric-val'>{} Bursts ({:.1}%)</span>
                    </div>
                    <div class='metric-box'>
                        <span class='metric-label'>MITRE Tactic Coverage</span>
                        <span class='metric-val'>{}/{} ({:.0}%)</span>
                    </div>
                </div>
                <div class='metric-detail'>
                    <strong>Critical Blind Spots:</strong> {}
                </div>
            </div>",
            escape_html(&sota.entity_id),
            sota.benford.chi_square_stat,
            sota.benford.p_value,
            benford_status,
            sota.certin_compliance.compliance_rate,
            certin_status,
            sota.shannon_entropy.entropy,
            sota.shannon_entropy.normalized_entropy * 100.0,
            entropy_status,
            sota.minhash_clusters.len(),
            sota.shift_dump.burst_closures_count,
            sota.shift_dump.burst_ratio,
            sota.mitre_attack.covered_tactics,
            sota.mitre_attack.total_tactics,
            sota.mitre_attack.coverage_density * 100.0,
            escape_html(&blind_spots_str)
        ));
    }

    let mut findings_html = String::new();
    for f in &analysis_data.findings {
        let badge_class = match f.severity.as_str() {
            "CRITICAL" => "badge-critical",
            "HIGH" => "badge-high",
            "MODERATE" => "badge-moderate",
            _ => "badge-low",
        };
        findings_html.push_str(&format!(
            "<div class='finding-card'>
                <div class='finding-header'>
                    <span class='finding-title'>{} - {}</span>
                    <span class='badge {}'>{}</span>
                </div>
                <p class='finding-desc'>{}</p>
                <div class='explain-box'><strong>Explainability:</strong> {}</div>
            </div>",
            escape_html(&f.entity_id),
            escape_html(&f.title),
            badge_class,
            escape_html(&f.severity),
            escape_html(&f.description),
            escape_html(f.explainability_notes.as_deref().unwrap_or("N/A"))
        ));
    }

    let seal = &analysis_data.merkle_seal;
    let merkle_html = format!(
        "<div class='seal-box'>
            <div class='seal-title'>&#128274; RFC 6962 CRYPTOGRAPHIC CHAIN-OF-CUSTODY AUDIT SEAL</div>
            <div class='seal-hash'>SHA-256 ROOT DIGEST: {}</div>
            <div class='seal-meta'>Batch: {} | Sealed Records: {} | Sealed At: {} | Algorithm: {} | Status: {}</div>
        </div>",
        escape_html(&seal.root_hash),
        escape_html(&seal.batch_id),
        seal.leaf_count,
        escape_html(&seal.sealed_at),
        escape_html(&seal.signature_algorithm),
        escape_html(&seal.verification_status)
    );

    let html_content = format!(
        "<!DOCTYPE html>
<html>
<head>
    <meta charset='utf-8'/>
    <title>NCIIPC SAT-SA Supervisory Audit Report</title>
    <style>
        body {{ font-family: 'Helvetica Neue', Arial, sans-serif; background: #0f172a; color: #f8fafc; padding: 30px; margin: 0; }}
        .header {{ border-bottom: 2px solid #2563eb; padding-bottom: 15px; margin-bottom: 25px; text-align: center; }}
        .header h1 {{ margin: 0; font-size: 22px; color: #f8fafc; font-weight: bold; }}
        .header p {{ margin: 5px 0 0 0; font-size: 13px; color: #94a3b8; }}
        .seal-box {{ background: #064e3b; border: 1px solid #059669; border-radius: 6px; padding: 12px; margin-bottom: 20px; }}
        .seal-title {{ font-weight: bold; font-size: 12px; color: #a7f3d0; margin-bottom: 4px; }}
        .seal-hash {{ font-family: monospace; font-size: 11px; color: #ffffff; word-break: break-all; margin-bottom: 4px; }}
        .seal-meta {{ font-size: 10px; color: #6ee7b7; }}
        .summary-box {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 15px; margin-bottom: 25px; font-size: 13px; line-height: 1.6; }}
        h2 {{ font-size: 16px; color: #f1f5f9; border-left: 4px solid #2563eb; padding-left: 10px; margin-top: 30px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 12px; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background: #1e293b; color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 11px; }}
        .badge {{ padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 10px; display: inline-block; }}
        .badge-critical {{ background: #7f1d1d; color: #fca5a5; border: 1px solid #b91c1c; }}
        .badge-high {{ background: #7c2d12; color: #fdba74; border: 1px solid #c2410c; }}
        .badge-moderate {{ background: #78350f; color: #fde047; border: 1px solid #a16207; }}
        .badge-low {{ background: #064e3b; color: #6ee7b7; border: 1px solid #047857; }}
        .sota-card {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 14px; margin-bottom: 12px; }}
        .sota-header {{ font-size: 13px; color: #38bdf8; margin-bottom: 8px; font-weight: bold; }}
        .sota-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; font-size: 11px; }}
        .metric-box {{ background: #0f172a; padding: 8px; border-radius: 4px; border: 1px solid #334155; }}
        .metric-label {{ display: block; color: #94a3b8; font-size: 10px; text-transform: uppercase; }}
        .metric-val {{ display: block; font-weight: bold; color: #f8fafc; font-family: monospace; margin-top: 2px; }}
        .metric-detail {{ margin-top: 8px; font-size: 11px; color: #cbd5e1; border-top: 1px solid #334155; padding-top: 6px; }}
        .finding-card {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 15px; margin-bottom: 12px; }}
        .finding-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }}
        .finding-title {{ font-weight: bold; font-size: 13px; color: #f8fafc; }}
        .finding-desc {{ font-size: 12px; color: #cbd5e1; margin-bottom: 8px; line-height: 1.5; }}
        .explain-box {{ background: #0f172a; padding: 8px 12px; border-radius: 6px; font-size: 11px; color: #94a3b8; border: 1px solid #334155; }}
        .footer {{ text-align: center; font-size: 11px; color: #64748b; margin-top: 40px; padding-top: 15px; border-top: 1px solid #334155; }}
    </style>
</head>
<body>
    <div class='header'>
        <h1>NATIONAL CRITICAL INFORMATION INFRASTRUCTURE PROTECTION CENTRE</h1>
        <p>SUPERVISORY ANALYTICS TOOL FOR SOC ASSESSMENT (SAT-SA): AUDIT REPORT (NTRO / NCIIPC)</p>
    </div>

    {}

    <div class='summary-box'>
        <strong>Assessment Timestamp:</strong> {}<br/>
        <strong>Total Critical Sector Entities Assessed:</strong> {}<br/>
        <strong>Entities at High / Critical Risk:</strong> {}<br/>
        <strong>Statutory Framework:</strong> Section 70A & Section 70B, Information Technology Act, 2000<br/>
        <strong>Deployment Mode:</strong> 100% Air-Gapped Offline Examination
    </div>

    <h2>1. Critical Sector Entity (CSE) Supervisory Risk Leaderboard</h2>
    <table>
        <thead>
            <tr>
                <th>Entity ID</th>
                <th>Entity Name</th>
                <th>Sector</th>
                <th>Execution Gap</th>
                <th>Negative Space</th>
                <th>Composite Risk</th>
                <th>Risk Level</th>
            </tr>
        </thead>
        <tbody>
            {}
        </tbody>
    </table>

    <h2>2. Advanced Mathematical & Behavioral Forensics Intelligence (SOTA)</h2>
    {}

    <h2>3. Flagged Operational Weakness Findings & Supervisory Evidence</h2>
    {}

    <div class='footer'>
        CONFIDENTIAL: For NCIIPC Supervisory Examiners & Statutory Auditors Only | SAT-SA v1.0.0
    </div>
</body>
</html>",
        merkle_html,
        timestamp_str,
        analysis_data.total_entities_analyzed,
        analysis_data.entities_at_risk_count,
        profiles_html,
        sota_html,
        findings_html
    );

    fs::write(&sanitized_path, html_content).map_err(|e| e.to_string())?;

    Ok(sanitized_path.to_string_lossy().to_string())
}
