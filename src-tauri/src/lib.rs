pub mod analytics;
pub mod commands;
pub mod db;
pub mod ingestion;
pub mod models;
pub mod reporting;

use commands::{
    export_json_report_package, export_pdf_report, health_check, ingest_csv_data, ingest_json_data,
    run_supervisory_analysis, seed_mock_data, AppState,
};
use db::init_db;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let db_path = std::env::temp_dir()
        .join("satsa_tauri.db")
        .to_string_lossy()
        .to_string();
    let _ = init_db(&db_path);

    tauri::Builder::default()
        .manage(AppState {
            db_path,
            cached_analysis: std::sync::Mutex::new(None),
        })
        .invoke_handler(tauri::generate_handler![
            health_check,
            seed_mock_data,
            ingest_csv_data,
            ingest_json_data,
            run_supervisory_analysis,
            export_pdf_report,
            export_json_report_package
        ])
        .run(tauri::generate_context!())
        .expect("error while running SAT-SA Tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;
    use analytics::risk_engine::run_full_supervisory_analysis;
    use db::init_db;
    use ingestion::{generate_benchmark_cses, save_batch};
    use reporting::exporter::{export_html_pdf_report, export_json_package};
    use std::fs;

    #[test]
    fn test_satsa_end_to_end_pipeline() {
        let test_db_path = "satsa_test_temp.db";
        let _ = fs::remove_file(test_db_path);

        // 1. Initialize DB
        let conn = init_db(test_db_path).expect("Failed to init SQLite DB");

        // 2. Ingest Benchmark Datasets
        let batch = generate_benchmark_cses();
        let ingest_res = save_batch(&conn, &batch).expect("Failed to save batch");
        assert_eq!(ingest_res.status, "SUCCESS");
        assert_eq!(ingest_res.total_entities_ingested, 3);
        assert_eq!(ingest_res.total_alerts_ingested, 105);

        // 3. Execute Supervisory Analytics
        let analysis_res = run_full_supervisory_analysis(&conn).expect("Failed to run supervisory analysis");
        assert_eq!(analysis_res.total_entities_analyzed, 3);
        assert!(analysis_res.entities_at_risk_count >= 1);

        // 4. Verify Execution Gap & Negative Space Findings
        let pg_profile = analysis_res.risk_profiles.iter().find(|p| p.entity_id == "CSE-POWERGRID").unwrap();
        assert!(pg_profile.execution_gap_score > 0.0);
        assert!(pg_profile.risk_level == "HIGH" || pg_profile.risk_level == "CRITICAL");

        let nb_profile = analysis_res.risk_profiles.iter().find(|p| p.entity_id == "CSE-NATBANK").unwrap();
        assert!(nb_profile.negative_space_score > 0.0);

        let tc_profile = analysis_res.risk_profiles.iter().find(|p| p.entity_id == "CSE-TELECOM").unwrap();
        assert_eq!(tc_profile.risk_level, "LOW");

        // Verify SOTA Forensic Details & Merkle Seal
        assert_eq!(analysis_res.sota_details.len(), 3);
        assert!(!analysis_res.merkle_seal.root_hash.is_empty());
        assert_eq!(analysis_res.merkle_seal.signature_algorithm, "SHA-256 (Merkle Tree RFC 6962)");
        assert!(analysis_res.merkle_seal.leaf_count > 0);

        // 5. Verify Report Exporters
        let pdf_out = "satsa_test_report.html";
        let json_out = "satsa_test_package.json";

        let pdf_path = export_html_pdf_report(pdf_out, &analysis_res).expect("Failed PDF export");
        assert!(fs::metadata(pdf_path).is_ok());

        let json_path = export_json_package(json_out, &analysis_res).expect("Failed JSON export");
        assert!(fs::metadata(json_path).is_ok());

        // Cleanup
        let _ = fs::remove_file(test_db_path);
        let _ = fs::remove_file(pdf_out);
        let _ = fs::remove_file(json_out);
    }

    #[test]
    fn test_security_path_sanitization() {
        use reporting::exporter::sanitize_export_path;

        // Path traversal attempts must be rejected
        assert!(sanitize_export_path("../../../etc/shadow").is_err());
        assert!(sanitize_export_path("exports/../../secret.txt").is_err());
        assert!(sanitize_export_path("..\\windows\\system32").is_err());
        assert!(sanitize_export_path("   ").is_err());

        // Safe export paths should succeed
        let safe = sanitize_export_path("exports/test_audit.html").expect("Valid path rejected");
        assert_eq!(safe.to_string_lossy(), "exports/test_audit.html");
    }

    #[test]
    fn test_security_html_escaping() {
        use reporting::exporter::escape_html;

        let raw = "<script>alert('XSS & injection')</script> \"quotes\"";
        let escaped = escape_html(raw);
        assert!(!escaped.contains('<'));
        assert!(!escaped.contains('>'));
        assert!(!escaped.contains('"'));
        assert!(!escaped.contains('\''));
        assert_eq!(
            escaped,
            "&lt;script&gt;alert(&#x27;XSS &amp; injection&#x27;)&lt;/script&gt; &quot;quotes&quot;"
        );
    }

    #[test]
    fn test_case_escalated_at_preservation() {
        let test_db_path = "satsa_test_esc_temp.db";
        let _ = fs::remove_file(test_db_path);

        let conn = init_db(test_db_path).expect("Failed to init DB");
        let batch = generate_benchmark_cses();
        save_batch(&conn, &batch).expect("Failed to save batch");

        // Verify that cases for CSE-POWERGRID or CSE-TELECOM retain escalated_at
        let mut stmt = conn
            .prepare("SELECT case_id, escalated, escalated_at FROM cases WHERE entity_id = 'CSE-TELECOM' AND escalated = 1 LIMIT 1")
            .unwrap();
        let mut rows = stmt.query([]).unwrap();
        if let Some(row) = rows.next().unwrap() {
            let esc: i32 = row.get(1).unwrap();
            let esc_at: Option<String> = row.get(2).unwrap();
            assert_eq!(esc, 1);
            assert!(esc_at.is_some(), "escalated_at was not saved in DB");
        }

        let _ = fs::remove_file(test_db_path);
    }

    #[test]
    fn test_csv_header_order_independence() {
        let test_db_path = "satsa_test_csv_temp.db";
        let _ = fs::remove_file(test_db_path);

        let conn = init_db(test_db_path).expect("Failed to init DB");

        // Rearranged columns: sector first, then entity_id, name, alert_id, severity, etc.
        let rearranged_csv = "sector,entity_id,entity_name,alert_id,asset_id,severity,category,rule_name,timestamp\n\
Energy,CSE-TEST-REORDER,Test Energy Corp,ALT-R-01,AST-01,CRITICAL,MALWARE,Rule_Malware,2026-09-24T00:00:00Z";

        let ingest_res = ingestion::ingest_csv_content(&conn, rearranged_csv).expect("CSV parse failed");
        assert_eq!(ingest_res.status, "SUCCESS");
        assert_eq!(ingest_res.total_entities_ingested, 1);
        assert_eq!(ingest_res.total_alerts_ingested, 1);

        // Verify entity fields are mapped correctly
        let mut stmt = conn.prepare("SELECT entity_id, name, sector FROM entities WHERE entity_id = 'CSE-TEST-REORDER'").unwrap();
        let entity: (String, String, String) = stmt.query_row([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).unwrap();
        assert_eq!(entity.0, "CSE-TEST-REORDER");
        assert_eq!(entity.1, "Test Energy Corp");
        assert_eq!(entity.2, "Energy");

        let _ = fs::remove_file(test_db_path);
    }
}
