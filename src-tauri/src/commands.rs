use crate::analytics::risk_engine::run_full_supervisory_analysis;
use crate::db::init_db;
use crate::ingestion::{generate_benchmark_cses, ingest_csv_content, save_batch};
use crate::models::{IngestionBatchRequest, IngestionResponse, SupervisoryAnalysisResponse};
use crate::reporting::exporter::{export_html_pdf_report, export_json_package};
use std::sync::Mutex;
use tauri::State;

pub struct AppState {
    pub db_path: String,
    pub cached_analysis: Mutex<Option<SupervisoryAnalysisResponse>>,
}

#[tauri::command]
pub fn health_check() -> serde_json::Value {
    serde_json::json!({
        "status": "OPERATIONAL",
        "service": "SAT-SA: Supervisory Analytics Tool for SOC Assessment",
        "version": "1.0.0",
        "mode": "AIR_GAPPED_SUPERVISORY_ANALYTICS_TAURI_RUST",
        "backend": "Rust + SQLite"
    })
}

#[tauri::command]
pub fn seed_mock_data(state: State<'_, AppState>) -> Result<IngestionResponse, String> {
    let conn = init_db(&state.db_path).map_err(|e| e.to_string())?;
    let batch = generate_benchmark_cses();
    let res = save_batch(&conn, &batch).map_err(|e| e.to_string())?;

    // Invalidate cached analysis upon new data seed
    if let Ok(mut cache) = state.cached_analysis.lock() {
        *cache = None;
    }

    Ok(res)
}

#[tauri::command]
pub fn ingest_csv_data(csv_str: String, state: State<'_, AppState>) -> Result<IngestionResponse, String> {
    let conn = init_db(&state.db_path).map_err(|e| e.to_string())?;
    let res = ingest_csv_content(&conn, &csv_str)?;

    // Invalidate cached analysis upon data import
    if let Ok(mut cache) = state.cached_analysis.lock() {
        *cache = None;
    }

    Ok(res)
}

#[tauri::command]
pub fn ingest_json_data(json_str: String, state: State<'_, AppState>) -> Result<IngestionResponse, String> {
    let conn = init_db(&state.db_path).map_err(|e| e.to_string())?;
    let batch: IngestionBatchRequest = serde_json::from_str(&json_str).map_err(|e| e.to_string())?;
    let res = save_batch(&conn, &batch).map_err(|e| e.to_string())?;

    // Invalidate cached analysis upon data import
    if let Ok(mut cache) = state.cached_analysis.lock() {
        *cache = None;
    }

    Ok(res)
}

#[tauri::command]
pub fn run_supervisory_analysis(state: State<'_, AppState>) -> Result<SupervisoryAnalysisResponse, String> {
    let conn = init_db(&state.db_path).map_err(|e| e.to_string())?;
    let res = run_full_supervisory_analysis(&conn).map_err(|e| e.to_string())?;

    // Cache computed analysis result for consistent export generation
    if let Ok(mut cache) = state.cached_analysis.lock() {
        *cache = Some(res.clone());
    }

    Ok(res)
}

#[tauri::command]
pub fn export_pdf_report(output_path: String, state: State<'_, AppState>) -> Result<String, String> {
    let analysis_data = {
        let cached = state.cached_analysis.lock().ok().and_then(|c| c.clone());
        match cached {
            Some(data) => data,
            None => {
                let conn = init_db(&state.db_path).map_err(|e| e.to_string())?;
                let fresh = run_full_supervisory_analysis(&conn).map_err(|e| e.to_string())?;
                if let Ok(mut cache) = state.cached_analysis.lock() {
                    *cache = Some(fresh.clone());
                }
                fresh
            }
        }
    };
    export_html_pdf_report(&output_path, &analysis_data)
}

#[tauri::command]
pub fn export_json_report_package(output_path: String, state: State<'_, AppState>) -> Result<String, String> {
    let analysis_data = {
        let cached = state.cached_analysis.lock().ok().and_then(|c| c.clone());
        match cached {
            Some(data) => data,
            None => {
                let conn = init_db(&state.db_path).map_err(|e| e.to_string())?;
                let fresh = run_full_supervisory_analysis(&conn).map_err(|e| e.to_string())?;
                if let Ok(mut cache) = state.cached_analysis.lock() {
                    *cache = Some(fresh.clone());
                }
                fresh
            }
        }
    };
    export_json_package(&output_path, &analysis_data)
}
