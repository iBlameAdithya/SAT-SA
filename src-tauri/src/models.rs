use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entity {
    pub entity_id: String,
    pub name: String,
    pub sector: String,
    pub total_assets: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub alert_id: String,
    pub entity_id: String,
    pub asset_id: String,
    pub subnet: Option<String>,
    pub rule_name: String,
    pub category: String,
    pub severity: String,
    pub timestamp: String,
    #[serde(default)]
    pub mitre_tactic: Option<String>,
    #[serde(default)]
    pub mitre_technique: Option<String>,
    pub raw_payload: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Case {
    pub case_id: String,
    pub alert_id: String,
    pub entity_id: String,
    pub investigator_id: String,
    pub created_at: String,
    pub closed_at: Option<String>,
    pub duration_seconds: Option<f64>,
    pub status: String,
    pub escalated: bool,
    #[serde(default)]
    pub escalated_at: Option<String>,
    pub resolution_notes: Option<String>,
    pub disposition: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenfordDigitFreq {
    pub digit: u32,
    pub observed_count: usize,
    pub observed_freq: f64,
    pub expected_freq: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenfordAnalysis {
    pub entity_id: String,
    pub total_samples: usize,
    pub distribution: Vec<BenfordDigitFreq>,
    pub chi_square_stat: f64,
    pub p_value: f64,
    pub is_tampered: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurstCluster {
    pub investigator_id: String,
    pub window_start: String,
    pub window_end: String,
    pub tickets_closed: usize,
    pub avg_duration_seconds: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShiftDumpAnalysis {
    pub entity_id: String,
    pub burst_closures_count: usize,
    pub total_closed_cases: usize,
    pub burst_ratio: f64,
    pub clusters: Vec<BurstCluster>,
    pub flagged_investigators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryFrequency {
    pub category: String,
    pub count: usize,
    pub probability: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShannonEntropyAnalysis {
    pub entity_id: String,
    pub entropy: f64,
    pub max_possible_entropy: f64,
    pub normalized_entropy: f64,
    pub alert_count: usize,
    pub category_frequencies: Vec<CategoryFrequency>,
    pub is_suppressed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTacticCoverage {
    pub tactic_id: String,
    pub tactic_name: String,
    pub alert_count: usize,
    pub is_covered: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreAttackAnalysis {
    pub entity_id: String,
    pub total_tactics: usize,
    pub covered_tactics: usize,
    pub coverage_density: f64,
    pub tactical_breakdown: Vec<MitreTacticCoverage>,
    pub critical_blind_spots: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertInSlaBreach {
    pub case_id: String,
    pub alert_id: String,
    pub severity: String,
    pub detected_at: String,
    pub reported_at: String,
    pub latency_seconds: f64,
    pub statutory_limit_seconds: f64,
    pub statutory_citation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertInComplianceAnalysis {
    pub entity_id: String,
    pub total_critical_incidents: usize,
    pub compliant_incidents: usize,
    pub breached_incidents: usize,
    pub compliance_rate: f64,
    pub breaches: Vec<CertInSlaBreach>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleAuditSeal {
    pub batch_id: String,
    pub root_hash: String,
    pub leaf_count: usize,
    pub sealed_at: String,
    pub verification_status: String,
    pub signature_algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinHashNoteCluster {
    pub cluster_id: String,
    pub sample_note: String,
    pub case_ids: Vec<String>,
    pub investigator_ids: Vec<String>,
    pub note_count: usize,
    pub similarity_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitySotaDetails {
    pub entity_id: String,
    pub benford: BenfordAnalysis,
    pub shift_dump: ShiftDumpAnalysis,
    pub minhash_clusters: Vec<MinHashNoteCluster>,
    pub shannon_entropy: ShannonEntropyAnalysis,
    pub mitre_attack: MitreAttackAnalysis,
    pub certin_compliance: CertInComplianceAnalysis,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub finding_id: String,
    pub entity_id: String,
    pub finding_type: String, // EXECUTION_GAP, NEGATIVE_SPACE, or REGULATORY_BREACH
    pub rule_code: String,
    pub title: String,
    pub severity: String, // LOW, MODERATE, HIGH, CRITICAL
    pub confidence: f64,
    pub description: String,
    pub explainability_notes: Option<String>,
    pub supporting_evidence: Option<serde_json::Value>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityRiskProfile {
    pub entity_id: String,
    pub entity_name: String,
    pub sector: String,
    pub execution_gap_score: f64,
    pub negative_space_score: f64,
    pub composite_risk_score: f64,
    pub risk_level: String, // LOW, MODERATE, HIGH, CRITICAL
    pub z_score_overall: f64,
    pub findings_count: usize,
    pub findings_by_severity: std::collections::HashMap<String, usize>,
    pub breakdown_json: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerBenchmarkItem {
    pub entity_id: String,
    pub entity_name: String,
    pub sector: String,
    pub alert_volume: usize,
    pub avg_resolution_seconds: f64,
    pub fast_closure_rate: f64,
    pub copy_paste_note_rate: f64,
    pub unescalated_critical_rate: f64,
    pub zero_telemetry_asset_count: usize,
    pub missing_category_count: usize,
    pub z_score: f64,
    pub risk_rank: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupervisoryAnalysisResponse {
    pub total_entities_analyzed: usize,
    pub analysis_timestamp: String,
    pub entities_at_risk_count: usize,
    pub risk_profiles: Vec<EntityRiskProfile>,
    pub findings: Vec<Finding>,
    pub peer_benchmarks: Vec<PeerBenchmarkItem>,
    pub sota_details: Vec<EntitySotaDetails>,
    pub merkle_seal: MerkleAuditSeal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestionBatchRequest {
    pub entities: Vec<Entity>,
    pub alerts: Vec<Alert>,
    pub cases: Vec<Case>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestionResponse {
    pub status: String,
    pub total_entities_ingested: usize,
    pub total_alerts_ingested: usize,
    pub total_cases_ingested: usize,
    pub message: String,
}
