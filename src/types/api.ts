export interface Finding {
  finding_id: string;
  entity_id: string;
  finding_type: 'EXECUTION_GAP' | 'NEGATIVE_SPACE' | 'REGULATORY_BREACH';
  rule_code: string;
  title: string;
  severity: 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';
  confidence: number;
  description: string;
  explainability_notes?: string;
  supporting_evidence?: Record<string, any>;
  created_at?: string;
}

export interface BenfordDigitFreq {
  digit: number;
  observed_count: number;
  observed_freq: number;
  expected_freq: number;
}

export interface BenfordAnalysis {
  entity_id: string;
  total_samples: number;
  distribution: BenfordDigitFreq[];
  chi_square_stat: number;
  p_value: number;
  is_tampered: boolean;
}

export interface BurstCluster {
  investigator_id: string;
  window_start: string;
  window_end: string;
  tickets_closed: number;
  avg_duration_seconds: number;
}

export interface ShiftDumpAnalysis {
  entity_id: string;
  burst_closures_count: number;
  total_closed_cases: number;
  burst_ratio: number;
  clusters: BurstCluster[];
  flagged_investigators: string[];
}

export interface MinHashNoteCluster {
  cluster_id: string;
  sample_note: string;
  case_ids: string[];
  investigator_ids: string[];
  note_count: number;
  similarity_score: number;
}

export interface CategoryFrequency {
  category: string;
  count: number;
  probability: number;
}

export interface ShannonEntropyAnalysis {
  entity_id: string;
  entropy: number;
  max_possible_entropy: number;
  normalized_entropy: number;
  alert_count: number;
  category_frequencies: CategoryFrequency[];
  is_suppressed: boolean;
}

export interface MitreTacticCoverage {
  tactic_id: string;
  tactic_name: string;
  alert_count: number;
  is_covered: boolean;
}

export interface MitreAttackAnalysis {
  entity_id: string;
  total_tactics: number;
  covered_tactics: number;
  coverage_density: number;
  tactical_breakdown: MitreTacticCoverage[];
  critical_blind_spots: string[];
}

export interface CertInSlaBreach {
  case_id: string;
  alert_id: string;
  severity: string;
  detected_at: string;
  reported_at: string;
  latency_seconds: number;
  statutory_limit_seconds: number;
  statutory_citation: string;
}

export interface CertInComplianceAnalysis {
  entity_id: string;
  total_critical_incidents: number;
  compliant_incidents: number;
  breached_incidents: number;
  compliance_rate: number;
  breaches: CertInSlaBreach[];
}

export interface MerkleAuditSeal {
  batch_id: string;
  root_hash: string;
  leaf_count: number;
  sealed_at: string;
  verification_status: string;
  signature_algorithm: string;
}

export interface EntitySotaDetails {
  entity_id: string;
  benford: BenfordAnalysis;
  shift_dump: ShiftDumpAnalysis;
  minhash_clusters: MinHashNoteCluster[];
  shannon_entropy: ShannonEntropyAnalysis;
  mitre_attack: MitreAttackAnalysis;
  certin_compliance: CertInComplianceAnalysis;
}

export interface EntityRiskProfile {
  entity_id: string;
  entity_name: string;
  sector: string;
  execution_gap_score: number;
  negative_space_score: number;
  composite_risk_score: number;
  risk_level: 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';
  z_score_overall: number;
  findings_count: number;
  findings_by_severity: Record<string, number>;
  breakdown_json: Record<string, any>;
}

export interface PeerBenchmarkItem {
  entity_id: string;
  entity_name: string;
  sector: string;
  alert_volume: number;
  avg_resolution_seconds: number;
  fast_closure_rate: number;
  copy_paste_note_rate: number;
  unescalated_critical_rate: number;
  zero_telemetry_asset_count: number;
  missing_category_count: number;
  z_score: number;
  risk_rank: number;
}

export interface SupervisoryAnalysisResponse {
  total_entities_analyzed: number;
  analysis_timestamp: string;
  entities_at_risk_count: number;
  risk_profiles: EntityRiskProfile[];
  findings: Finding[];
  peer_benchmarks: PeerBenchmarkItem[];
  sota_details?: EntitySotaDetails[];
  merkle_seal?: MerkleAuditSeal;
}

export interface IngestionResponse {
  status: string;
  total_entities_ingested: number;
  total_alerts_ingested: number;
  total_cases_ingested: number;
  message: string;
}
