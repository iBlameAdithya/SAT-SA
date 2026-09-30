import { IngestionResponse, SupervisoryAnalysisResponse } from '../types/api';

const MOCK_SUPERVISORY_RESPONSE: SupervisoryAnalysisResponse = {
  total_entities_analyzed: 3,
  entities_at_risk_count: 2,
  analysis_timestamp: new Date().toISOString(),
  risk_profiles: [
    {
      entity_id: 'CSE-POWERGRID',
      entity_name: 'National Power Transmission Grid Corp',
      sector: 'Energy & Power',
      execution_gap_score: 85.0,
      negative_space_score: 40.0,
      composite_risk_score: 62.5,
      risk_level: 'HIGH',
      z_score_overall: 1.28,
      findings_count: 3,
      findings_by_severity: { CRITICAL: 1, HIGH: 2 },
      breakdown_json: {},
    },
    {
      entity_id: 'CSE-NATBANK',
      entity_name: 'National Financial Infrastructure Bank',
      sector: 'Banking & Finance',
      execution_gap_score: 20.0,
      negative_space_score: 75.0,
      composite_risk_score: 47.5,
      risk_level: 'MODERATE',
      z_score_overall: 0.45,
      findings_count: 2,
      findings_by_severity: { CRITICAL: 1, HIGH: 1 },
      breakdown_json: {},
    },
    {
      entity_id: 'CSE-TELECOM',
      entity_name: 'Bharat National Telecom Infrastructure',
      sector: 'Telecommunications',
      execution_gap_score: 5.0,
      negative_space_score: 10.0,
      composite_risk_score: 7.5,
      risk_level: 'LOW',
      z_score_overall: -0.81,
      findings_count: 0,
      findings_by_severity: {},
      breakdown_json: {},
    },
  ],
  findings: [
    {
      finding_id: 'FIND-PG-001',
      entity_id: 'CSE-POWERGRID',
      finding_type: 'EXECUTION_GAP',
      rule_code: 'FAST_TICKET_CLOSURE',
      title: 'Superficial Ticket Closure (25.0s closure duration)',
      severity: 'CRITICAL',
      confidence: 0.95,
      description: 'Case CAS-PG-001 for Critical Unauthorized Access alert closed in 25.0 seconds without investigation.',
      explainability_notes: 'Section 70B IT Act 2000 - Audit Clause 4.2',
      supporting_evidence: { case_id: 'CAS-PG-001', duration_seconds: 25.0 },
    },
    {
      finding_id: 'FIND-PG-002',
      entity_id: 'CSE-POWERGRID',
      finding_type: 'EXECUTION_GAP',
      rule_code: 'DUPLICATE_NOTES_TFIDF',
      title: 'Copy-Pasted Resolution Notes (TF-IDF Similarity: 98.4%)',
      severity: 'HIGH',
      confidence: 0.98,
      description: 'Multiple investigation notes match verbatim across separate alerts.',
      explainability_notes: 'Section 70B IT Act 2000 - Audit Clause 4.5',
      supporting_evidence: { cosine_similarity: 0.984, matching_case_id: 'CAS-PG-004' },
    },
    {
      finding_id: 'FIND-NB-001',
      entity_id: 'CSE-NATBANK',
      finding_type: 'NEGATIVE_SPACE',
      rule_code: 'MISSING_MANDATORY_THREAT_CATEGORY',
      title: 'Telemetry Blind Spot: Zero Malware or Ransomware Alerts',
      severity: 'CRITICAL',
      confidence: 0.90,
      description: 'Entity logs zero alerts for Malware or Ransomware over 90-day evaluation window.',
      explainability_notes: 'NCIIPC Security Guideline 2024 - Telemetry Coverage',
      supporting_evidence: { missing_categories: ['MALWARE', 'RANSOMWARE', 'EXFILTRATION'] },
    },
    {
      finding_id: 'FIND-NB-002',
      entity_id: 'CSE-NATBANK',
      finding_type: 'NEGATIVE_SPACE',
      rule_code: 'UNMONITORED_CRITICAL_SUBNET',
      title: 'Unmonitored Subnet 10.200.0.0/16',
      severity: 'HIGH',
      confidence: 0.88,
      description: 'Core financial subnet 10.200.0.0/16 shows zero logged events or alerts.',
      explainability_notes: 'NCIIPC Security Guideline 2024 - Subnet Monitoring',
      supporting_evidence: { unmonitored_subnet: '10.200.0.0/16' },
    },
  ],
  peer_benchmarks: [
    {
      entity_id: 'CSE-POWERGRID',
      entity_name: 'National Power Transmission Grid Corp',
      sector: 'Energy & Power',
      alert_volume: 45,
      avg_resolution_seconds: 245.0,
      fast_closure_rate: 0.85,
      copy_paste_note_rate: 0.72,
      unescalated_critical_rate: 0.60,
      zero_telemetry_asset_count: 0,
      missing_category_count: 0,
      z_score: 1.28,
      risk_rank: 1,
    },
    {
      entity_id: 'CSE-NATBANK',
      entity_name: 'National Financial Infrastructure Bank',
      sector: 'Banking & Finance',
      alert_volume: 35,
      avg_resolution_seconds: 1800.0,
      fast_closure_rate: 0.05,
      copy_paste_note_rate: 0.10,
      unescalated_critical_rate: 0.15,
      zero_telemetry_asset_count: 12,
      missing_category_count: 3,
      z_score: 0.45,
      risk_rank: 2,
    },
    {
      entity_id: 'CSE-TELECOM',
      entity_name: 'Bharat National Telecom Infrastructure',
      sector: 'Telecommunications',
      alert_volume: 25,
      avg_resolution_seconds: 2800.0,
      fast_closure_rate: 0.0,
      copy_paste_note_rate: 0.0,
      unescalated_critical_rate: 0.0,
      zero_telemetry_asset_count: 0,
      missing_category_count: 0,
      z_score: -0.81,
      risk_rank: 3,
    },
  ],
  sota_details: [
    {
      entity_id: 'CSE-POWERGRID',
      benford: {
        entity_id: 'CSE-POWERGRID',
        total_samples: 45,
        distribution: [
          { digit: 1, observed_count: 6, observed_freq: 0.133, expected_freq: 0.301 },
          { digit: 2, observed_count: 22, observed_freq: 0.489, expected_freq: 0.176 },
          { digit: 3, observed_count: 6, observed_freq: 0.133, expected_freq: 0.125 },
          { digit: 4, observed_count: 4, observed_freq: 0.089, expected_freq: 0.097 },
          { digit: 5, observed_count: 3, observed_freq: 0.067, expected_freq: 0.079 },
          { digit: 6, observed_count: 2, observed_freq: 0.044, expected_freq: 0.067 },
          { digit: 7, observed_count: 1, observed_freq: 0.022, expected_freq: 0.058 },
          { digit: 8, observed_count: 1, observed_freq: 0.022, expected_freq: 0.051 },
          { digit: 9, observed_count: 0, observed_freq: 0.0, expected_freq: 0.046 },
        ],
        chi_square_stat: 34.82,
        p_value: 0.00004,
        is_tampered: true,
      },
      shift_dump: {
        entity_id: 'CSE-POWERGRID',
        burst_closures_count: 24,
        total_closed_cases: 45,
        burst_ratio: 0.533,
        clusters: [
          {
            investigator_id: 'INV-4029',
            window_start: '2026-09-24T17:45:00Z',
            window_end: '2026-09-24T17:50:00Z',
            tickets_closed: 8,
            avg_duration_seconds: 32.5,
          },
          {
            investigator_id: 'INV-1082',
            window_start: '2026-09-24T23:50:00Z',
            window_end: '2026-09-24T23:55:00Z',
            tickets_closed: 6,
            avg_duration_seconds: 28.0,
          },
        ],
        flagged_investigators: ['INV-4029', 'INV-1082'],
      },
      minhash_clusters: [
        {
          cluster_id: 'MHC-PG-001',
          sample_note: 'Alert verified as legitimate background maintenance activity. No anomalous lateral telemetry observed. Ticket closed.',
          case_ids: ['CAS-PG-001', 'CAS-PG-004', 'CAS-PG-012', 'CAS-PG-019'],
          investigator_ids: ['INV-4029', 'INV-1082'],
          note_count: 14,
          similarity_score: 0.94,
        },
      ],
      shannon_entropy: {
        entity_id: 'CSE-POWERGRID',
        entropy: 1.12,
        max_possible_entropy: 2.58,
        normalized_entropy: 0.434,
        alert_count: 45,
        category_frequencies: [
          { category: 'AUTH_FAILURE', count: 32, probability: 0.711 },
          { category: 'PORT_SCAN', count: 8, probability: 0.178 },
          { category: 'POLICY_VIOLATION', count: 5, probability: 0.111 },
        ],
        is_suppressed: true,
      },
      mitre_attack: {
        entity_id: 'CSE-POWERGRID',
        total_tactics: 11,
        covered_tactics: 4,
        coverage_density: 0.364,
        tactical_breakdown: [
          { tactic_id: 'TA0001', tactic_name: 'Initial Access', alert_count: 18, is_covered: true },
          { tactic_id: 'TA0002', tactic_name: 'Execution', alert_count: 7, is_covered: true },
          { tactic_id: 'TA0003', tactic_name: 'Persistence', alert_count: 0, is_covered: false },
          { tactic_id: 'TA0004', tactic_name: 'Privilege Escalation', alert_count: 4, is_covered: true },
          { tactic_id: 'TA0005', tactic_name: 'Defense Evasion', alert_count: 0, is_covered: false },
          { tactic_id: 'TA0006', tactic_name: 'Credential Access', alert_count: 0, is_covered: false },
          { tactic_id: 'TA0007', tactic_name: 'Discovery', alert_count: 16, is_covered: true },
          { tactic_id: 'TA0008', tactic_name: 'Lateral Movement', alert_count: 0, is_covered: false },
          { tactic_id: 'TA0009', tactic_name: 'Collection', alert_count: 0, is_covered: false },
          { tactic_id: 'TA0010', tactic_name: 'Exfiltration', alert_count: 0, is_covered: false },
          { tactic_id: 'TA0040', tactic_name: 'Impact', alert_count: 0, is_covered: false },
        ],
        critical_blind_spots: ['TA0003: Persistence', 'TA0006: Credential Access', 'TA0008: Lateral Movement', 'TA0010: Exfiltration'],
      },
      certin_compliance: {
        entity_id: 'CSE-POWERGRID',
        total_critical_incidents: 12,
        compliant_incidents: 4,
        breached_incidents: 8,
        compliance_rate: 0.333,
        breaches: [
          {
            case_id: 'CAS-PG-001',
            alert_id: 'ALT-PG-088',
            severity: 'CRITICAL',
            detected_at: '2026-09-20T04:12:00Z',
            reported_at: '2026-09-20T14:45:00Z',
            latency_seconds: 37980,
            statutory_limit_seconds: 21600,
            statutory_citation: 'Section 70B(6) IT Act 2000 & CERT-In Directions 2022',
          },
          {
            case_id: 'CAS-PG-007',
            alert_id: 'ALT-PG-104',
            severity: 'CRITICAL',
            detected_at: '2026-09-21T09:00:00Z',
            reported_at: '2026-09-21T18:30:00Z',
            latency_seconds: 34200,
            statutory_limit_seconds: 21600,
            statutory_citation: 'Section 70B(6) IT Act 2000 & CERT-In Directions 2022',
          },
        ],
      },
    },
    {
      entity_id: 'CSE-NATBANK',
      benford: {
        entity_id: 'CSE-NATBANK',
        total_samples: 35,
        distribution: [
          { digit: 1, observed_count: 10, observed_freq: 0.286, expected_freq: 0.301 },
          { digit: 2, observed_count: 7, observed_freq: 0.200, expected_freq: 0.176 },
          { digit: 3, observed_count: 5, observed_freq: 0.143, expected_freq: 0.125 },
          { digit: 4, observed_count: 3, observed_freq: 0.086, expected_freq: 0.097 },
          { digit: 5, observed_count: 3, observed_freq: 0.086, expected_freq: 0.079 },
          { digit: 6, observed_count: 2, observed_freq: 0.057, expected_freq: 0.067 },
          { digit: 7, observed_count: 2, observed_freq: 0.057, expected_freq: 0.058 },
          { digit: 8, observed_count: 2, observed_freq: 0.057, expected_freq: 0.051 },
          { digit: 9, observed_count: 1, observed_freq: 0.029, expected_freq: 0.046 },
        ],
        chi_square_stat: 1.18,
        p_value: 0.997,
        is_tampered: false,
      },
      shift_dump: {
        entity_id: 'CSE-NATBANK',
        burst_closures_count: 2,
        total_closed_cases: 35,
        burst_ratio: 0.057,
        clusters: [],
        flagged_investigators: [],
      },
      minhash_clusters: [],
      shannon_entropy: {
        entity_id: 'CSE-NATBANK',
        entropy: 0.88,
        max_possible_entropy: 2.58,
        normalized_entropy: 0.341,
        alert_count: 35,
        category_frequencies: [
          { category: 'AUTH_FAILURE', count: 28, probability: 0.800 },
          { category: 'POLICY_VIOLATION', count: 7, probability: 0.200 },
        ],
        is_suppressed: true,
      },
      mitre_attack: {
        entity_id: 'CSE-NATBANK',
        total_tactics: 11,
        covered_tactics: 3,
        coverage_density: 0.273,
        tactical_breakdown: [
          { tactic_id: 'TA0001', tactic_name: 'Initial Access', alert_count: 20, is_covered: true },
          { tactic_id: 'TA0002', tactic_name: 'Execution', alert_count: 0, is_covered: false },
          { tactic_id: 'TA0003', tactic_name: 'Persistence', alert_count: 0, is_covered: false },
          { tactic_id: 'TA0004', tactic_name: 'Privilege Escalation', alert_count: 8, is_covered: true },
          { tactic_id: 'TA0005', tactic_name: 'Defense Evasion', alert_count: 7, is_covered: true },
          { tactic_id: 'TA0006', tactic_name: 'Credential Access', alert_count: 0, is_covered: false },
          { tactic_id: 'TA0007', tactic_name: 'Discovery', alert_count: 0, is_covered: false },
          { tactic_id: 'TA0008', tactic_name: 'Lateral Movement', alert_count: 0, is_covered: false },
          { tactic_id: 'TA0009', tactic_name: 'Collection', alert_count: 0, is_covered: false },
          { tactic_id: 'TA0010', tactic_name: 'Exfiltration', alert_count: 0, is_covered: false },
          { tactic_id: 'TA0040', tactic_name: 'Impact', alert_count: 0, is_covered: false },
        ],
        critical_blind_spots: ['TA0002: Execution', 'TA0006: Credential Access', 'TA0008: Lateral Movement', 'TA0010: Exfiltration'],
      },
      certin_compliance: {
        entity_id: 'CSE-NATBANK',
        total_critical_incidents: 8,
        compliant_incidents: 6,
        breached_incidents: 2,
        compliance_rate: 0.75,
        breaches: [
          {
            case_id: 'CAS-NB-003',
            alert_id: 'ALT-NB-014',
            severity: 'CRITICAL',
            detected_at: '2026-09-22T02:00:00Z',
            reported_at: '2026-09-22T10:15:00Z',
            latency_seconds: 29700,
            statutory_limit_seconds: 21600,
            statutory_citation: 'Section 70B(6) IT Act 2000 & CERT-In Directions 2022',
          },
        ],
      },
    },
    {
      entity_id: 'CSE-TELECOM',
      benford: {
        entity_id: 'CSE-TELECOM',
        total_samples: 25,
        distribution: [
          { digit: 1, observed_count: 8, observed_freq: 0.320, expected_freq: 0.301 },
          { digit: 2, observed_count: 4, observed_freq: 0.160, expected_freq: 0.176 },
          { digit: 3, observed_count: 3, observed_freq: 0.120, expected_freq: 0.125 },
          { digit: 4, observed_count: 3, observed_freq: 0.120, expected_freq: 0.097 },
          { digit: 5, observed_count: 2, observed_freq: 0.080, expected_freq: 0.079 },
          { digit: 6, observed_count: 2, observed_freq: 0.080, expected_freq: 0.067 },
          { digit: 7, observed_count: 1, observed_freq: 0.040, expected_freq: 0.058 },
          { digit: 8, observed_count: 1, observed_freq: 0.040, expected_freq: 0.051 },
          { digit: 9, observed_count: 1, observed_freq: 0.040, expected_freq: 0.046 },
        ],
        chi_square_stat: 0.82,
        p_value: 0.999,
        is_tampered: false,
      },
      shift_dump: {
        entity_id: 'CSE-TELECOM',
        burst_closures_count: 0,
        total_closed_cases: 25,
        burst_ratio: 0.0,
        clusters: [],
        flagged_investigators: [],
      },
      minhash_clusters: [],
      shannon_entropy: {
        entity_id: 'CSE-TELECOM',
        entropy: 2.32,
        max_possible_entropy: 2.58,
        normalized_entropy: 0.899,
        alert_count: 25,
        category_frequencies: [
          { category: 'AUTH_FAILURE', count: 6, probability: 0.24 },
          { category: 'MALWARE', count: 5, probability: 0.20 },
          { category: 'POLICY_VIOLATION', count: 4, probability: 0.16 },
          { category: 'PORT_SCAN', count: 4, probability: 0.16 },
          { category: 'EXFILTRATION', count: 3, probability: 0.12 },
          { category: 'RANSOMWARE', count: 3, probability: 0.12 },
        ],
        is_suppressed: false,
      },
      mitre_attack: {
        entity_id: 'CSE-TELECOM',
        total_tactics: 11,
        covered_tactics: 9,
        coverage_density: 0.818,
        tactical_breakdown: [
          { tactic_id: 'TA0001', tactic_name: 'Initial Access', alert_count: 6, is_covered: true },
          { tactic_id: 'TA0002', tactic_name: 'Execution', alert_count: 5, is_covered: true },
          { tactic_id: 'TA0003', tactic_name: 'Persistence', alert_count: 3, is_covered: true },
          { tactic_id: 'TA0004', tactic_name: 'Privilege Escalation', alert_count: 4, is_covered: true },
          { tactic_id: 'TA0005', tactic_name: 'Defense Evasion', alert_count: 2, is_covered: true },
          { tactic_id: 'TA0006', tactic_name: 'Credential Access', alert_count: 2, is_covered: true },
          { tactic_id: 'TA0007', tactic_name: 'Discovery', alert_count: 3, is_covered: true },
          { tactic_id: 'TA0008', tactic_name: 'Lateral Movement', alert_count: 0, is_covered: false },
          { tactic_id: 'TA0009', tactic_name: 'Collection', alert_count: 0, is_covered: false },
          { tactic_id: 'TA0010', tactic_name: 'Exfiltration', alert_count: 2, is_covered: true },
          { tactic_id: 'TA0040', tactic_name: 'Impact', alert_count: 3, is_covered: true },
        ],
        critical_blind_spots: ['TA0008: Lateral Movement', 'TA0009: Collection'],
      },
      certin_compliance: {
        entity_id: 'CSE-TELECOM',
        total_critical_incidents: 5,
        compliant_incidents: 5,
        breached_incidents: 0,
        compliance_rate: 1.0,
        breaches: [],
      },
    },
  ],
  merkle_seal: {
    batch_id: 'NCIIPC-BATCH-AUDIT-2026',
    root_hash: '9f83a45c6b72d81e04a91b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e',
    leaf_count: 142,
    sealed_at: new Date().toISOString(),
    verification_status: 'CRYPTOGRAPHICALLY_VERIFIED',
    signature_algorithm: 'RFC 6962 SHA-256 Merkle Tree Domain Separation',
  },
};

async function invokeTauriCommand<T>(cmd: string, args?: Record<string, any>): Promise<T> {
  if (typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window) {
    const { invoke } = await import('@tauri-apps/api/core');
    return invoke<T>(cmd, args);
  } else {
    // Browser Fallback Mode for web browser & Playwright end-to-end testing
    console.warn(`[Browser Fallback] Executing command '${cmd}' with structured response`);

    if (cmd === 'health_check') {
      return 'SAT-SA Supervisory Audit Engine Active (Air-Gapped Offline Mode)' as unknown as T;
    }
    if (cmd === 'seed_mock_data' || cmd === 'ingest_json_data' || cmd === 'ingest_csv_data') {
      return {
        status: 'SUCCESS',
        total_entities_ingested: 3,
        total_alerts_ingested: 105,
        total_cases_ingested: 105,
        message: 'Dataset parsed and ingested into SQLite database.',
      } as unknown as T;
    }
    if (cmd === 'run_supervisory_analysis') {
      return MOCK_SUPERVISORY_RESPONSE as unknown as T;
    }
    if (cmd === 'export_pdf_report') {
      return 'exports/satsa_supervisory_audit_report.html' as unknown as T;
    }
    if (cmd === 'export_json_report_package') {
      return 'exports/satsa_export_package.json' as unknown as T;
    }
    throw new Error(`Command '${cmd}' not supported in browser fallback.`);
  }
}

export async function healthCheck() {
  return invokeTauriCommand('health_check');
}

export async function seedMockData(): Promise<IngestionResponse> {
  return invokeTauriCommand<IngestionResponse>('seed_mock_data');
}

export async function ingestJsonData(jsonStr: string): Promise<IngestionResponse> {
  return invokeTauriCommand<IngestionResponse>('ingest_json_data', { jsonStr });
}

export async function ingestCsvData(csvStr: string): Promise<IngestionResponse> {
  return invokeTauriCommand<IngestionResponse>('ingest_csv_data', { csvStr });
}

export async function runSupervisoryAnalysis(): Promise<SupervisoryAnalysisResponse> {
  return invokeTauriCommand<SupervisoryAnalysisResponse>('run_supervisory_analysis');
}

export async function exportPdfReport(outputPath: string): Promise<string> {
  return invokeTauriCommand<string>('export_pdf_report', { outputPath });
}

export async function exportJsonPackage(outputPath: string): Promise<string> {
  return invokeTauriCommand<string>('export_json_report_package', { outputPath });
}
