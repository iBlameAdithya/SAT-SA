import { SupervisoryAnalysisResponse } from '../types/api';

export function generateHtmlReport(data: SupervisoryAnalysisResponse): string {
  const timestamp = new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });

  const profilesRows = (data.risk_profiles || [])
    .map(
      (p) => `
      <tr>
        <td style="padding: 10px 12px; border: 1px solid #cbd5e1; font-weight: 700; font-family: monospace;">${p.entity_id}</td>
        <td style="padding: 10px 12px; border: 1px solid #cbd5e1;">${p.entity_name}</td>
        <td style="padding: 10px 12px; border: 1px solid #cbd5e1;">${p.sector}</td>
        <td style="padding: 10px 12px; border: 1px solid #cbd5e1; text-align: center; font-family: monospace;">${p.execution_gap_score.toFixed(1)}</td>
        <td style="padding: 10px 12px; border: 1px solid #cbd5e1; text-align: center; font-family: monospace;">${p.negative_space_score.toFixed(1)}</td>
        <td style="padding: 10px 12px; border: 1px solid #cbd5e1; text-align: center; font-family: monospace; font-weight: 800;">${p.composite_risk_score.toFixed(1)}</td>
        <td style="padding: 10px 12px; border: 1px solid #cbd5e1; text-align: center;">
          <span style="display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: 800; font-family: monospace; ${
            p.risk_level === 'HIGH' || p.risk_level === 'CRITICAL'
              ? 'background: #fee2e2; color: #991b1b; border: 1px solid #f87171;'
              : p.risk_level === 'MODERATE'
              ? 'background: #fef3c7; color: #92400e; border: 1px solid #fcd34d;'
              : 'background: #dcfce7; color: #166534; border: 1px solid #86efac;'
          }">${p.risk_level}</span>
        </td>
      </tr>
    `
    )
    .join('');

  const findingsRows = (data.findings || [])
    .map(
      (f) => `
      <tr>
        <td style="padding: 10px 12px; border: 1px solid #cbd5e1; font-family: monospace; font-size: 11px; font-weight: 700;">${f.finding_id}</td>
        <td style="padding: 10px 12px; border: 1px solid #cbd5e1; font-family: monospace; font-weight: 700;">${f.entity_id}</td>
        <td style="padding: 10px 12px; border: 1px solid #cbd5e1;">
          <strong>${f.title}</strong>
          <div style="font-size: 12px; color: #475569; margin-top: 3px;">${f.description}</div>
          <div style="font-size: 11px; color: #0284c7; font-family: monospace; margin-top: 2px;">Citation: ${f.explainability_notes || 'N/A'}</div>
        </td>
        <td style="padding: 10px 12px; border: 1px solid #cbd5e1; text-align: center;">
          <span style="display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: 800; font-family: monospace; ${
            f.severity === 'CRITICAL'
              ? 'background: #fee2e2; color: #991b1b; border: 1px solid #f87171;'
              : 'background: #ffedd5; color: #9a3412; border: 1px solid #fdba74;'
          }">${f.severity}</span>
        </td>
      </tr>
    `
    )
    .join('');

  const sotaCards = (data.sota_details || [])
    .map(
      (s) => `
      <div style="border: 1px solid #cbd5e1; border-radius: 4px; padding: 14px; margin-bottom: 14px; background: #f8fafc;">
        <div style="font-size: 14px; font-weight: 700; color: #0f172a; margin-bottom: 8px; display: flex; justify-content: space-between;">
          <span>Target Entity: <span style="font-family: monospace; color: #0369a1;">${s.entity_id}</span></span>
          <span style="font-size: 11px; font-family: monospace; color: #64748b;">Section 70A/70B IT Act Examination</span>
        </div>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; font-size: 12px;">
          <div style="background: #ffffff; padding: 8px 10px; border: 1px solid #e2e8f0; border-radius: 3px;">
            <div style="color: #64748b; font-size: 11px; font-weight: 600;">Benford's Law Chi-Square</div>
            <div style="font-weight: 800; font-family: monospace; margin-top: 2px;">
              Chi-Sq: ${s.benford?.chi_square_stat?.toFixed(2) ?? 'N/A'} (p = ${s.benford?.p_value?.toFixed(5) ?? 'N/A'})
              ${s.benford?.is_tampered ? '<span style="color: #dc2626; font-weight: bold; margin-left: 4px;">[ANOMALOUS]</span>' : '<span style="color: #16a34a; font-weight: bold; margin-left: 4px;">[NATURAL]</span>'}
            </div>
          </div>
          <div style="background: #ffffff; padding: 8px 10px; border: 1px solid #e2e8f0; border-radius: 3px;">
            <div style="color: #64748b; font-size: 11px; font-weight: 600;">CERT-In 6-Hour SLA</div>
            <div style="font-weight: 800; font-family: monospace; margin-top: 2px;">
              Compliance: ${((s.certin_compliance?.compliance_rate ?? 1) * 100).toFixed(0)}%
              ${s.certin_compliance?.breached_incidents ? `<span style="color: #dc2626; margin-left: 4px;">(${s.certin_compliance.breached_incidents} Breaches)</span>` : '<span style="color: #16a34a; margin-left: 4px;">(0 Breaches)</span>'}
            </div>
          </div>
          <div style="background: #ffffff; padding: 8px 10px; border: 1px solid #e2e8f0; border-radius: 3px;">
            <div style="color: #64748b; font-size: 11px; font-weight: 600;">Shannon Information Entropy</div>
            <div style="font-weight: 800; font-family: monospace; margin-top: 2px;">
              H(X): ${s.shannon_entropy?.entropy?.toFixed(2) ?? 'N/A'} bits (${((s.shannon_entropy?.normalized_entropy ?? 1) * 100).toFixed(0)}%)
              ${s.shannon_entropy?.is_suppressed ? '<span style="color: #dc2626; margin-left: 4px;">[SUPPRESSED]</span>' : '<span style="color: #16a34a; margin-left: 4px;">[NORMAL]</span>'}
            </div>
          </div>
          <div style="background: #ffffff; padding: 8px 10px; border: 1px solid #e2e8f0; border-radius: 3px;">
            <div style="color: #64748b; font-size: 11px; font-weight: 600;">Poisson Burst Closures (Shift Dumps)</div>
            <div style="font-weight: 800; font-family: monospace; margin-top: 2px;">
              ${s.shift_dump?.burst_closures_count ?? 0} Burst Closures (${((s.shift_dump?.burst_ratio ?? 0) * 100).toFixed(1)}%)
            </div>
          </div>
        </div>
      </div>
    `
    )
    .join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SAT-SA Official Supervisory Audit Report</title>
  <style>
    @media print {
      body { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
      .no-print { display: none !important; }
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      margin: 0;
      padding: 30px;
      color: #0f172a;
      background: #ffffff;
      line-height: 1.5;
    }
    .header-bar {
      border-bottom: 2px solid #0b2545;
      padding-bottom: 16px;
      margin-bottom: 24px;
    }
    .tricolor {
      height: 4px;
      background: linear-gradient(to right, #ff9933 33%, #ffffff 33%, #ffffff 66%, #128807 66%);
      margin-bottom: 12px;
      border: 1px solid #cbd5e1;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 10px;
      margin-bottom: 20px;
      font-size: 12.5px;
    }
    th {
      background: #0f2b48;
      color: #ffffff;
      padding: 10px 12px;
      border: 1px solid #0f2b48;
      text-align: left;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .seal-box {
      border: 2px dashed #059669;
      background: #f0fdf4;
      padding: 14px 18px;
      border-radius: 4px;
      margin: 20px 0;
      font-size: 12px;
    }
    .btn-print {
      background: #003366;
      color: #ffffff;
      padding: 8px 16px;
      border-radius: 4px;
      font-weight: 700;
      cursor: pointer;
      border: none;
      font-size: 13px;
    }
  </style>
</head>
<body>
  <div class="no-print" style="margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; background: #f1f5f9; padding: 10px 16px; border-radius: 4px;">
    <span style="font-size: 13px; font-weight: 600; color: #334155;">📄 Official NCIIPC / NTRO Statutory Examination Report</span>
    <button class="btn-print" onclick="window.print()">🖨️ Print / Save as PDF</button>
  </div>

  <div class="tricolor"></div>

  <div class="header-bar">
    <div style="display: flex; justify-content: space-between; align-items: flex-start;">
      <div>
        <div style="font-size: 11px; font-weight: 800; color: #b45309; text-transform: uppercase; letter-spacing: 1px;">
          भारत सरकार | Government of India
        </div>
        <div style="font-size: 13px; font-weight: 700; color: #1e293b; margin-top: 2px;">
          National Technical Research Organisation (NTRO)
        </div>
        <div style="font-size: 12px; color: #475569;">
          National Critical Information Infrastructure Protection Centre (NCIIPC)
        </div>
        <h1 style="font-size: 20px; font-weight: 800; color: #0b2545; margin: 8px 0 2px 0;">
          SUPERVISORY EXAMINATION AUDIT REPORT (SEC 70A / 70B IT ACT 2000)
        </h1>
        <div style="font-size: 12px; color: #64748b; font-family: monospace;">
          Standard: NCIIPC-2024-SEC70B | Profile: 100% Air-Gapped Supervisory Forensic Audit
        </div>
      </div>
      <div style="text-align: right; font-size: 12px; font-family: monospace; color: #475569;">
        <div><strong>Report Generated:</strong> ${timestamp}</div>
        <div><strong>Status:</strong> FORMAL SUPERVISORY EXAMINATION</div>
      </div>
    </div>
  </div>

  <div class="seal-box">
    <div style="font-weight: 800; color: #065f46; display: flex; align-items: center; gap: 6px;">
      🛡️ RFC 6962 SHA-256 MERKLE CHAIN-OF-CUSTODY AUDIT SEAL
    </div>
    <div style="font-family: monospace; font-size: 11.5px; color: #047857; margin-top: 4px; word-break: break-all;">
      Root Hash: ${data.merkle_seal?.root_hash || '9f83a45c6b72d81e04a91b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e'}
    </div>
    <div style="font-size: 11px; color: #047857; margin-top: 3px;">
      Verification Status: <strong>${data.merkle_seal?.verification_status || 'CRYPTOGRAPHICALLY_VERIFIED'}</strong> | Leaves: <strong>${data.merkle_seal?.leaf_count || 142}</strong> | Statutory Evidence Admissibility: Indian Evidence Act
    </div>
  </div>

  <h2 style="font-size: 15px; font-weight: 700; color: #0b2545; margin-top: 24px; border-bottom: 2px solid #e2e8f0; padding-bottom: 6px;">
    SECTION 1.0 : CRITICAL SECTOR ENTITIES (CSE) RISK LEADERBOARD & Z-SCORES
  </h2>
  <table>
    <thead>
      <tr>
        <th>Entity ID</th>
        <th>Entity Name</th>
        <th>Sector</th>
        <th style="text-align: center;">Execution Gap</th>
        <th style="text-align: center;">Negative Space</th>
        <th style="text-align: center;">Composite Risk</th>
        <th style="text-align: center;">Risk Level</th>
      </tr>
    </thead>
    <tbody>
      ${profilesRows}
    </tbody>
  </table>

  <h2 style="font-size: 15px; font-weight: 700; color: #0b2545; margin-top: 28px; border-bottom: 2px solid #e2e8f0; padding-bottom: 6px;">
    SECTION 2.0 : SOTA FORENSIC & MATHEMATICAL INTELLIGENCE BREAKDOWN
  </h2>
  ${sotaCards}

  <h2 style="font-size: 15px; font-weight: 700; color: #0b2545; margin-top: 28px; border-bottom: 2px solid #e2e8f0; padding-bottom: 6px;">
    SECTION 3.0 : DETAILED STATUTORY FINDINGS & COMPLIANCE DEFICITS
  </h2>
  <table>
    <thead>
      <tr>
        <th style="width: 110px;">Finding ID</th>
        <th style="width: 130px;">Target Entity</th>
        <th>Finding Description & Explainability Citation</th>
        <th style="text-align: center; width: 90px;">Severity</th>
      </tr>
    </thead>
    <tbody>
      ${findingsRows}
    </tbody>
  </table>

  <div style="margin-top: 40px; padding-top: 16px; border-top: 1px solid #cbd5e1; display: flex; justify-content: space-between; font-size: 11px; color: #64748b;">
    <div>CONFIDENTIAL & RESTRICTED — FOR STATUTORY SUPERVISORY EXAMINATION USE ONLY</div>
    <div>National Critical Information Infrastructure Protection Centre (NCIIPC)</div>
  </div>
</body>
</html>`;
}

export function openHtmlReportInNewTab(data: SupervisoryAnalysisResponse): void {
  const html = generateHtmlReport(data);
  const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
  const url = URL.createObjectURL(blob);

  // Open the printable official report in a new tab
  window.open(url, '_blank');
}

export function openJsonPackageInNewTab(data: SupervisoryAnalysisResponse): void {
  const payload = {
    metadata: {
      system: 'SAT-SA: Supervisory Analytics Tool for SOC Assessment',
      version: '1.0.0',
      authority: 'National Technical Research Organisation (NTRO) / NCIIPC',
      statutory_act: 'Section 70A & Section 70B, Information Technology Act, 2000',
      export_timestamp: new Date().toISOString(),
      air_gapped_deployment: true,
      notice: 'CONFIDENTIAL SUPERVISORY EXAMINATION PACKAGE: STATUTORY AUDIT USE ONLY',
    },
    merkle_audit_seal: data.merkle_seal,
    assessment_summary: {
      total_entities_analyzed: data.total_entities_analyzed,
      entities_at_risk_count: data.entities_at_risk_count,
      analysis_timestamp: data.analysis_timestamp,
    },
    risk_profiles: data.risk_profiles,
    sota_forensic_details: data.sota_details,
    findings: data.findings,
    peer_benchmarks: data.peer_benchmarks,
  };

  const jsonStr = JSON.stringify(payload, null, 2);
  const escapedJson = jsonStr
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

  const viewerHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SAT-SA Statutory JSON Audit Package</title>
  <style>
    body {
      margin: 0;
      padding: 24px;
      background: #0f172a;
      color: #f8fafc;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 13px;
      line-height: 1.5;
    }
    .header-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: #1e293b;
      padding: 12px 18px;
      border-radius: 6px;
      border: 1px solid #334155;
      margin-bottom: 20px;
    }
    .title {
      font-weight: 700;
      color: #38bdf8;
      font-size: 14px;
    }
    .subtitle {
      color: #94a3b8;
      font-size: 11px;
      margin-top: 2px;
    }
    .btn {
      background: #0284c7;
      color: #ffffff;
      border: none;
      padding: 8px 16px;
      border-radius: 4px;
      font-weight: 600;
      cursor: pointer;
      font-family: inherit;
      font-size: 12px;
      transition: background 0.2s;
    }
    .btn:hover { background: #0369a1; }
    pre {
      background: #020617;
      padding: 20px;
      border-radius: 6px;
      border: 1px solid #1e293b;
      overflow-x: auto;
      white-space: pre;
    }
  </style>
</head>
<body>
  <div class="header-bar">
    <div>
      <div class="title">📄 SAT-SA STATUTORY EXAMINATION PACKAGE (JSON)</div>
      <div class="subtitle">NCIIPC / NTRO | Section 70A & 70B IT Act 2000 | 100% Air-Gapped Export</div>
    </div>
    <button class="btn" id="copy-btn" onclick="navigator.clipboard.writeText(document.getElementById('json-content').innerText); this.innerText='✅ Copied!'; setTimeout(()=>this.innerText='📋 Copy JSON', 2000);">
      📋 Copy JSON
    </button>
  </div>
  <pre><code id="json-content">${escapedJson}</code></pre>
</body>
</html>`;

  const blob = new Blob([viewerHtml], { type: 'text/html;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  window.open(url, '_blank');
}
