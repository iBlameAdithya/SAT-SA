import React from 'react';
import { CertInComplianceAnalysis } from '../types/api';
import { FileCheck2, AlertCircle, Clock, ShieldCheck, Scale, Info } from 'lucide-react';

interface CertInComplianceCardProps {
  compliance: CertInComplianceAnalysis | null | undefined;
  entityId: string;
}

export const CertInComplianceCard: React.FC<CertInComplianceCardProps> = ({
  compliance,
  entityId,
}) => {
  if (!compliance) {
    return (
      <div className="bg-white rounded-sm border border-slate-300 p-6 text-center text-xs text-slate-500">
        No CERT-In statutory compliance records for {entityId}.
      </div>
    );
  }

  const { total_critical_incidents, compliant_incidents, breached_incidents, compliance_rate, breaches } = compliance;
  const isFullyCompliant = breached_incidents === 0;

  return (
    <div className="bg-white rounded-sm border border-slate-300 shadow-sm overflow-hidden">
      {/* Official Header */}
      <div className="bg-[#0b2545] text-white px-4 py-3 border-b border-slate-700 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center space-x-2">
          <Scale className="w-5 h-5 text-amber-400" />
          <h3 className="text-sm font-bold tracking-wide uppercase font-serif">
            SECTION 4.0 : CERT-IN 6-HOUR STATUTORY SLA AUDITOR (SEC 70B IT ACT 2000)
          </h3>
        </div>

        <div className="flex items-center space-x-2">
          <span className="text-[10px] font-mono text-slate-300 bg-slate-800 px-2 py-0.5 rounded border border-slate-600">
            MANDATE: &Delta;t &le; 21,600s (6h)
          </span>
          <span
            className={`text-xs font-bold px-2.5 py-0.5 rounded-sm border font-mono flex items-center gap-1.5 ${
              isFullyCompliant
                ? 'bg-emerald-900 text-emerald-100 border-emerald-700'
                : 'bg-red-900 text-red-100 border-red-700'
            }`}
          >
            {isFullyCompliant ? (
              <>
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-300" />
                100% STATUTORY COMPLIANT
              </>
            ) : (
              <>
                <AlertCircle className="w-3.5 h-3.5 text-red-300" />
                {breached_incidents} STATUTORY BREACHES
              </>
            )}
          </span>
        </div>
      </div>

      {/* Statutory Guidance */}
      <div className="p-3 bg-slate-50 border-b border-slate-200 text-xs text-slate-700 flex items-start gap-2">
        <Info className="w-4 h-4 text-blue-700 flex-shrink-0 mt-0.5" />
        <p>
          Mandatory compliance evaluation pursuant to <strong>Section 70B(6) of the Information Technology Act, 2000</strong> and
          <strong> CERT-In Directions 2022 (No. 20(3)/2022-CERT-In)</strong>: all High and Critical cyber incidents must be formally
          reported to CERT-In within <strong>6 hours</strong> of notice.
        </p>
      </div>

      <div className="p-4 space-y-4">
        {/* Compliance Statistics Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="bg-slate-50 p-2.5 rounded border border-slate-200">
            <span className="text-[10px] text-slate-500 font-bold uppercase block">Total Critical Incidents</span>
            <span className="text-lg font-bold font-mono text-slate-800">{total_critical_incidents}</span>
            <span className="text-[10px] text-slate-400 block">High/Critical Severity</span>
          </div>

          <div className="bg-slate-50 p-2.5 rounded border border-slate-200">
            <span className="text-[10px] text-slate-500 font-bold uppercase block">Compliant (&le; 6 Hours)</span>
            <span className="text-lg font-bold font-mono text-emerald-700">{compliant_incidents}</span>
            <span className="text-[10px] text-slate-400 block">Reported in statutory window</span>
          </div>

          <div className="bg-slate-50 p-2.5 rounded border border-slate-200">
            <span className="text-[10px] text-slate-500 font-bold uppercase block">Breached (&gt; 6 Hours)</span>
            <span className={`text-lg font-bold font-mono ${breached_incidents > 0 ? 'text-red-700' : 'text-slate-800'}`}>
              {breached_incidents}
            </span>
            <span className="text-[10px] text-slate-400 block">Statutory Non-Compliance</span>
          </div>

          <div className="bg-slate-50 p-2.5 rounded border border-slate-200">
            <span className="text-[10px] text-slate-500 font-bold uppercase block">Compliance Rate</span>
            <span className={`text-lg font-bold font-mono ${compliance_rate < 100 ? 'text-red-700' : 'text-emerald-700'}`}>
              {compliance_rate.toFixed(1)}%
            </span>
            <span className="text-[10px] text-slate-400 block">National Benchmark: 100.0%</span>
          </div>
        </div>

        {/* Breaches Table */}
        {breaches.length > 0 ? (
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold text-red-900 flex items-center gap-1.5">
                <AlertCircle className="w-4 h-4 text-red-600" />
                <span>Statutory 6-Hour Reporting SLA Violations ({breaches.length})</span>
              </span>
              <span className="text-[10px] font-mono text-red-700 bg-red-100 px-2 py-0.5 rounded border border-red-200">
                PENALTY RISK: SEC 70B(7) IT ACT
              </span>
            </div>

            <div className="overflow-x-auto border border-red-200 rounded">
              <table className="w-full text-left text-xs">
                <thead className="bg-red-50 text-red-900 border-b border-red-200 text-[11px] font-mono font-bold uppercase">
                  <tr>
                    <th className="p-2">Case ID</th>
                    <th className="p-2">Alert ID</th>
                    <th className="p-2">Severity</th>
                    <th className="p-2">Detected At</th>
                    <th className="p-2">Reported At</th>
                    <th className="p-2 text-right">Reporting Latency</th>
                    <th className="p-2 text-right">Breach Excess</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-red-100 bg-white">
                  {breaches.map((b) => {
                    const latencyHours = (b.latency_seconds / 3600).toFixed(1);
                    const excessHours = ((b.latency_seconds - b.statutory_limit_seconds) / 3600).toFixed(1);

                    return (
                      <tr key={b.case_id} className="hover:bg-red-50/40">
                        <td className="p-2 font-mono font-bold text-slate-900">{b.case_id}</td>
                        <td className="p-2 font-mono text-slate-600">{b.alert_id}</td>
                        <td className="p-2 font-mono font-bold text-red-700">{b.severity}</td>
                        <td className="p-2 text-[11px] text-slate-600 font-mono">
                          {new Date(b.detected_at).toLocaleString()}
                        </td>
                        <td className="p-2 text-[11px] text-slate-600 font-mono">
                          {new Date(b.reported_at).toLocaleString()}
                        </td>
                        <td className="p-2 text-right font-mono font-bold text-red-800">
                          {latencyHours} hrs ({b.latency_seconds.toFixed(0)}s)
                        </td>
                        <td className="p-2 text-right font-mono text-red-600 font-bold">
                          +{excessHours} hrs
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            <div className="bg-red-900 text-red-100 p-2.5 rounded text-[11px] font-mono mt-3 border border-red-800">
              <span className="font-bold text-amber-300 block mb-0.5">LEGAL SANCTIONS NOTICE:</span>
              Failure to comply with CERT-In directions under Section 70B(6) attracts statutory penal action under Section 70B(7)
              of the Information Technology Act 2000, including imprisonment for a term up to one year and/or fines up to ₹1,00,000 per violation.
            </div>
          </div>
        ) : (
          <div className="bg-emerald-50 border border-emerald-200 rounded p-4 text-center text-xs text-emerald-800 font-medium flex items-center justify-center gap-2">
            <FileCheck2 className="w-4 h-4 text-emerald-600" />
            <span>All High and Critical security incidents were escalated within the 6-hour statutory window. Full CERT-In compliance verified.</span>
          </div>
        )}
      </div>
    </div>
  );
};
