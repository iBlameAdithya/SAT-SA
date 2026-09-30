import React, { useState } from 'react';
import { Finding } from '../types/api';
import { AlertTriangle, Clock, Copy, ShieldAlert, RotateCcw, ChevronDown, ChevronUp, Terminal } from 'lucide-react';

interface ExecutionGapsPanelProps {
  findings: Finding[];
  selectedEntityId: string | null;
}

export const ExecutionGapsPanel: React.FC<ExecutionGapsPanelProps> = ({
  findings,
  selectedEntityId,
}) => {
  const [expandedEvidences, setExpandedEvidences] = useState<Record<string, boolean>>({});

  const toggleEvidence = (findingId: string) => {
    setExpandedEvidences((prev) => ({
      ...prev,
      [findingId]: !prev[findingId],
    }));
  };

  const gapFindings = findings.filter(
    (f) =>
      f.finding_type === 'EXECUTION_GAP' &&
      (!selectedEntityId || f.entity_id === selectedEntityId)
  );

  const getRuleIcon = (ruleCode: string) => {
    switch (ruleCode) {
      case 'FAST_TICKET_CLOSURE':
        return <Clock className="w-4 h-4 text-orange-700" />;
      case 'COPY_PASTE_INVESTIGATION_NOTES':
        return <Copy className="w-4 h-4 text-amber-700" />;
      case 'UNESCALATED_CRITICAL_ALERTS':
        return <ShieldAlert className="w-4 h-4 text-red-700" />;
      case 'REMEDIATION_DEFICIT':
        return <RotateCcw className="w-4 h-4 text-purple-700" />;
      default:
        return <AlertTriangle className="w-4 h-4 text-orange-700" />;
    }
  };

  const getSeverityStyle = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-red-700 text-white border-red-900';
      case 'HIGH':
        return 'bg-orange-700 text-white border-orange-900';
      default:
        return 'bg-amber-600 text-white border-amber-800';
    }
  };

  return (
    <div className="bg-white rounded-sm border border-slate-300 shadow-sm overflow-hidden">
      {/* Official Government Section Header */}
      <div className="bg-[#0b2545] text-white px-4 py-3 border-b border-slate-700 flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <AlertTriangle className="w-5 h-5 text-amber-400" />
          <h3 className="text-sm font-bold tracking-wide uppercase font-serif">
            SECTION 2.0 : EXECUTION GAP DEFICITS (SECTION 70B IT ACT 2000)
          </h3>
        </div>
        <span className="text-xs bg-orange-900 text-orange-100 font-bold px-2.5 py-0.5 rounded-sm border border-orange-700 font-mono">
          {gapFindings.length} DEFICITS FLAGGED
        </span>
      </div>

      <div className="p-4 bg-slate-50 border-b border-slate-200 text-xs text-slate-700">
        Superficial compliance and procedural gaming: fast ticket closures (under 60 seconds), copy-paste investigation notes (Forensic Cosine Similarity &ge; 85%), and unescalated critical alerts.
      </div>

      <div className="p-4">
        {gapFindings.length === 0 ? (
          <div className="bg-slate-50 rounded-sm border border-slate-200 p-6 text-center text-slate-600 text-xs font-medium">
            No Execution Gap deficits detected for the selected entity criteria.
          </div>
        ) : (
          <div className="space-y-3">
            {gapFindings.map((finding) => (
              <div
                key={finding.finding_id}
                className="bg-white rounded-sm border border-slate-300 p-4 hover:border-slate-400 shadow-xs transition"
              >
                <div className="flex items-start justify-between gap-3 mb-2.5 border-b border-slate-200 pb-2">
                  <div className="flex items-center gap-2">
                    <div className="p-1.5 bg-slate-100 rounded-sm border border-slate-300">
                      {getRuleIcon(finding.rule_code)}
                    </div>
                    <div>
                      <h4 className="text-xs font-bold text-slate-900 font-serif">{finding.title}</h4>
                      <span className="text-[10px] text-slate-600 font-mono font-semibold">
                        ENTITY: {finding.entity_id} | CODE: {finding.rule_code}
                      </span>
                    </div>
                  </div>
                  <span
                    className={`text-[10px] font-bold px-2 py-0.5 rounded-sm border uppercase tracking-wider ${getSeverityStyle(
                      finding.severity
                    )}`}
                  >
                    {finding.severity}
                  </span>
                </div>

                <p className="text-xs text-slate-800 mb-3 leading-relaxed font-sans">
                  {finding.description}
                </p>

                {finding.explainability_notes && (
                  <div className="bg-slate-50 rounded-sm p-3 border border-slate-300 text-xs text-slate-700 mb-3">
                    <strong className="text-slate-900 font-semibold block mb-1 text-[11px] uppercase tracking-wider">
                      Statutory Audit Explainability:
                    </strong>
                    {finding.explainability_notes}
                  </div>
                )}

                {finding.supporting_evidence && (
                  <div className="mt-2">
                    <button
                      onClick={() => toggleEvidence(finding.finding_id)}
                      className="flex items-center gap-1.5 text-[11px] font-mono font-bold text-slate-700 hover:text-slate-900 bg-slate-100 hover:bg-slate-200 px-2.5 py-1 rounded border border-slate-300 transition cursor-pointer mb-2"
                    >
                      <Terminal className="w-3.5 h-3.5 text-blue-800" />
                      <span>{expandedEvidences[finding.finding_id] ? 'Hide Evidentiary Trace' : 'Inspect Statutory Forensic Trace'}</span>
                      {expandedEvidences[finding.finding_id] ? (
                        <ChevronUp className="w-3.5 h-3.5" />
                      ) : (
                        <ChevronDown className="w-3.5 h-3.5" />
                      )}
                    </button>
                    {expandedEvidences[finding.finding_id] && (
                      <div className="bg-slate-900 text-slate-100 rounded-sm p-3 border border-slate-800 text-[11px] font-mono animate-in fade-in duration-150">
                        <span className="text-slate-400 block mb-1 font-sans font-bold uppercase tracking-wider text-[10px]">
                          Supporting Evidentiary Data (Supervisory Audit Record):
                        </span>
                        <pre className="overflow-x-auto whitespace-pre-wrap text-amber-300">
                          {JSON.stringify(finding.supporting_evidence, null, 2)}
                        </pre>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
