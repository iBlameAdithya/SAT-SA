import React from 'react';
import { MitreAttackAnalysis } from '../types/api';
import { ShieldAlert, ShieldCheck, AlertTriangle, Layers, Info } from 'lucide-react';

interface MitreAttackHeatmapProps {
  analysis: MitreAttackAnalysis | null | undefined;
  entityId: string;
}

export const MitreAttackHeatmap: React.FC<MitreAttackHeatmapProps> = ({
  analysis,
  entityId,
}) => {
  if (!analysis) {
    return (
      <div className="bg-white rounded-sm border border-slate-300 p-6 text-center text-xs text-slate-500">
        No MITRE ATT&CK telemetry available for {entityId}.
      </div>
    );
  }

  const { total_tactics, covered_tactics, coverage_density, tactical_breakdown, critical_blind_spots } = analysis;
  const densityPct = (coverage_density * 100).toFixed(1);
  const isHealthy = coverage_density >= 0.70;

  return (
    <div className="bg-white rounded-sm border border-slate-300 shadow-sm overflow-hidden">
      {/* Official Header */}
      <div className="bg-[#0b2545] text-white px-4 py-3 border-b border-slate-700 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center space-x-2">
          <Layers className="w-5 h-5 text-amber-400" />
          <h3 className="text-sm font-bold tracking-wide uppercase font-serif">
            SECTION 3.1 : MITRE ATT&CK&reg; ENTERPRISE MATRIX TACTICAL HEATMAP (v14)
          </h3>
        </div>

        <div className="flex items-center space-x-2">
          <span className="text-[10px] font-mono text-slate-300 bg-slate-800 px-2 py-0.5 rounded border border-slate-600">
            {covered_tactics} / {total_tactics} TACTICS MONITORED
          </span>
          <span
            className={`text-xs font-bold px-2.5 py-0.5 rounded-sm border font-mono flex items-center gap-1.5 ${
              isHealthy
                ? 'bg-emerald-900 text-emerald-100 border-emerald-700'
                : 'bg-red-900 text-red-100 border-red-700'
            }`}
          >
            {isHealthy ? (
              <>
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-300" />
                HIGH DENSITY ({densityPct}%)
              </>
            ) : (
              <>
                <ShieldAlert className="w-3.5 h-3.5 text-red-300" />
                DEFICIT ({densityPct}%)
              </>
            )}
          </span>
        </div>
      </div>

      {/* Subtitle / Legal Context */}
      <div className="p-3 bg-slate-50 border-b border-slate-200 text-xs text-slate-700 flex items-start gap-2">
        <Info className="w-4 h-4 text-blue-700 flex-shrink-0 mt-0.5" />
        <p>
          Evaluates telemetry coverage across the 11 core MITRE ATT&CK Enterprise Matrix tactics. Missing coverage in key tactics
          reveals critical supervisory detection blind spots where advanced persistent threats (APTs) operate undetected.
        </p>
      </div>

      <div className="p-4 space-y-4">
        {/* Coverage Progress Bar */}
        <div>
          <div className="flex justify-between items-center text-xs font-bold text-slate-800 mb-1.5">
            <span>Tactical Telemetry Density Index</span>
            <span className="font-mono text-blue-900">{covered_tactics} of {total_tactics} Covered ({densityPct}%)</span>
          </div>
          <div className="w-full bg-slate-200 h-3 rounded-xs overflow-hidden border border-slate-300">
            <div
              style={{ width: `${densityPct}%` }}
              className={`h-full transition-all ${
                coverage_density >= 0.70
                  ? 'bg-emerald-600'
                  : coverage_density >= 0.40
                  ? 'bg-amber-500'
                  : 'bg-red-600'
              }`}
            />
          </div>
        </div>

        {/* Tactical Heatmap Matrix */}
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-2">
          {tactical_breakdown.map((tactic) => {
            const hasAlerts = tactic.is_covered;

            return (
              <div
                key={tactic.tactic_id}
                className={`p-2.5 rounded-sm border flex flex-col justify-between transition-all ${
                  hasAlerts
                    ? 'bg-blue-50/70 border-blue-300 text-blue-950'
                    : 'bg-red-50 border-red-300 text-red-950'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-[10px] font-mono font-bold text-slate-500">
                      {tactic.tactic_id}
                    </span>
                    {hasAlerts ? (
                      <span className="w-2 h-2 rounded-full bg-emerald-500" title="Active Telemetry" />
                    ) : (
                      <span className="w-2 h-2 rounded-full bg-red-500" title="Unmonitored Blind Spot" />
                    )}
                  </div>
                  <h4 className="text-xs font-bold leading-tight font-serif">
                    {tactic.tactic_name}
                  </h4>
                </div>

                <div className="mt-3 pt-1.5 border-t border-slate-200/80 flex items-center justify-between">
                  <span className="text-[10px] text-slate-500 font-medium">Alerts:</span>
                  <span className={`text-xs font-mono font-bold ${hasAlerts ? 'text-blue-900' : 'text-red-700'}`}>
                    {tactic.alert_count}
                  </span>
                </div>
              </div>
            );
          })}
        </div>

        {/* Critical Blind Spots Callout */}
        {critical_blind_spots.length > 0 && (
          <div className="bg-red-50 border border-red-200 rounded p-3 text-xs">
            <div className="flex items-center gap-1.5 text-red-900 font-bold mb-1.5">
              <AlertTriangle className="w-4 h-4 text-red-600" />
              <span>CRITICAL TACTICAL BLIND SPOTS IDENTIFIED ({critical_blind_spots.length}):</span>
            </div>
            <p className="text-slate-700 mb-2 leading-relaxed">
              The following tactics have 0% alert generation in the ingested dataset, representing immediate operational blind spots:
            </p>
            <div className="flex flex-wrap gap-1.5">
              {critical_blind_spots.map((bs) => (
                <span
                  key={bs}
                  className="bg-red-200/80 text-red-900 font-mono text-[11px] font-semibold px-2 py-0.5 rounded border border-red-300"
                >
                  {bs}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
