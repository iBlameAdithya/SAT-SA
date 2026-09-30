import React from 'react';
import { PeerBenchmarkItem } from '../types/api';
import { BarChart3 } from 'lucide-react';

interface PeerBenchmarkPanelProps {
  benchmarks: PeerBenchmarkItem[];
  selectedEntityId?: string | null;
  onSelectEntity?: (entityId: string) => void;
}

export const PeerBenchmarkPanel: React.FC<PeerBenchmarkPanelProps> = ({
  benchmarks,
  selectedEntityId,
  onSelectEntity,
}) => {
  return (
    <div className="bg-white rounded-sm border border-slate-300 shadow-sm overflow-hidden">
      {/* Official Government Section Header */}
      <div className="bg-[#0b2545] text-white px-4 py-3 border-b border-slate-700 flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <BarChart3 className="w-5 h-5 text-amber-400" />
          <h3 className="text-sm font-bold tracking-wide uppercase font-serif">
            SECTION 4.0 : STATISTICAL PEER BENCHMARKING & Z-SCORE AUDIT MATRIX
          </h3>
        </div>
        <span className="text-xs bg-slate-800 text-slate-200 font-mono px-2.5 py-0.5 rounded-sm border border-slate-600">
          Z = (X - μ) / σ
        </span>
      </div>

      <div className="p-4 bg-slate-50 border-b border-slate-200 text-xs text-slate-700">
        Cross-entity statistical comparison calculating mean (μ) and standard deviation (σ) across operational metrics to produce normalized Z-scores. Higher positive scores indicate severe negative operational deviation.
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="bg-slate-100 border-b border-slate-300 text-slate-800 font-bold uppercase tracking-wider text-[11px]">
              <th className="py-2.5 px-3 border-r border-slate-200">Risk Rank</th>
              <th className="py-2.5 px-3 border-r border-slate-200">CSE Entity ID</th>
              <th className="py-2.5 px-3 border-r border-slate-200">Critical Sector</th>
              <th className="py-2.5 px-3 text-right border-r border-slate-200">Alert Volume</th>
              <th className="py-2.5 px-3 text-right border-r border-slate-200">Fast Closure %</th>
              <th className="py-2.5 px-3 text-right border-r border-slate-200">Unesc Critical %</th>
              <th className="py-2.5 px-3 text-right border-r border-slate-200">Missing Categories</th>
              <th className="py-2.5 px-3 text-right">Normalized Z-Score</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-200 font-mono">
            {benchmarks.map((b) => {
              const isSelected = selectedEntityId === b.entity_id;
              const isHighRisk = b.z_score >= 0.5;
              return (
                <tr
                  key={b.entity_id}
                  onClick={() => onSelectEntity && onSelectEntity(b.entity_id)}
                  className={`transition cursor-pointer ${
                    isSelected
                      ? 'bg-blue-100/90 font-bold border-l-4 border-l-[#003366]'
                      : isHighRisk
                      ? 'bg-red-50/70 hover:bg-red-100/70'
                      : 'bg-white hover:bg-slate-100'
                  }`}
                  title="Click to inspect this CSE across all forensic & SOTA modules"
                >
                  <td className="py-3 px-3 font-bold text-slate-900 border-r border-slate-200">#{b.risk_rank}</td>
                  <td className="py-3 px-3 font-sans font-bold text-slate-900 border-r border-slate-200">
                    <span className="flex items-center gap-1.5">
                      <span>{b.entity_id}</span>
                      {isSelected && (
                        <span className="text-[9px] bg-[#003366] text-white px-1.5 py-0.2 rounded font-sans uppercase">
                          Selected
                        </span>
                      )}
                    </span>
                  </td>
                  <td className="py-3 px-3 font-sans text-slate-700 border-r border-slate-200">{b.sector}</td>
                  <td className="py-3 px-3 text-right text-slate-900 border-r border-slate-200">{b.alert_volume}</td>
                  <td className="py-3 px-3 text-right border-r border-slate-200">
                    <span className={b.fast_closure_rate >= 30 ? 'text-red-700 font-bold' : 'text-slate-800'}>
                      {b.fast_closure_rate.toFixed(1)}%
                    </span>
                  </td>
                  <td className="py-3 px-3 text-right border-r border-slate-200">
                    <span className={b.unescalated_critical_rate >= 30 ? 'text-red-700 font-bold' : 'text-slate-800'}>
                      {b.unescalated_critical_rate.toFixed(1)}%
                    </span>
                  </td>
                  <td className="py-3 px-3 text-right border-r border-slate-200">
                    <span className={b.missing_category_count >= 3 ? 'text-purple-700 font-bold' : 'text-slate-800'}>
                      {b.missing_category_count}
                    </span>
                  </td>
                  <td className="py-3 px-3 text-right">
                    <span
                      className={`inline-block px-2 py-0.5 rounded-sm text-xs font-bold ${
                        b.z_score >= 0.5
                          ? 'bg-red-700 text-white border border-red-900'
                          : b.z_score < 0
                          ? 'bg-emerald-700 text-white border border-emerald-900'
                          : 'bg-slate-200 text-slate-800 border border-slate-300'
                      }`}
                    >
                      {b.z_score > 0 ? `+${b.z_score.toFixed(2)}` : b.z_score.toFixed(2)}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
