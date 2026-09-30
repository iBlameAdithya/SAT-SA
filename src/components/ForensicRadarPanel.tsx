import React from 'react';
import { ShiftDumpAnalysis, MinHashNoteCluster, ShannonEntropyAnalysis } from '../types/api';
import { Zap, Copy, Activity, UserX, AlertTriangle, CheckCircle, Info } from 'lucide-react';

interface ForensicRadarPanelProps {
  shiftDump: ShiftDumpAnalysis | null | undefined;
  minhashClusters: MinHashNoteCluster[] | null | undefined;
  shannonEntropy: ShannonEntropyAnalysis | null | undefined;
  entityId: string;
}

export const ForensicRadarPanel: React.FC<ForensicRadarPanelProps> = ({
  shiftDump,
  minhashClusters,
  shannonEntropy,
  entityId,
}) => {
  return (
    <div className="bg-white rounded-sm border border-slate-300 shadow-sm overflow-hidden space-y-4">
      {/* Header */}
      <div className="bg-[#0b2545] text-white px-4 py-3 border-b border-slate-700 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center space-x-2">
          <Activity className="w-5 h-5 text-amber-400" />
          <h3 className="text-sm font-bold tracking-wide uppercase font-serif">
            SECTION 2.2 : ADVANCED BEHAVIORAL & TELEMETRY FORENSICS RADAR
          </h3>
        </div>
        <span className="text-[11px] font-mono text-amber-300 bg-slate-900 px-2.5 py-0.5 rounded border border-slate-700">
          ENTITY: {entityId}
        </span>
      </div>

      <div className="p-4 space-y-6">
        {/* 1. Shift-End Ticket Dumping (Poisson Windowing) */}
        <div className="border border-slate-200 rounded p-4 bg-slate-50/50">
          <div className="flex flex-wrap items-center justify-between gap-2 mb-2 pb-2 border-b border-slate-200">
            <div className="flex items-center space-x-2">
              <Zap className="w-4 h-4 text-orange-600" />
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-900 font-serif">
                Shift-End Ticket Dumping Radar (5-Minute Poisson Windowing)
              </h4>
            </div>
            {shiftDump && shiftDump.burst_ratio > 0 ? (
              <span className="text-xs font-bold font-mono px-2 py-0.5 rounded bg-orange-100 text-orange-800 border border-orange-300">
                BURST RATIO: {shiftDump.burst_ratio}% ({shiftDump.burst_closures_count} / {shiftDump.total_closed_cases})
              </span>
            ) : (
              <span className="text-xs font-bold font-mono px-2 py-0.5 rounded bg-emerald-100 text-emerald-800 border border-emerald-300">
                NO RAPID BURSTS DETECTED
              </span>
            )}
          </div>

          <p className="text-xs text-slate-600 mb-3 leading-relaxed">
            Identifies artificial bursts where investigators close multiple tickets in rapid 5-minute (300s) windows with avg duration &le; 120s to inflate SLA metrics prior to shift handover.
          </p>

          {shiftDump && shiftDump.clusters.length > 0 ? (
            <div className="space-y-2">
              <div className="text-[11px] font-bold text-slate-700 flex items-center gap-1.5">
                <UserX className="w-3.5 h-3.5 text-red-600" />
                <span>Flagged Investigators: </span>
                <span className="font-mono text-red-700">{shiftDump.flagged_investigators.join(', ')}</span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-2 mt-2">
                {shiftDump.clusters.map((cluster, idx) => (
                  <div key={idx} className="bg-white p-2.5 rounded border border-orange-200 text-xs shadow-2xs">
                    <div className="flex justify-between items-center font-mono font-bold text-slate-900 border-b border-slate-100 pb-1 mb-1.5">
                      <span className="text-orange-900">{cluster.investigator_id}</span>
                      <span className="text-orange-700">{cluster.tickets_closed} Tickets Closed</span>
                    </div>
                    <div className="space-y-0.5 text-[11px] text-slate-600">
                      <div>Window: <span className="font-mono">{new Date(cluster.window_start).toLocaleTimeString()} - {new Date(cluster.window_end).toLocaleTimeString()}</span></div>
                      <div>Avg Duration: <span className="font-mono font-bold text-orange-900">{cluster.avg_duration_seconds}s</span> per ticket</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="text-xs text-slate-500 italic">Ticket closures follow natural temporal Poisson inter-arrival intervals without burst anomalies.</div>
          )}
        </div>

        {/* 2. MinHash LSH Boilerplate & Collusion Detection */}
        <div className="border border-slate-200 rounded p-4 bg-slate-50/50">
          <div className="flex flex-wrap items-center justify-between gap-2 mb-2 pb-2 border-b border-slate-200">
            <div className="flex items-center space-x-2">
              <Copy className="w-4 h-4 text-purple-600" />
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-900 font-serif">
                MinHash LSH & Jaccard Shingling (Boilerplate Collusion)
              </h4>
            </div>
            {minhashClusters && minhashClusters.length > 0 ? (
              <span className="text-xs font-bold font-mono px-2 py-0.5 rounded bg-purple-100 text-purple-800 border border-purple-300">
                {minhashClusters.length} COLLUSION CLUSTERS (J &ge; 0.75)
              </span>
            ) : (
              <span className="text-xs font-bold font-mono px-2 py-0.5 rounded bg-emerald-100 text-emerald-800 border border-emerald-300">
                0 COLLUSION CLUSTERS
              </span>
            )}
          </div>

          <p className="text-xs text-slate-600 mb-3 leading-relaxed">
            Applies 3-gram character shingling and 32 MinHash permutations over resolution text to detect canned boilerplate notes reused across distinct alerts.
          </p>

          {minhashClusters && minhashClusters.length > 0 ? (
            <div className="space-y-2.5">
              {minhashClusters.map((cluster) => (
                <div key={cluster.cluster_id} className="bg-white p-3 rounded border border-purple-200 text-xs">
                  <div className="flex flex-wrap justify-between items-center mb-1.5 pb-1 border-b border-slate-100 text-[11px] font-mono">
                    <span className="font-bold text-purple-900">{cluster.cluster_id} ({cluster.note_count} Duplicate Cases)</span>
                    <span className="text-purple-700 font-bold">Similarity Index: {(cluster.similarity_score * 100).toFixed(0)}%</span>
                  </div>

                  <div className="bg-slate-100 text-slate-800 p-2 rounded text-[11px] italic font-serif mb-2 border border-slate-200">
                    &ldquo;{cluster.sample_note}&rdquo;
                  </div>

                  <div className="flex flex-wrap gap-3 text-[11px] text-slate-600 font-mono">
                    <div>
                      <span className="font-bold text-slate-700">Investigators: </span>
                      <span>{cluster.investigator_ids.join(', ')}</span>
                    </div>
                    <div>
                      <span className="font-bold text-slate-700">Cases: </span>
                      <span>{cluster.case_ids.slice(0, 4).join(', ')}{cluster.case_ids.length > 4 ? ` +${cluster.case_ids.length - 4} more` : ''}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-xs text-slate-500 italic">No duplicate template clusters detected. Investigators author independent custom notes.</div>
          )}
        </div>

        {/* 3. Shannon Information Entropy (Alert Suppression) */}
        {shannonEntropy && (
          <div className="border border-slate-200 rounded p-4 bg-slate-50/50">
            <div className="flex flex-wrap items-center justify-between gap-2 mb-2 pb-2 border-b border-slate-200">
              <div className="flex items-center space-x-2">
                <Activity className="w-4 h-4 text-blue-600" />
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-900 font-serif">
                  Shannon Telemetry Information Entropy H(X)
                </h4>
              </div>
              <span
                className={`text-xs font-bold font-mono px-2 py-0.5 rounded border ${
                  shannonEntropy.is_suppressed
                    ? 'bg-red-100 text-red-800 border-red-300'
                    : 'bg-emerald-100 text-emerald-800 border-emerald-300'
                }`}
              >
                {shannonEntropy.is_suppressed ? 'ENTROPY COLLAPSE (SUPPRESSION)' : 'HEALTHY DIVERSITY'}
              </span>
            </div>

            <p className="text-xs text-slate-600 mb-3 leading-relaxed">
              Calculates informational entropy <code className="text-blue-900 font-mono font-bold">H(X) = -&sum; p_i log&#8322;(p_i)</code> across alert categories. An entropy collapse indicates selective rule silencing or suppression of severe threat categories.
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-3">
              <div className="bg-white p-2.5 rounded border border-slate-200">
                <span className="text-[10px] text-slate-500 font-bold uppercase block">Shannon Entropy H(X)</span>
                <span className={`text-base font-bold font-mono ${shannonEntropy.is_suppressed ? 'text-red-700' : 'text-slate-800'}`}>
                  {shannonEntropy.entropy.toFixed(2)} bits
                </span>
                <span className="text-[10px] text-slate-400 block">Max Theoretical: {shannonEntropy.max_possible_entropy.toFixed(2)} bits</span>
              </div>

              <div className="bg-white p-2.5 rounded border border-slate-200">
                <span className="text-[10px] text-slate-500 font-bold uppercase block">Normalized Entropy %</span>
                <span className={`text-base font-bold font-mono ${shannonEntropy.normalized_entropy < 0.35 ? 'text-red-700' : 'text-slate-800'}`}>
                  {(shannonEntropy.normalized_entropy * 100).toFixed(1)}%
                </span>
                <span className="text-[10px] text-slate-400 block">Warning Threshold: &lt; 35%</span>
              </div>

              <div className="bg-white p-2.5 rounded border border-slate-200">
                <span className="text-[10px] text-slate-500 font-bold uppercase block">Total Alerts Evaluated</span>
                <span className="text-base font-bold font-mono text-slate-800">
                  {shannonEntropy.alert_count}
                </span>
                <span className="text-[10px] text-slate-400 block">Across {shannonEntropy.category_frequencies.length} Categories</span>
              </div>
            </div>

            {/* Category Probability Distribution */}
            <div className="bg-white p-3 rounded border border-slate-200">
              <span className="text-[11px] font-bold text-slate-800 block mb-2">Category Distribution & Probabilities:</span>
              <div className="space-y-1.5">
                {shannonEntropy.category_frequencies.map((cat) => (
                  <div key={cat.category} className="flex items-center text-xs">
                    <span className="w-40 font-mono text-[11px] text-slate-700 truncate">{cat.category}</span>
                    <div className="flex-1 bg-slate-100 h-2 rounded-xs overflow-hidden mx-2 border border-slate-200">
                      <div
                        style={{ width: `${(cat.probability * 100).toFixed(1)}%` }}
                        className="bg-blue-600 h-full"
                      />
                    </div>
                    <span className="w-16 text-right font-mono text-[11px] text-slate-600">
                      {(cat.probability * 100).toFixed(1)}% (n={cat.count})
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
