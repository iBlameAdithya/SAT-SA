import React from 'react';
import { BenfordAnalysis } from '../types/api';
import { Scale, AlertOctagon, CheckCircle2, Info } from 'lucide-react';

interface BenfordInspectorProps {
  analysis: BenfordAnalysis | null | undefined;
  entityId: string;
}

export const BenfordInspector: React.FC<BenfordInspectorProps> = ({
  analysis,
  entityId,
}) => {
  if (!analysis) {
    return (
      <div className="bg-white rounded-sm border border-slate-300 p-6 text-center text-xs text-slate-500">
        No Benford duration telemetry available for {entityId}.
      </div>
    );
  }

  const { total_samples, distribution, chi_square_stat, p_value, is_tampered } = analysis;

  return (
    <div className="bg-white rounded-sm border border-slate-300 shadow-sm overflow-hidden">
      {/* Header */}
      <div className="bg-[#0b2545] text-white px-4 py-3 border-b border-slate-700 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center space-x-2">
          <Scale className="w-5 h-5 text-amber-400" />
          <h3 className="text-sm font-bold tracking-wide uppercase font-serif">
            SECTION 2.1 : BENFORD'S LAW FIRST-DIGIT TEST (&chi;&sup2; GOODNESS-OF-FIT)
          </h3>
        </div>

        <div className="flex items-center space-x-2">
          <span className="text-[10px] font-mono text-slate-300 bg-slate-800 px-2 py-0.5 rounded border border-slate-600">
            N = {total_samples} SAMPLES
          </span>
          <span
            className={`text-xs font-bold px-2.5 py-0.5 rounded-sm border font-mono flex items-center gap-1.5 ${
              is_tampered
                ? 'bg-red-900 text-red-100 border-red-700'
                : 'bg-emerald-900 text-emerald-100 border-emerald-700'
            }`}
          >
            {is_tampered ? (
              <>
                <AlertOctagon className="w-3.5 h-3.5 text-red-300" />
                TAMPERING DETECTED (p &lt; 0.01)
              </>
            ) : (
              <>
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-300" />
                NATURAL CONVERGENCE
              </>
            )}
          </span>
        </div>
      </div>

      {/* Subtitle / Legal Context */}
      <div className="p-3 bg-slate-50 border-b border-slate-200 text-xs text-slate-700 flex items-start gap-2">
        <Info className="w-4 h-4 text-blue-700 flex-shrink-0 mt-0.5" />
        <p>
          Tests first significant digit of investigation durations against logarithmic distribution{' '}
          <code className="text-blue-900 font-bold font-mono">P(d) = log&#8321;&#8320;(1 + 1/d)</code>.
          Natural human investigative triage obeys Benford's Law; artificial or mass-automated ticket closures
          deviate toward uniform or skewed frequencies.
        </p>
      </div>

      <div className="p-4 space-y-4">
        {/* Statistical Summary Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="bg-slate-50 p-2.5 rounded border border-slate-200">
            <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider block">
              &chi;&sup2; Test Statistic
            </span>
            <span className={`text-lg font-bold font-mono ${chi_square_stat > 20.09 ? 'text-red-700' : 'text-slate-800'}`}>
              {chi_square_stat.toFixed(2)}
            </span>
            <span className="text-[10px] text-slate-400 block">Critical (&alpha;=0.01, df=8): 20.09</span>
          </div>

          <div className="bg-slate-50 p-2.5 rounded border border-slate-200">
            <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider block">
              p-value
            </span>
            <span className={`text-lg font-bold font-mono ${p_value < 0.01 ? 'text-red-700' : 'text-emerald-700'}`}>
              {p_value < 0.0001 ? '< 0.0001' : p_value.toFixed(4)}
            </span>
            <span className="text-[10px] text-slate-400 block">Significance: p &lt; 0.01</span>
          </div>

          <div className="bg-slate-50 p-2.5 rounded border border-slate-200">
            <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider block">
              Sample Count
            </span>
            <span className="text-lg font-bold font-mono text-slate-800">
              {total_samples}
            </span>
            <span className="text-[10px] text-slate-400 block">Evaluated Ticket Durations</span>
          </div>

          <div className="bg-slate-50 p-2.5 rounded border border-slate-200">
            <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider block">
              Forensic Verdict
            </span>
            <span className={`text-xs font-bold font-serif block mt-1 ${is_tampered ? 'text-red-700' : 'text-emerald-700'}`}>
              {is_tampered ? 'Fabrication Indicated' : 'Procedurally Compliant'}
            </span>
            <span className="text-[10px] text-slate-400 block">NCIIPC Evidentiary Standard</span>
          </div>
        </div>

        {/* First-Digit Comparative Distribution Chart */}
        <div>
          <div className="flex items-center justify-between text-xs font-bold text-slate-800 mb-2">
            <span>First-Digit Frequency Comparison (Digits 1-9)</span>
            <div className="flex items-center space-x-3 text-[11px] font-normal">
              <span className="flex items-center gap-1">
                <span className="w-2.5 h-2.5 bg-blue-600 rounded-xs inline-block" />
                <span>Observed %</span>
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2.5 h-2.5 bg-amber-500 rounded-xs inline-block" />
                <span>Expected Benford %</span>
              </span>
            </div>
          </div>

          <div className="grid grid-cols-9 gap-1.5 sm:gap-2">
            {distribution.map((item) => {
              const obsPct = item.observed_freq * 100;
              const expPct = item.expected_freq * 100;
              const diff = obsPct - expPct;
              const isSevere = Math.abs(diff) > 15;

              return (
                <div
                  key={item.digit}
                  className={`bg-slate-50 rounded p-2 text-center border flex flex-col justify-between ${
                    isSevere ? 'border-red-300 bg-red-50/40' : 'border-slate-200'
                  }`}
                >
                  <div className="text-xs font-bold font-mono text-slate-900 border-b border-slate-200 pb-1 mb-1">
                    Digit {item.digit}
                  </div>

                  {/* Bars Container */}
                  <div className="h-28 flex items-end justify-center gap-1 my-1 px-1">
                    {/* Observed Bar */}
                    <div
                      style={{ height: `${Math.min(100, obsPct * 2.2)}%` }}
                      className={`w-3 sm:w-4 rounded-t transition-all ${
                        isSevere ? 'bg-red-600' : 'bg-blue-600'
                      }`}
                      title={`Observed: ${obsPct.toFixed(1)}% (${item.observed_count} tickets)`}
                    />
                    {/* Expected Bar */}
                    <div
                      style={{ height: `${Math.min(100, expPct * 2.2)}%` }}
                      className="w-3 sm:w-4 bg-amber-500 rounded-t opacity-85 transition-all"
                      title={`Expected: ${expPct.toFixed(1)}%`}
                    />
                  </div>

                  {/* Frequency Labels */}
                  <div className="text-[10px] font-mono leading-tight space-y-0.5 pt-1 border-t border-slate-200">
                    <div className="font-bold text-blue-900">{obsPct.toFixed(0)}%</div>
                    <div className="text-slate-500">{expPct.toFixed(0)}%</div>
                    <div className="text-[9px] text-slate-400">n={item.observed_count}</div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Explainability Callout */}
        <div className="bg-slate-900 text-slate-200 p-3 rounded text-[11px] font-mono border border-slate-800">
          <span className="text-amber-400 font-bold block mb-1">
            STATUTORY EVIDENCE NOTE (NCIIPC / CERT-IN AUDIT SPECIFICATION):
          </span>
          {is_tampered ? (
            <p className="text-red-300 leading-relaxed">
              Ticket closure times fail Pearson's Goodness-of-Fit test with &chi;&sup2; = {chi_square_stat.toFixed(2)} (p = {p_value.toFixed(4)}).
              The duration distribution significantly diverges from normal human investigative triage intervals, providing mathematical proof
              of bulk automated closure scripts or fabricated resolution intervals.
            </p>
          ) : (
            <p className="text-emerald-300 leading-relaxed">
              Ticket investigation durations adhere strictly to Benford's Law (&chi;&sup2; = {chi_square_stat.toFixed(2)}, p = {p_value.toFixed(4)}),
              confirming genuine human cognitive problem-solving variance across the analyzed ticket queue.
            </p>
          )}
        </div>
      </div>
    </div>
  );
};
