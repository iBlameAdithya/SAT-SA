import React from 'react';
import { EntityRiskProfile } from '../types/api';
import { Activity, ShieldAlert, Award } from 'lucide-react';

interface RiskLeaderboardProps {
  profiles: EntityRiskProfile[];
  selectedEntityId: string | null;
  onSelectEntity: (entityId: string) => void;
}

export const RiskLeaderboard: React.FC<RiskLeaderboardProps> = ({
  profiles,
  selectedEntityId,
  onSelectEntity,
}) => {
  const getBadgeStyle = (level: string) => {
    switch (level) {
      case 'CRITICAL':
        return 'bg-red-700 text-white border-red-900';
      case 'HIGH':
        return 'bg-orange-600 text-white border-orange-800';
      case 'MODERATE':
        return 'bg-amber-600 text-white border-amber-800';
      default:
        return 'bg-emerald-700 text-white border-emerald-900';
    }
  };

  return (
    <div className="bg-white rounded-sm border border-slate-300 shadow-sm overflow-hidden">
      {/* Official Government Section Header */}
      <div className="bg-[#0b2545] text-white px-4 py-3 border-b border-slate-700 flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <Activity className="w-5 h-5 text-amber-400" />
          <h2 className="text-sm font-bold tracking-wide uppercase font-serif">
            SECTION 1.0 : CSE SUPERVISORY RISK MATRIX & LEADERBOARD
          </h2>
        </div>
        <span className="text-xs bg-slate-800 text-slate-200 px-2.5 py-0.5 rounded-sm font-mono border border-slate-600">
          Ref: NCIIPC-STATUTORY-AUDIT-2026
        </span>
      </div>

      <div className="p-4 bg-slate-50 border-b border-slate-200 text-xs text-slate-700">
        Entities categorized by composite Supervisory Risk Score (0-100) evaluating Execution Gaps (superficial compliance) and Negative Space (telemetry omissions).
      </div>

      <div className="p-4 grid grid-cols-1 md:grid-cols-3 gap-4 bg-white">
        {profiles.map((profile) => {
          const isSelected = selectedEntityId === profile.entity_id;
          return (
            <div
              key={profile.entity_id}
              onClick={() => onSelectEntity(profile.entity_id)}
              className={`cursor-pointer rounded-sm border p-4 transition-all duration-150 ${
                isSelected
                  ? 'bg-blue-50/80 border-[#003366] ring-2 ring-[#003366]/30 shadow-md'
                  : 'bg-white border-slate-300 hover:border-slate-400 hover:bg-slate-50'
              }`}
            >
              {/* Header */}
              <div className="flex items-start justify-between mb-3 border-b border-slate-200 pb-2.5">
                <div>
                  <div className="flex items-center space-x-1.5">
                    <h3 className="text-sm font-bold text-slate-900 font-mono">{profile.entity_id}</h3>
                  </div>
                  <p className="text-xs text-slate-600 font-medium truncate max-w-[180px] mt-0.5">
                    {profile.entity_name}
                  </p>
                </div>
                <span
                  className={`px-2 py-0.5 text-[10px] font-bold rounded-sm border uppercase tracking-wider ${getBadgeStyle(
                    profile.risk_level
                  )}`}
                >
                  {profile.risk_level}
                </span>
              </div>

              {/* Score Meter */}
              <div className="mb-3 bg-slate-100 p-2.5 rounded-sm border border-slate-200">
                <div className="flex justify-between items-center text-xs mb-1">
                  <span className="text-slate-700 font-semibold">Supervisory Risk Score:</span>
                  <span className="font-mono font-bold text-slate-900 text-sm">
                    {profile.composite_risk_score.toFixed(1)} / 100
                  </span>
                </div>
                <div className="w-full bg-slate-300 h-2 rounded-sm overflow-hidden">
                  <div
                    className={`h-full transition-all duration-300 ${
                      profile.composite_risk_score >= 60
                        ? 'bg-red-600'
                        : profile.composite_risk_score >= 30
                        ? 'bg-amber-600'
                        : 'bg-emerald-600'
                    }`}
                    style={{ width: `${Math.max(5, profile.composite_risk_score)}%` }}
                  />
                </div>
              </div>

              {/* Component breakdown */}
              <div className="grid grid-cols-2 gap-2 text-xs bg-slate-50 p-2.5 rounded-sm border border-slate-200">
                <div>
                  <span className="text-slate-500 block text-[10px] uppercase font-semibold">Execution Gap Score</span>
                  <span className="font-bold text-orange-700 font-mono text-sm">
                    {profile.execution_gap_score.toFixed(1)}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px] uppercase font-semibold">Negative Space Score</span>
                  <span className="font-bold text-purple-700 font-mono text-sm">
                    {profile.negative_space_score.toFixed(1)}
                  </span>
                </div>
              </div>

              {/* Findings count */}
              <div className="mt-3 flex items-center justify-between text-xs text-slate-600 pt-2 border-t border-slate-200">
                <span className="font-semibold text-slate-700">
                  {profile.findings_count} Statutory Deficits
                </span>
                <span className="font-mono text-slate-700 font-semibold bg-slate-200 px-1.5 py-0.5 rounded-sm border border-slate-300">
                  Z: {profile.z_score_overall > 0 ? `+${profile.z_score_overall}` : profile.z_score_overall}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
