import React, { useState, useRef } from 'react';
import { Shield, HardDrive, RefreshCw, FileText, Download, Lock, ChevronRight, Upload, ShieldCheck } from 'lucide-react';
import { MerkleAuditSeal } from '../types/api';

interface HeaderProps {
  onSeedData: () => void;
  onRunAnalysis: () => void;
  onDownloadPdf: () => void;
  onDownloadJson: () => void;
  onImportFile: (content: string, fileName: string) => void;
  loading: boolean;
  totalEntities: number;
  atRiskEntities: number;
  merkleSeal?: MerkleAuditSeal | null;
  onOpenMerkleSeal?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  onSeedData,
  onRunAnalysis,
  onDownloadPdf,
  onDownloadJson,
  onImportFile,
  loading,
  totalEntities,
  atRiskEntities,
  merkleSeal,
  onOpenMerkleSeal,
}) => {
  const [fontSize, setFontSize] = useState<'normal' | 'large' | 'small'>('normal');
  const [lang, setLang] = useState<'en' | 'hi'>('en');
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleSetFontSize = (size: 'small' | 'normal' | 'large') => {
    setFontSize(size);
    if (size === 'small') {
      document.documentElement.style.fontSize = '14px';
    } else if (size === 'large') {
      document.documentElement.style.fontSize = '18px';
    } else {
      document.documentElement.style.fontSize = '16px';
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (evt) => {
      const content = evt.target?.result as string;
      if (content) {
        onImportFile(content, file.name);
      }
    };
    reader.readAsText(file);
    e.target.value = '';
  };

  return (
    <header className="bg-white border-b border-slate-300 shadow-sm sticky top-0 z-50">
      {/* 1. Indian National Flag Accent Line */}
      <div className="tricolor-stripe" />

      {/* 2. Official Government Top Accessibility Bar */}
      <div className="bg-[#0b2545] text-slate-200 text-[11px] px-4 py-1 flex items-center justify-between border-b border-slate-800">
        <div className="flex items-center space-x-4">
          <span className="font-semibold text-amber-400">भारत सरकार | Government of India</span>
          <span className="hidden md:inline text-slate-400">|</span>
          <span className="hidden md:inline text-slate-300">National Technical Research Organisation (NTRO)</span>
          <span className="hidden lg:inline text-slate-400">|</span>
          <span className="hidden lg:inline text-slate-300">NCIIPC - Section 70A IT Act 2000</span>
        </div>

        <div className="flex items-center space-x-3 text-slate-300">
          {merkleSeal && (
            <button
              onClick={onOpenMerkleSeal}
              className="flex items-center space-x-1.5 bg-emerald-950/80 hover:bg-emerald-900 text-emerald-200 px-2 py-0.5 rounded text-[10px] border border-emerald-600 transition cursor-pointer"
              title="Click to inspect cryptographic Merkle tree audit seal"
            >
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
              <span className="font-mono font-bold tracking-tight">SEAL: {merkleSeal.root_hash.slice(0, 8)}...</span>
            </button>
          )}

          <div className="flex items-center space-x-1 bg-slate-900 px-2 py-0.5 rounded text-[10px] border border-slate-700">
            <Lock className="w-3 h-3 text-emerald-400" />
            <span className="font-mono text-emerald-300">AIR-GAPPED OFFLINE MODE</span>
          </div>

          <div className="hidden sm:flex items-center space-x-1 border-l border-slate-700 pl-3">
            <button
              onClick={() => handleSetFontSize('small')}
              className={`px-1.5 py-0.5 rounded hover:text-white font-mono cursor-pointer transition ${fontSize === 'small' ? 'text-amber-400 font-bold bg-slate-800' : 'text-slate-300'}`}
              title="Small Text (90%)"
            >
              A-
            </button>
            <button
              onClick={() => handleSetFontSize('normal')}
              className={`px-1.5 py-0.5 rounded hover:text-white font-mono cursor-pointer transition ${fontSize === 'normal' ? 'text-amber-400 font-bold bg-slate-800' : 'text-slate-300'}`}
              title="Normal Text (100%)"
            >
              A
            </button>
            <button
              onClick={() => handleSetFontSize('large')}
              className={`px-1.5 py-0.5 rounded hover:text-white font-mono cursor-pointer transition ${fontSize === 'large' ? 'text-amber-400 font-bold bg-slate-800' : 'text-slate-300'}`}
              title="Large Text (115%)"
            >
              A+
            </button>
          </div>

          <div className="hidden sm:inline text-slate-400">|</div>
          <button
            onClick={() => setLang('en')}
            className={`cursor-pointer hover:text-amber-300 transition text-[11px] font-medium ${lang === 'en' ? 'text-amber-400 font-bold' : 'text-slate-300'}`}
          >
            English
          </button>
          <span className="text-slate-500">/</span>
          <button
            onClick={() => setLang('hi')}
            className={`cursor-pointer hover:text-amber-300 transition text-[11px] font-medium ${lang === 'hi' ? 'text-amber-400 font-bold' : 'text-slate-300'}`}
          >
            हिन्दी
          </button>
        </div>
      </div>

      {/* 3. Main Department Branding Banner */}
      <div className="bg-[#0f2b48] text-white px-4 sm:px-6 py-3 border-b border-slate-800">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row md:items-center md:justify-between gap-4">

          {/* Official Emblem & Title */}
          <div className="flex items-center space-x-3.5">
            <div className="p-2.5 bg-white/10 rounded border border-white/20 text-amber-400 flex-shrink-0">
              <Shield className="w-8 h-8" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h1 className="text-lg md:text-xl font-bold tracking-tight text-white font-serif">
                  SAT-SA
                </h1>
                <span className="bg-amber-500 text-slate-950 font-bold px-2 py-0.5 text-[10px] rounded-sm uppercase tracking-wider">
                  Official Audit System
                </span>
              </div>
              <p className="text-xs text-slate-200 mt-0.5 font-medium">
                Supervisory Analytics Tool for SOC Assessment
              </p>
              <p className="text-[11px] text-amber-300/90 font-mono mt-0.5">
                National Critical Information Infrastructure Protection Centre (NCIIPC / NTRO)
              </p>
            </div>
          </div>

          {/* Quick Metrics Bar */}
          <div className="flex items-center space-x-4 bg-slate-900/90 px-4 py-2 rounded border border-slate-700">
            <div>
              <span className="text-[10px] text-slate-400 uppercase tracking-wider font-semibold block">
                Critical Entities (CSE)
              </span>
              <span className="text-base font-bold text-white font-mono">{totalEntities}</span>
            </div>
            <div className="h-7 w-px bg-slate-700" />
            <div>
              <span className="text-[10px] text-slate-400 uppercase tracking-wider font-semibold block">
                Flagged At-Risk
              </span>
              <span className={`text-base font-bold font-mono ${atRiskEntities > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                {atRiskEntities}
              </span>
            </div>
            <div className="h-7 w-px bg-slate-700" />
            <div>
              <span className="text-[10px] text-slate-400 uppercase tracking-wider font-semibold block">
                Audit Standard
              </span>
              <span className="text-xs font-bold text-amber-300 font-mono">NCIIPC-2024-SEC70B</span>
            </div>
            {merkleSeal && (
              <>
                <div className="h-7 w-px bg-slate-700" />
                <button
                  onClick={onOpenMerkleSeal}
                  className="text-left group cursor-pointer"
                  title="Inspect RFC 6962 SHA-256 Cryptographic Chain-of-Custody Seal"
                >
                  <span className="text-[10px] text-emerald-400 uppercase tracking-wider font-semibold flex items-center gap-1">
                    <ShieldCheck className="w-3 h-3 text-emerald-400 inline" />
                    Merkle Seal
                  </span>
                  <span className="text-xs font-bold text-white font-mono group-hover:text-emerald-300 transition underline decoration-dotted">
                    Sealed ({merkleSeal.leaf_count} Leaves)
                  </span>
                </button>
              </>
            )}
          </div>

        </div>
      </div>

      {/* 4. Official Command Bar & Action Navigation */}
      <div className="bg-slate-100 px-4 sm:px-6 py-2 border-b border-slate-300">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">

          <div className="flex items-center space-x-1.5 text-xs text-slate-700 font-medium">
            <span className="text-slate-500">Portal</span>
            <ChevronRight className="w-3.5 h-3.5 text-slate-400" />
            <span className="text-slate-500">Examiner Dashboard</span>
            <ChevronRight className="w-3.5 h-3.5 text-slate-400" />
            <span className="text-blue-900 font-bold">SOC Governance Assessment</span>
          </div>

          {/* Action Buttons */}
          <div className="flex flex-wrap items-center gap-2">
            <input
              id="csv-file-input"
              type="file"
              ref={fileInputRef}
              onChange={handleFileChange}
              accept=".csv,.json"
              className="hidden"
            />

            <button
              onClick={() => fileInputRef.current?.click()}
              disabled={loading}
              className="flex items-center space-x-1.5 px-3 py-1.5 text-xs font-bold bg-amber-600 hover:bg-amber-700 text-white rounded-sm transition border border-amber-800 shadow-sm disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed"
              title="Import authentic SOC log export file (.csv or .json)"
            >
              <Upload className="w-3.5 h-3.5 text-amber-100" />
              <span>Import Real SOC File (.csv / .json)</span>
            </button>

            <button
              onClick={onSeedData}
              disabled={loading}
              className="flex items-center space-x-1.5 px-3 py-1.5 text-xs font-bold bg-slate-700 hover:bg-slate-800 text-white rounded-sm transition border border-slate-800 shadow-sm disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed"
            >
              <HardDrive className="w-3.5 h-3.5 text-amber-400" />
              <span>Seed Benchmark Datasets</span>
            </button>

            <button
              onClick={onRunAnalysis}
              disabled={loading}
              className="flex items-center space-x-1.5 px-3.5 py-1.5 text-xs font-bold bg-[#003366] hover:bg-[#002244] text-white rounded-sm transition border border-[#002244] shadow-sm disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed"
            >
              <RefreshCw className={`w-3.5 h-3.5 text-blue-300 ${loading ? 'animate-spin' : ''}`} />
              <span>Execute Supervisory Analysis</span>
            </button>

            <button
              onClick={onDownloadPdf}
              disabled={loading}
              className="flex items-center space-x-1.5 px-3 py-1.5 text-xs font-bold bg-red-800 hover:bg-red-900 text-white rounded-sm transition border border-red-900 shadow-sm disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed"
            >
              <FileText className="w-3.5 h-3.5 text-red-200" />
              <span>Official PDF Report</span>
            </button>

            <button
              onClick={onDownloadJson}
              disabled={loading}
              className="flex items-center space-x-1.5 px-3 py-1.5 text-xs font-bold bg-emerald-800 hover:bg-emerald-900 text-white rounded-sm transition border border-emerald-900 shadow-sm disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed"
            >
              <Download className="w-3.5 h-3.5 text-emerald-200" />
              <span>Export Audit Package</span>
            </button>
          </div>

        </div>
      </div>
    </header>
  );
};
