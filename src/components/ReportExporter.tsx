import React from 'react';
import { FileText, Download, ShieldCheck, CheckCircle, FileCheck } from 'lucide-react';

interface ReportExporterProps {
  onDownloadPdf: () => void;
  onDownloadJson: () => void;
  loading: boolean;
}

export const ReportExporter: React.FC<ReportExporterProps> = ({
  onDownloadPdf,
  onDownloadJson,
  loading,
}) => {
  return (
    <div className="bg-white rounded-sm border border-slate-300 shadow-sm overflow-hidden">
      {/* Official Government Section Header */}
      <div className="bg-[#0b2545] text-white px-4 py-3 border-b border-slate-700 flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <ShieldCheck className="w-5 h-5 text-emerald-400" />
          <h3 className="text-sm font-bold tracking-wide uppercase font-serif">
            SECTION 5.0 : STATUTORY AUDIT REPORT EXPORT MANAGER
          </h3>
        </div>
        <span className="text-xs bg-slate-800 text-slate-200 font-mono px-2.5 py-0.5 rounded-sm border border-slate-600">
          NCIIPC DIRECTIVE 2024 / SEC 70A
        </span>
      </div>

      <div className="p-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* PDF Exporter */}
          <div className="bg-slate-50 rounded-sm border border-slate-300 p-4 flex flex-col justify-between">
            <div>
              <div className="flex items-center space-x-2 text-red-800 mb-2 border-b border-slate-200 pb-2">
                <FileText className="w-5 h-5" />
                <h4 className="text-sm font-bold text-slate-900 font-serif">Official PDF Supervisory Audit Report</h4>
              </div>
              <p className="text-xs text-slate-700 leading-relaxed mb-4">
                Compiles the formal <b>NCIIPC Supervisory Assessment Audit Report</b> featuring executive governance summaries, CSE risk matrices, Execution Gap findings, Negative Space telemetry evidence, and statutory examiner recommendations.
              </p>
            </div>
            <button
              onClick={onDownloadPdf}
              disabled={loading}
              className="w-full flex items-center justify-center space-x-2 py-2 px-4 bg-red-800 hover:bg-red-900 text-white text-xs font-bold rounded-sm transition border border-red-900 shadow-xs disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed"
            >
              <FileText className="w-4 h-4" />
              <span>Generate Official PDF Audit Report</span>
            </button>
          </div>

          {/* JSON Exporter */}
          <div className="bg-slate-50 rounded-sm border border-slate-300 p-4 flex flex-col justify-between">
            <div>
              <div className="flex items-center space-x-2 text-blue-900 mb-2 border-b border-slate-200 pb-2">
                <Download className="w-5 h-5" />
                <h4 className="text-sm font-bold text-slate-900 font-serif">Supervisory JSON Audit Package</h4>
              </div>
              <p className="text-xs text-slate-700 leading-relaxed mb-4">
                Exports the complete structured <b>satsa_export_package.json</b> containing normalized entity profiles, raw finding evidence, and peer benchmarking z-scores for offline air-gapped examiner archives.
              </p>
            </div>
            <button
              onClick={onDownloadJson}
              disabled={loading}
              className="w-full flex items-center justify-center space-x-2 py-2 px-4 bg-[#003366] hover:bg-[#002244] text-white text-xs font-bold rounded-sm transition border border-[#002244] shadow-xs disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed"
            >
              <Download className="w-4 h-4" />
              <span>Export Statutory JSON Package</span>
            </button>
          </div>
        </div>

        <div className="mt-4 bg-emerald-50 p-3 rounded-sm border border-emerald-300 flex items-center gap-2.5 text-xs text-emerald-900 font-medium">
          <FileCheck className="w-4 h-4 text-emerald-700 flex-shrink-0" />
          <span>
            Air-Gapped Examination Certified: All audit reports and statutory packages are generated locally within the secure air-gapped system perimeter without external network connections.
          </span>
        </div>
      </div>
    </div>
  );
};
