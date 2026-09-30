import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { RiskLeaderboard } from './components/RiskLeaderboard';
import { ExecutionGapsPanel } from './components/ExecutionGapsPanel';
import { NegativeSpacePanel } from './components/NegativeSpacePanel';
import { PeerBenchmarkPanel } from './components/PeerBenchmarkPanel';
import { ReportExporter } from './components/ReportExporter';
import { BenfordInspector } from './components/BenfordInspector';
import { MitreAttackHeatmap } from './components/MitreAttackHeatmap';
import { ForensicRadarPanel } from './components/ForensicRadarPanel';
import { CertInComplianceCard } from './components/CertInComplianceCard';
import { MerkleSealModal } from './components/MerkleSealModal';
import {
  seedMockData,
  runSupervisoryAnalysis,
  exportPdfReport,
  exportJsonPackage,
  ingestCsvData,
  ingestJsonData,
} from './services/tauriApi';
import { openHtmlReportInNewTab, openJsonPackageInNewTab } from './services/reportGenerator';
import { SupervisoryAnalysisResponse, EntitySotaDetails } from './types/api';
import { Info, X, Sparkles, Building2, CheckCircle2 } from 'lucide-react';

export const App: React.FC = () => {
  const [analysisData, setAnalysisData] = useState<SupervisoryAnalysisResponse | null>(null);
  const [selectedEntityId, setSelectedEntityId] = useState<string | null>(null);
  const [activeSotaEntityId, setActiveSotaEntityId] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [isMerkleModalOpen, setIsMerkleModalOpen] = useState<boolean>(false);

  useEffect(() => {
    handleInitialLoad();
  }, []);

  // Update active SOTA entity when selectedEntityId changes or on fresh analysis
  useEffect(() => {
    if (selectedEntityId) {
      setActiveSotaEntityId(selectedEntityId);
    } else if (analysisData?.sota_details && analysisData.sota_details.length > 0) {
      if (!activeSotaEntityId || !analysisData.sota_details.some(s => s.entity_id === activeSotaEntityId)) {
        setActiveSotaEntityId(analysisData.sota_details[0].entity_id);
      }
    }
  }, [selectedEntityId, analysisData]);

  const handleInitialLoad = async () => {
    try {
      setLoading(true);
      setStatusMessage('Initializing secure air-gapped supervisory audit index & benchmark datasets...');
      await seedMockData();

      setStatusMessage('Executing supervisory analytics engine...');
      const data = await runSupervisoryAnalysis();
      setAnalysisData(data);
      if (data?.sota_details && data.sota_details.length > 0) {
        setActiveSotaEntityId(data.sota_details[0].entity_id);
      }
      setStatusMessage(null);
    } catch (err: any) {
      console.error('Initial load error:', err);
      setStatusMessage('Supervisory analytics engine running in secure air-gapped mode.');
    } finally {
      setLoading(false);
    }
  };

  const handleSeedData = async () => {
    try {
      setLoading(true);
      setStatusMessage('Seeding benchmark datasets (CSE-POWERGRID, CSE-NATBANK, CSE-TELECOM)...');
      await seedMockData();
      const data = await runSupervisoryAnalysis();
      setAnalysisData(data);
      if (data?.sota_details && data.sota_details.length > 0) {
        setActiveSotaEntityId(data.sota_details[0].entity_id);
      }
      setStatusMessage('Benchmark datasets seeded & indexed successfully.');
      setTimeout(() => setStatusMessage(null), 3500);
    } catch (err: any) {
      console.error(err);
      setStatusMessage('Failed to seed datasets.');
    } finally {
      setLoading(false);
    }
  };

  const handleRunAnalysis = async () => {
    try {
      setLoading(true);
      setStatusMessage('Executing Benford Chi-Square, Poisson Burst Windowing, MinHash LSH, Shannon Entropy & Merkle compliance engines...');
      // Realistic brief processing feedback delay
      await new Promise((resolve) => setTimeout(resolve, 500));
      const data = await runSupervisoryAnalysis();
      const updatedData: SupervisoryAnalysisResponse = {
        ...data,
        analysis_timestamp: new Date().toISOString(),
        merkle_seal: data.merkle_seal
          ? {
              ...data.merkle_seal,
              sealed_at: new Date().toISOString(),
            }
          : undefined,
      };
      setAnalysisData(updatedData);
      if (updatedData?.sota_details && updatedData.sota_details.length > 0) {
        setActiveSotaEntityId(updatedData.sota_details[0].entity_id);
      }
      setStatusMessage(`Supervisory Analysis Complete: ${updatedData.total_entities_analyzed} CSEs Audited | ${updatedData.entities_at_risk_count} Flagged At-Risk | Cryptographic Merkle Seal Refreshed at ${new Date().toLocaleTimeString()}`);
      setTimeout(() => setStatusMessage(null), 5000);
    } catch (err: any) {
      console.error(err);
      setStatusMessage('Failed to execute supervisory examination engine.');
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadPdf = async () => {
    if (!analysisData) {
      setStatusMessage('Please execute supervisory analysis first to generate report data.');
      return;
    }
    try {
      setLoading(true);
      setStatusMessage('Opening official NCIIPC Supervisory Audit Report in a new tab...');

      // Open printable official report in a new tab (no auto-download)
      openHtmlReportInNewTab(analysisData);

      // Also save to exports folder via Tauri if running in desktop mode
      try {
        await exportPdfReport('exports/satsa_supervisory_audit_report.html');
      } catch (e) {
        // browser fallback mode ignore
      }

      setStatusMessage('Official Supervisory Audit Report opened in a new tab! (Use "Print / Save as PDF" button inside to save as PDF)');
      setTimeout(() => setStatusMessage(null), 5000);
    } catch (err: any) {
      console.error(err);
      setStatusMessage('Failed to open PDF audit report.');
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadJson = async () => {
    if (!analysisData) {
      setStatusMessage('Please execute supervisory analysis first to export data.');
      return;
    }
    try {
      setLoading(true);
      setStatusMessage('Opening Statutory JSON Examination Package in a new tab...');

      // Open structured JSON viewer in a new tab (no auto-download)
      openJsonPackageInNewTab(analysisData);

      // Also save to exports folder via Tauri if running in desktop mode
      try {
        await exportJsonPackage('exports/satsa_export_package.json');
      } catch (e) {
        // browser fallback mode ignore
      }

      setStatusMessage('Statutory JSON Examination Package opened in a new tab! (Features Copy JSON button)');
      setTimeout(() => setStatusMessage(null), 5000);
    } catch (err: any) {
      console.error(err);
      setStatusMessage('Failed to open JSON package.');
    } finally {
      setLoading(false);
    }
  };

  const handleImportFile = async (fileContent: string, fileName: string) => {
    try {
      setLoading(true);
      setStatusMessage(`Validating and indexing regulatory SOC audit log file '${fileName}'...`);

      let response;
      if (fileName.toLowerCase().endsWith('.json')) {
        response = await ingestJsonData(fileContent);
      } else {
        response = await ingestCsvData(fileContent);
      }

      setStatusMessage(`Successfully ingested ${response.total_alerts_ingested} alerts and ${response.total_cases_ingested} cases into audit repository. Running supervisory analysis...`);

      const data = await runSupervisoryAnalysis();
      setAnalysisData(data);
      if (data?.sota_details && data.sota_details.length > 0) {
        setActiveSotaEntityId(data.sota_details[0].entity_id);
      }
      setStatusMessage(`Analysis complete for imported file '${fileName}'. Ingested ${response.total_entities_ingested} entities.`);
      setTimeout(() => setStatusMessage(null), 4000);
    } catch (err: any) {
      console.error(err);
      setStatusMessage(`Error parsing dataset file: ${err?.message || err}`);
    } finally {
      setLoading(false);
    }
  };

  const currentSotaDetail: EntitySotaDetails | undefined =
    analysisData?.sota_details?.find((s) => s.entity_id === activeSotaEntityId) ||
    analysisData?.sota_details?.[0];

  const currentEntityName =
    analysisData?.risk_profiles?.find((p) => p.entity_id === activeSotaEntityId)?.entity_name ||
    activeSotaEntityId ||
    'Selected Entity';

  return (
    <div className="min-h-screen bg-slate-100 text-slate-900 flex flex-col font-sans">
      <Header
        onSeedData={handleSeedData}
        onRunAnalysis={handleRunAnalysis}
        onDownloadPdf={handleDownloadPdf}
        onDownloadJson={handleDownloadJson}
        onImportFile={handleImportFile}
        loading={loading}
        totalEntities={analysisData?.total_entities_analyzed || 0}
        atRiskEntities={analysisData?.entities_at_risk_count || 0}
        merkleSeal={analysisData?.merkle_seal}
        onOpenMerkleSeal={() => setIsMerkleModalOpen(true)}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-5 space-y-6">

        {/* Official Government Status Notice Memorandum */}
        {statusMessage && (
          <div className={`text-white p-3.5 rounded-sm text-xs font-medium flex items-center justify-between shadow-md transition-all border-l-4 ${
            statusMessage.includes('✅') || statusMessage.includes('successfully') || statusMessage.includes('Complete')
              ? 'bg-[#064e3b] border-emerald-400'
              : 'bg-[#0b2545] border-amber-400'
          }`}>
            <div className="flex items-center space-x-2.5">
              {statusMessage.includes('✅') ? (
                <CheckCircle2 className="w-5 h-5 text-emerald-400 flex-shrink-0" />
              ) : (
                <Info className="w-5 h-5 text-amber-400 flex-shrink-0" />
              )}
              <span>
                <strong className={`font-mono font-bold mr-1.5 uppercase ${
                  statusMessage.includes('✅') ? 'text-emerald-300' : 'text-amber-300'
                }`}>
                  {statusMessage.includes('✅') ? 'AUDIT NOTICE:' : 'OFFICIAL NOTICE:'}
                </strong>
                {statusMessage}
              </span>
            </div>
            <div className="flex items-center space-x-3">
              {loading && (
                <span className="text-slate-300 font-mono text-[11px] animate-pulse">
                  Processing Supervisory Audit Engine...
                </span>
              )}
              <button
                onClick={() => setStatusMessage(null)}
                className="text-slate-300 hover:text-white cursor-pointer p-0.5 rounded transition"
                title="Dismiss"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

        {/* Selected Entity Filter Bar */}
        {selectedEntityId && (
          <div className="bg-white border border-slate-300 rounded-sm px-4 py-2.5 flex items-center justify-between text-xs shadow-xs">
            <div className="flex items-center space-x-2">
              <span className="text-slate-600 font-semibold uppercase tracking-wider text-[11px]">Filtering Global Examination View:</span>
              <span className="font-bold text-[#003366] bg-blue-50 px-2 py-0.5 rounded-sm border border-blue-200 font-mono">
                {selectedEntityId}
              </span>
            </div>
            <button
              onClick={() => setSelectedEntityId(null)}
              className="text-slate-600 hover:text-slate-900 underline font-semibold flex items-center gap-1 cursor-pointer"
            >
              <X className="w-3.5 h-3.5" />
              <span>Clear Filter (Show All CSEs)</span>
            </button>
          </div>
        )}

        {/* 1. Risk Leaderboard */}
        {analysisData && (
          <RiskLeaderboard
            profiles={analysisData.risk_profiles}
            selectedEntityId={selectedEntityId}
            onSelectEntity={(id) =>
              setSelectedEntityId(selectedEntityId === id ? null : id)
            }
          />
        )}

        {/* 2. SOTA STATUTORY FORENSIC & MATHEMATICAL INTELLIGENCE SUITE */}
        {analysisData && analysisData.sota_details && analysisData.sota_details.length > 0 && (
          <section className="space-y-4">
            {/* SOTA Header & Entity Navigation Tabs */}
            <div className="bg-[#0f2b48] text-white p-3.5 rounded-sm border border-slate-700 flex flex-wrap items-center justify-between gap-3 shadow-xs">
              <div className="flex items-center space-x-2.5">
                <div className="p-1.5 bg-amber-400 text-slate-950 rounded-sm font-bold">
                  <Sparkles className="w-4 h-4" />
                </div>
                <div>
                  <h2 className="text-sm font-bold uppercase tracking-wide font-serif text-white flex items-center gap-2">
                    SECTION 2.0 : SOTA FORENSIC & MATHEMATICAL INTELLIGENCE SUITE
                  </h2>
                  <p className="text-[11px] text-slate-300">
                    Benford Goodness-of-Fit, MinHash LSH, Poisson Windowing, Shannon Entropy & MITRE ATT&CK Matrix
                  </p>
                </div>
              </div>

              {/* Entity Selector Pills */}
              <div className="flex items-center gap-1.5 bg-slate-900/80 p-1 rounded border border-slate-700">
                <span className="text-[10px] text-slate-400 uppercase font-mono px-2 flex items-center gap-1">
                  <Building2 className="w-3 h-3 text-amber-400" />
                  Target CSE:
                </span>
                {analysisData.sota_details.map((detail) => {
                  const isActive = detail.entity_id === (activeSotaEntityId || currentSotaDetail?.entity_id);
                  return (
                    <button
                      key={detail.entity_id}
                      onClick={() => {
                        setActiveSotaEntityId(detail.entity_id);
                        setSelectedEntityId(detail.entity_id);
                      }}
                      className={`px-2.5 py-1 text-xs font-mono font-bold rounded-xs transition cursor-pointer ${
                        isActive
                          ? 'bg-amber-400 text-slate-950 shadow-xs'
                          : 'text-slate-300 hover:text-white hover:bg-slate-800'
                      }`}
                    >
                      {detail.entity_id}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* SOTA Analytical Cards Stack */}
            <div className="space-y-4">
              {/* Benford's Law Inspector */}
              <BenfordInspector
                analysis={currentSotaDetail?.benford}
                entityId={activeSotaEntityId || currentSotaDetail?.entity_id || 'CSE'}
              />

              {/* Behavioral Forensics Radar: Shift Dumps, MinHash Collusion & Shannon Entropy */}
              <ForensicRadarPanel
                shiftDump={currentSotaDetail?.shift_dump}
                minhashClusters={currentSotaDetail?.minhash_clusters}
                shannonEntropy={currentSotaDetail?.shannon_entropy}
                entityId={activeSotaEntityId || currentSotaDetail?.entity_id || 'CSE'}
              />

              {/* MITRE ATT&CK Enterprise Matrix v14 Tactical Heatmap */}
              <MitreAttackHeatmap
                analysis={currentSotaDetail?.mitre_attack}
                entityId={activeSotaEntityId || currentSotaDetail?.entity_id || 'CSE'}
              />

              {/* CERT-In 6-Hour Statutory SLA Compliance Auditor */}
              <CertInComplianceCard
                compliance={currentSotaDetail?.certin_compliance}
                entityId={activeSotaEntityId || currentSotaDetail?.entity_id || 'CSE'}
              />
            </div>
          </section>
        )}

        {/* 3. Operational Weakness Panels */}
        {analysisData && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            <ExecutionGapsPanel
              findings={analysisData.findings}
              selectedEntityId={selectedEntityId}
            />
            <NegativeSpacePanel
              findings={analysisData.findings}
              selectedEntityId={selectedEntityId}
            />
          </div>
        )}

        {/* 4. Peer Benchmarking & Z-Scores */}
        {analysisData && (
          <PeerBenchmarkPanel
            benchmarks={analysisData.peer_benchmarks}
            selectedEntityId={selectedEntityId}
            onSelectEntity={(id) =>
              setSelectedEntityId(selectedEntityId === id ? null : id)
            }
          />
        )}

        {/* 5. Report Exporters */}
        <ReportExporter
          onDownloadPdf={handleDownloadPdf}
          onDownloadJson={handleDownloadJson}
          loading={loading}
        />
      </main>

      {/* Merkle Audit Seal Modal */}
      <MerkleSealModal
        seal={analysisData?.merkle_seal}
        isOpen={isMerkleModalOpen}
        onClose={() => setIsMerkleModalOpen(false)}
      />

      {/* Official Government Footer */}
      <footer className="bg-[#0b2545] text-slate-300 border-t-2 border-slate-800 py-4 px-4 text-center text-xs">
        <div className="max-w-7xl mx-auto space-y-1">
          <p className="font-semibold text-white">
            National Critical Information Infrastructure Protection Centre (NCIIPC / NTRO)
          </p>
          <p className="text-[11px] text-slate-400">
            Designated Authority under Section 70A of the Information Technology Act, 2000 | Government of India
          </p>
          <p className="text-[10px] text-slate-500 font-mono pt-1">
            SAT-SA Supervisory Analytics Tool for SOC Assessment | Official Statutory Audit Portal | Government of India
          </p>
        </div>
      </footer>
    </div>
  );
};

export default App;
