import React, { useState } from 'react';
import { MerkleAuditSeal } from '../types/api';
import { ShieldCheck, Copy, Check, Lock, FileKey2, X, Terminal } from 'lucide-react';

interface MerkleSealModalProps {
  seal: MerkleAuditSeal | null | undefined;
  isOpen: boolean;
  onClose: () => void;
}

export const MerkleSealModal: React.FC<MerkleSealModalProps> = ({ seal, isOpen, onClose }) => {
  const [copied, setCopied] = useState(false);

  if (!isOpen || !seal) return null;

  const handleCopyHash = () => {
    navigator.clipboard.writeText(seal.root_hash);
    setCopied(true);
    setTimeout(() => setCopied(false), 2500);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
      <div className="bg-white rounded-sm border border-slate-400 shadow-2xl max-w-2xl w-full overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        {/* Modal Header */}
        <div className="bg-[#0b2545] text-white px-5 py-3.5 border-b border-slate-700 flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <div className="p-1.5 bg-emerald-500/20 text-emerald-400 rounded border border-emerald-500/40">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold uppercase tracking-wide font-serif">
                RFC 6962 Cryptographic Chain-of-Custody Audit Seal
              </h3>
              <p className="text-[11px] text-slate-300 font-mono">
                Statutory Evidence Authentication | NCIIPC - NTRO
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded transition cursor-pointer"
            title="Close"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-5 space-y-4">
          {/* Status Badge */}
          <div className="bg-emerald-50 border border-emerald-300 rounded p-3 flex items-center justify-between">
            <div className="flex items-center space-x-2.5">
              <FileKey2 className="w-5 h-5 text-emerald-700" />
              <div>
                <span className="text-xs font-bold text-emerald-950 block">
                  AIR-GAPPED SHA-256 BINARY MERKLE ROOT CONFIRMED
                </span>
                <span className="text-[11px] text-emerald-800">
                  Domain Separated: Leaf (0x00) Internal Node (0x01)
                </span>
              </div>
            </div>
            <span className="bg-emerald-700 text-white font-mono text-[11px] font-bold px-2.5 py-1 rounded">
              {seal.verification_status}
            </span>
          </div>

          {/* Cryptographic Root Hash Display */}
          <div className="bg-slate-900 rounded p-3 border border-slate-800">
            <div className="flex items-center justify-between mb-1.5 text-xs text-slate-400">
              <span className="font-mono flex items-center gap-1.5 text-amber-400 font-bold">
                <Terminal className="w-3.5 h-3.5" />
                MERKLE_ROOT_SHA256 (256-bit Digest)
              </span>
              <button
                onClick={handleCopyHash}
                className="flex items-center space-x-1 text-[11px] text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 px-2 py-0.5 rounded border border-slate-600 transition cursor-pointer"
              >
                {copied ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    <span className="text-emerald-400">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    <span>Copy Hash</span>
                  </>
                )}
              </button>
            </div>
            <div className="font-mono text-xs text-emerald-400 break-all select-all bg-black/50 p-2.5 rounded border border-slate-800 leading-relaxed">
              {seal.root_hash}
            </div>
          </div>

          {/* Details Grid */}
          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="bg-slate-50 p-2.5 rounded border border-slate-200">
              <span className="text-[10px] text-slate-500 uppercase font-bold block">Batch Audit Identifier</span>
              <span className="font-mono font-bold text-slate-900">{seal.batch_id}</span>
            </div>

            <div className="bg-slate-50 p-2.5 rounded border border-slate-200">
              <span className="text-[10px] text-slate-500 uppercase font-bold block">Sealed Leaves (Records)</span>
              <span className="font-mono font-bold text-slate-900">{seal.leaf_count} Encrypted Findings</span>
            </div>

            <div className="bg-slate-50 p-2.5 rounded border border-slate-200">
              <span className="text-[10px] text-slate-500 uppercase font-bold block">Sealed Timestamp (UTC)</span>
              <span className="font-mono font-bold text-slate-900">{new Date(seal.sealed_at).toUTCString()}</span>
            </div>

            <div className="bg-slate-50 p-2.5 rounded border border-slate-200">
              <span className="text-[10px] text-slate-500 uppercase font-bold block">Cryptographic Standard</span>
              <span className="font-mono font-bold text-slate-900">{seal.signature_algorithm}</span>
            </div>
          </div>

          {/* Legal Chain-of-Custody Guarantee */}
          <div className="bg-slate-100 p-3 rounded text-[11px] text-slate-700 border border-slate-300 leading-relaxed">
            <div className="flex items-center gap-1.5 font-bold text-slate-900 mb-1">
              <Lock className="w-3.5 h-3.5 text-blue-900" />
              <span>INDIAN EVIDENCE ACT & IT ACT EVIDENTIARY COMPLIANCE:</span>
            </div>
            <p>
              This cryptographic digest seals all evaluated alerts, investigator durations, resolution notes, and statutory findings into an immutable Merkle tree.
              Any retrospective alteration of forensic records invalidates the root digest, ensuring non-repudiation in supervisory inquiries under
              <strong> Section 70B of the Information Technology Act, 2000</strong>.
            </p>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="bg-slate-100 px-5 py-3 border-t border-slate-300 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 text-xs font-bold bg-slate-800 hover:bg-slate-900 text-white rounded-sm transition cursor-pointer"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
};
