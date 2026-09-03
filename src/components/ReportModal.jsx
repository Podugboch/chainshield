import React, { useState } from 'react';
import { X, Copy, Check, Printer, FileText, Shield } from 'lucide-react';
import { DEFAULT_INCIDENT, generateLawEnforcementDossier } from '../lib/blockchainForensics';

export function ReportModal({ isOpen, onClose, customIncident }) {
  // Hooks first. App.jsx renders this modal unconditionally and toggles `isOpen`,
  // so returning before useState took the hook count from 0 to 1 on open, which
  // React rejects outright ("Rendered more hooks than during the previous
  // render") -- the modal could not be opened at all.
  const [copied, setCopied] = useState(false);
  const incidentData = customIncident || DEFAULT_INCIDENT;
  const dossierText = isOpen ? generateLawEnforcementDossier(incidentData) : '';

  if (!isOpen) return null;

  const handleCopy = () => {
    navigator.clipboard.writeText(dossierText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
      <div className="w-full max-w-3xl max-h-[90vh] bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl flex flex-col overflow-hidden">
        
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/80">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 rounded-lg bg-sky-500/20 text-sky-400 flex items-center justify-center">
              <FileText className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white">Official Fraud & Law Enforcement Dossier</h3>
              <p className="text-xs text-slate-400">Formatted for Binance Security & Cybercrime Portals (IC3/Interpol)</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Content */}
        <div className="p-6 overflow-y-auto font-mono text-xs text-slate-300 leading-relaxed bg-[#070a0f] space-y-4">
          <pre className="whitespace-pre-wrap selection:bg-sky-500/30 selection:text-sky-200">
            {dossierText}
          </pre>
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-4 border-t border-slate-800 bg-slate-950 flex items-center justify-between">
          <span className="text-xs text-slate-500">
            Ready to attach to Binance Ticket or Police Report
          </span>
          <div className="flex space-x-3">
            <button
              onClick={handleCopy}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white font-semibold text-xs rounded-xl transition flex items-center space-x-1.5"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied to Clipboard' : 'Copy Text'}</span>
            </button>
            <button
              onClick={handlePrint}
              className="px-4 py-2 bg-gradient-to-r from-sky-500 to-indigo-600 hover:from-sky-400 hover:to-indigo-500 text-white font-semibold text-xs rounded-xl transition flex items-center space-x-1.5 shadow-lg shadow-sky-500/25"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>Print / PDF</span>
            </button>
          </div>
        </div>

      </div>
    </div>
  );
}
