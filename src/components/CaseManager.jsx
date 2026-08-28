import React, { useState, useEffect } from 'react';
import { FileText, Plus, CheckCircle, Clock, AlertTriangle, Shield, Download, ArrowRight } from 'lucide-react';
import { dbService } from '../lib/supabase';

export function CaseManager({ onOpenDossier }) {
  const [cases, setCases] = useState([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    loadCases();
  }, []);

  const loadCases = async () => {
    setIsLoading(true);
    const data = await dbService.getCases();
    setCases(data);
    setIsLoading(false);
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'EVIDENCE_COLLECTED':
        return { label: 'Evidence Collected', color: 'bg-sky-500/20 text-sky-400 border-sky-500/30' };
      case 'REPORTED_TO_BINANCE':
        return { label: 'Reported to Binance', color: 'bg-amber-500/20 text-amber-400 border-amber-500/30' };
      case 'POLICE_REPORTED':
        return { label: 'Law Enforcement Filed', color: 'bg-indigo-500/20 text-indigo-400 border-indigo-500/30' };
      case 'FROZEN':
        return { label: 'Funds Frozen', color: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30' };
      default:
        return { label: status, color: 'bg-slate-700 text-slate-300 border-slate-600' };
    }
  };

  return (
    <div className="space-y-8 max-w-6xl mx-auto">
      
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-extrabold text-white">Investigation Cases</h1>
          <p className="text-slate-400 text-sm mt-1">
            Active forensic investigation dossiers and incident recovery workflows.
          </p>
        </div>
      </div>

      {isLoading ? (
        <div className="text-center py-12 text-slate-500 font-mono text-sm">Loading investigation dossiers...</div>
      ) : (
        <div className="grid grid-cols-1 gap-6">
          {cases.map((item) => {
            const badge = getStatusBadge(item.status);
            return (
              <div key={item.id} className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-5">
                
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
                  <div className="space-y-1">
                    <div className="flex items-center space-x-3">
                      <h3 className="text-lg font-bold text-white">{item.title}</h3>
                      <span className={`px-2.5 py-0.5 rounded-full text-xs font-mono border ${badge.color}`}>
                        {badge.label}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 font-mono">
                      Platform: <b className="text-slate-200">{item.platform_name}</b> | Incident Date: {new Date(item.created_at).toLocaleDateString()}
                    </p>
                  </div>

                  <div className="text-right">
                    <span className="text-xs text-slate-400 font-mono block">STOLEN ASSET AMOUNT</span>
                    <span className="text-2xl font-extrabold text-red-400 font-mono">
                      ${Number(item.amount_lost_usd).toFixed(2)} USD
                    </span>
                  </div>
                </div>

                {/* Case Details Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 text-xs font-mono">
                  
                  <div className="p-3 rounded-xl bg-[#0a0d14] border border-slate-800 space-y-1">
                    <span className="text-slate-500">Asset Token:</span>
                    <p className="text-slate-200 font-semibold">{item.token_symbol}</p>
                  </div>

                  <div className="p-3 rounded-xl bg-[#0a0d14] border border-slate-800 space-y-1">
                    <span className="text-slate-500">Intermediary Wallet:</span>
                    <p className="text-red-300 truncate" title={item.scammer_intermediary_wallet}>
                      {item.scammer_intermediary_wallet.slice(0, 8)}...{item.scammer_intermediary_wallet.slice(-6)}
                    </p>
                  </div>

                  <div className="p-3 rounded-xl bg-[#0a0d14] border border-slate-800 space-y-1">
                    <span className="text-slate-500">Destination CEX:</span>
                    <p className="text-amber-300 font-semibold">{item.destination_entity}</p>
                  </div>

                  <div className="p-3 rounded-xl bg-[#0a0d14] border border-slate-800 space-y-1">
                    <span className="text-slate-500">TXID Hash:</span>
                    <p className="text-sky-300 truncate" title={item.tx_hash}>
                      {item.tx_hash.slice(0, 8)}...{item.tx_hash.slice(-6)}
                    </p>
                  </div>

                </div>

                <p className="text-xs text-slate-300 bg-slate-950 p-3.5 rounded-xl border border-slate-800/80">
                  {item.dossier_notes}
                </p>

                {/* Actions */}
                <div className="flex flex-wrap items-center justify-between pt-2">
                  <div className="text-xs text-slate-500">
                    Next recommended step: <b>Submit formal Law Enforcement request to Binance LER portal</b>
                  </div>
                  <button
                    onClick={() => onOpenDossier && onOpenDossier()}
                    className="px-4 py-2 bg-sky-500/15 hover:bg-sky-500/25 border border-sky-500/30 text-sky-400 text-xs font-semibold rounded-xl transition flex items-center space-x-1.5"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>View & Export Full Dossier</span>
                  </button>
                </div>

              </div>
            );
          })}
        </div>
      )}

    </div>
  );
}
