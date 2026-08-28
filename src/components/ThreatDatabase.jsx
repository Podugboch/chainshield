import React, { useState, useEffect } from 'react';
import { Database, ShieldAlert, Globe, ExternalLink, RefreshCw } from 'lucide-react';
import { dbService } from '../lib/supabase';

export function ThreatDatabase() {
  const [wallets, setWallets] = useState([]);
  const [scans, setScans] = useState([]);
  const [activeSubTab, setActiveSubTab] = useState('wallets');
  const [isLoading, setIsLoading] = useState(true);

  const loadData = async () => {
    setIsLoading(true);
    const w = await dbService.getScamWallets();
    const s = await dbService.getScans();
    setWallets(w);
    setScans(s);
    setIsLoading(false);
  };

  useEffect(() => {
    loadData();
  }, []);

  return (
    <div className="space-y-8 max-w-6xl mx-auto">
      
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-extrabold text-white">Threat Intelligence Database</h1>
          <p className="text-slate-400 text-sm mt-1">
            Community-reported scammer wallets, phishing links, and malicious indicators.
          </p>
        </div>
        <button
          onClick={loadData}
          className="flex items-center space-x-2 px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          <span>Refresh Feed</span>
        </button>
      </div>

      {/* Sub-Tabs */}
      <div className="flex space-x-2 border-b border-slate-800 pb-2">
        <button
          onClick={() => setActiveSubTab('wallets')}
          className={`px-4 py-2 rounded-xl text-xs font-mono font-semibold transition ${
            activeSubTab === 'wallets' ? 'bg-sky-500/20 text-sky-400 border border-sky-500/30' : 'text-slate-400 hover:text-white'
          }`}
        >
          Flagged Scam Wallets ({wallets.length})
        </button>
        <button
          onClick={() => setActiveSubTab('scans')}
          className={`px-4 py-2 rounded-xl text-xs font-mono font-semibold transition ${
            activeSubTab === 'scans' ? 'bg-sky-500/20 text-sky-400 border border-sky-500/30' : 'text-slate-400 hover:text-white'
          }`}
        >
          Scanned Phishing URLs ({scans.length})
        </button>
      </div>

      {/* Content */}
      {activeSubTab === 'wallets' ? (
        <div className="rounded-2xl bg-slate-900/90 border border-slate-800 overflow-hidden shadow-xl">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="p-4">Scammer Address</th>
                  <th className="p-4">Network</th>
                  <th className="p-4">Category / Target</th>
                  <th className="p-4">Stolen (USD)</th>
                  <th className="p-4">Destination Entity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {wallets.map((w) => (
                  <tr key={w.id} className="hover:bg-slate-800/40 transition">
                    <td className="p-4 font-bold text-red-400 break-all select-all">
                      {w.wallet_address}
                    </td>
                    <td className="p-4 text-slate-400">{w.network}</td>
                    <td className="p-4">
                      <span className="px-2 py-0.5 rounded bg-red-950/50 text-red-300 border border-red-900/40">
                        {w.impersonated_brand || w.scam_category}
                      </span>
                    </td>
                    <td className="p-4 font-bold text-slate-200">
                      ${Number(w.total_stolen_usd || 0).toFixed(2)}
                    </td>
                    <td className="p-4 text-amber-400 font-semibold">{w.destination_entity || 'Unknown'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        <div className="rounded-2xl bg-slate-900/90 border border-slate-800 overflow-hidden shadow-xl">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="p-4">Target Input / Domain</th>
                  <th className="p-4">Type</th>
                  <th className="p-4">Risk Rating</th>
                  <th className="p-4">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {scans.map((s) => (
                  <tr key={s.id} className="hover:bg-slate-800/40 transition">
                    <td className="p-4 text-slate-200 break-all">{s.input_content || s.target_domain}</td>
                    <td className="p-4 uppercase text-slate-400">{s.scan_type}</td>
                    <td className="p-4">
                      <span className={`px-2 py-0.5 rounded font-bold ${
                        s.risk_level === 'MALICIOUS' ? 'bg-red-500/20 text-red-400' :
                        s.risk_level === 'SUSPICIOUS' ? 'bg-amber-500/20 text-amber-400' :
                        'bg-emerald-500/20 text-emerald-400'
                      }`}>
                        {s.risk_level} ({s.risk_score}%)
                      </span>
                    </td>
                    <td className="p-4 text-slate-500">{new Date(s.created_at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

    </div>
  );
}
