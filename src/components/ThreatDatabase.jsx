import React, { useState, useEffect } from 'react';
import { RefreshCw, Search, Plus, ArrowRight, BadgeCheck, HelpCircle } from 'lucide-react';
import { dbService } from '../lib/supabase';

export function ThreatDatabase({ onOpenFlagModal, onScanAddress }) {
  const [wallets, setWallets] = useState([]);
  const [scans, setScans] = useState([]);
  const [activeSubTab, setActiveSubTab] = useState('wallets');
  const [searchQuery, setSearchQuery] = useState('');
  const [isLoading, setIsLoading] = useState(true);

  const loadData = async () => {
    setIsLoading(true);
    try {
      const [w, s] = await Promise.all([dbService.getScamWallets(), dbService.getScans()]);
      setWallets(w);
      setScans(s);
    } finally {
      // Without the finally, a throw left the refresh icon spinning forever.
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const filteredWallets = wallets.filter(w => {
    const q = searchQuery.toLowerCase();
    return (
      w.wallet_address?.toLowerCase().includes(q) ||
      w.impersonated_brand?.toLowerCase().includes(q) ||
      w.scam_category?.toLowerCase().includes(q) ||
      w.destination_entity?.toLowerCase().includes(q)
    );
  });

  const filteredScans = scans.filter(s => {
    const q = searchQuery.toLowerCase();
    return (
      s.input_content?.toLowerCase().includes(q) ||
      s.target_domain?.toLowerCase().includes(q) ||
      s.risk_level?.toLowerCase().includes(q)
    );
  });

  return (
    <div className="space-y-8 max-w-6xl mx-auto">
      
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-extrabold text-white">Threat Intelligence Database</h1>
          <p className="text-slate-400 text-sm mt-1">
            Flagged scammer wallets, rogue domains and phishing indicators. Rows are marked
            verified or unverified — an unverified row is one person's report, not a finding.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={() => onOpenFlagModal && onOpenFlagModal()}
            className="flex items-center space-x-1.5 px-4 py-2 rounded-xl bg-gradient-to-r from-red-600 to-rose-700 hover:from-red-500 hover:to-rose-600 text-white text-xs font-mono font-bold shadow-lg shadow-red-600/25 transition"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Flag Scammer Address</span>
          </button>
          
          <button
            onClick={loadData}
            className="flex items-center space-x-1.5 px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono transition"
            title="Refresh database feed"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Search & Tabs Controls */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 pb-2 border-b border-slate-800">
        <div className="flex space-x-2">
          <button
            onClick={() => setActiveSubTab('wallets')}
            className={`px-4 py-2 rounded-xl text-xs font-mono font-semibold transition ${
              activeSubTab === 'wallets' ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'text-slate-400 hover:text-white'
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

        {/* Search input */}
        <div className="relative w-full sm:w-72">
          <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search address, brand, or scam..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 bg-[#0a0d14] border border-slate-700 rounded-xl text-white placeholder-slate-500 text-xs font-mono focus:outline-none focus:border-red-500"
          />
        </div>
      </div>

      {/* Content */}
      {activeSubTab === 'wallets' ? (
        <div className="rounded-2xl bg-slate-900/90 border border-slate-800 overflow-hidden shadow-xl">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="p-4">Flagged Address</th>
                  <th className="p-4">Status</th>
                  <th className="p-4">Network</th>
                  <th className="p-4">Impersonated Platform</th>
                  <th className="p-4">Stolen (USD)</th>
                  <th className="p-4">Destination Entity</th>
                  <th className="p-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {filteredWallets.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="p-8 text-center text-slate-500">
                      No matching scammer wallets found.
                    </td>
                  </tr>
                ) : (
                  filteredWallets.map((w) => (
                    <tr key={w.id} className="hover:bg-slate-800/40 transition">
                      <td className="p-4">
                        <div className="flex items-center space-x-2">
                          <span className="font-bold text-red-400 break-all select-all">
                            {w.wallet_address}
                          </span>
                        </div>
                        {w.notes && (
                          <p className="text-[11px] text-slate-500 font-sans mt-0.5 max-w-sm truncate">
                            {w.notes}
                          </p>
                        )}
                      </td>
                      <td className="p-4">
                        {w.verified !== false ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-red-500/15 text-red-300 border border-red-500/30">
                            <BadgeCheck className="w-3 h-3" /> verified
                          </span>
                        ) : (
                          <span
                            className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/30"
                            title="Submitted by a user and not yet reviewed. Treat as a lead, not a finding."
                          >
                            <HelpCircle className="w-3 h-3" /> unverified
                          </span>
                        )}
                      </td>
                      <td className="p-4 text-slate-400">{w.network}</td>
                      <td className="p-4">
                        <span className="px-2.5 py-0.5 rounded bg-red-950/50 text-red-300 border border-red-900/40 font-bold">
                          {w.impersonated_brand || w.scam_category}
                        </span>
                      </td>
                      <td className="p-4 font-bold text-slate-200">
                        {/* A missing amount used to render as "$0.00", which reads as a
                            measured loss of nothing rather than an unrecorded one. */}
                        {Number.isFinite(Number(w.total_stolen_usd)) && w.total_stolen_usd !== null
                          ? `$${Number(w.total_stolen_usd).toFixed(2)}`
                          : <span className="text-slate-500 font-normal">not recorded</span>}
                      </td>
                      <td className="p-4 text-amber-400 font-semibold">{w.destination_entity || 'Unknown'}</td>
                      <td className="p-4 text-right">
                        <button
                          onClick={() => onScanAddress && onScanAddress(w.wallet_address)}
                          className="px-3 py-1 rounded-lg bg-sky-500/15 hover:bg-sky-500/25 text-sky-400 border border-sky-500/30 text-[11px] font-semibold transition inline-flex items-center space-x-1"
                        >
                          <span>Trace Live</span>
                          <ArrowRight className="w-3 h-3" />
                        </button>
                      </td>
                    </tr>
                  ))
                )}
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
                {filteredScans.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="p-8 text-center text-slate-500">
                      No matching scans found.
                    </td>
                  </tr>
                ) : (
                  filteredScans.map((s) => (
                    <tr key={s.id} className="hover:bg-slate-800/40 transition">
                      <td className="p-4 text-slate-200 break-all">{s.input_content || s.target_domain}</td>
                      <td className="p-4 uppercase text-slate-400">{s.scan_type}</td>
                      <td className="p-4">
                        <span className={`px-2 py-0.5 rounded font-bold ${
                          ['MALICIOUS', 'CRITICAL', 'CRITICAL MALICIOUS'].includes(s.risk_level) ? 'bg-red-500/20 text-red-400' :
                          ['HIGH RISK', 'SUSPICIOUS'].includes(s.risk_level) ? 'bg-amber-500/20 text-amber-400' :
                          ['LOW RISK'].includes(s.risk_level) ? 'bg-sky-500/20 text-sky-400' :
                          ['SAFE', 'CLEAN', 'NO THREATS FOUND'].includes(s.risk_level) ? 'bg-emerald-500/20 text-emerald-400' :
                          // Anything unrecognised, including UNKNOWN, is grey. It used to
                          // land in the green branch by default.
                          'bg-slate-700/40 text-slate-300'
                        }`}>
                          {s.risk_level || 'UNKNOWN'}
                          {Number.isFinite(Number(s.risk_score)) ? ` (${s.risk_score}%)` : ''}
                        </span>
                      </td>
                      <td className="p-4 text-slate-500">{new Date(s.created_at).toLocaleString()}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

    </div>
  );
}
