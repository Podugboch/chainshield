import React, { useState } from 'react';
import { Activity, ArrowRight, ShieldAlert, Building2, Briefcase, ExternalLink, Copy, Check, Download, AlertCircle } from 'lucide-react';
import { SAMPLE_INCIDENT, buildTransactionFlowGraph, identifyEntity } from '../lib/blockchainForensics';

export function CryptoForensics({ onGenerateReport }) {
  const [walletInput, setWalletInput] = useState(SAMPLE_INCIDENT.scammerAddress);
  const [txInput, setTxInput] = useState(SAMPLE_INCIDENT.txHash);
  const [network, setNetwork] = useState('Ethereum (ERC-20)');
  const [copiedKey, setCopiedKey] = useState(null);

  const flowGraph = buildTransactionFlowGraph(walletInput, txInput);

  const copyToClipboard = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  return (
    <div className="space-y-8 max-w-6xl mx-auto">
      
      {/* Top Banner */}
      <div className="text-center space-y-3">
        <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-amber-500/10 text-amber-400 text-xs font-mono border border-amber-500/20">
          <Activity className="w-3.5 h-3.5" />
          <span>On-Chain Transaction Flow & CEX De-Anonymization</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          Cryptocurrency Scam Forensics
        </h1>
        <p className="text-slate-400 max-w-2xl mx-auto text-sm sm:text-base">
          Trace stolen USDT across intermediate collection wallets directly to centralized exchange (Binance) deposit clusters.
        </p>
      </div>

      {/* Target Address & TX Inputs */}
      <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          
          <div className="space-y-1 md:col-span-1">
            <label className="text-xs font-mono text-slate-400">NETWORK PROTOCOL:</label>
            <select
              value={network}
              onChange={(e) => setNetwork(e.target.value)}
              className="w-full py-2.5 px-3 bg-[#0a0d14] border border-slate-700 rounded-xl text-white text-sm focus:outline-none focus:border-amber-500"
            >
              <option>Ethereum (ERC-20 USDT)</option>
              <option>BNB Smart Chain (BEP-20)</option>
              <option>Polygon (PoS USDT)</option>
              <option>Arbitrum One</option>
              <option>Tron (TRC-20)</option>
            </select>
          </div>

          <div className="space-y-1 md:col-span-2">
            <label className="text-xs font-mono text-slate-400">SCAMMER INTERCEPT WALLET:</label>
            <div className="relative">
              <input
                type="text"
                value={walletInput}
                onChange={(e) => setWalletInput(e.target.value)}
                className="w-full py-2.5 px-3 bg-[#0a0d14] border border-slate-700 rounded-xl text-white font-mono text-xs focus:outline-none focus:border-amber-500"
              />
            </div>
          </div>

        </div>

        <div className="space-y-1">
          <label className="text-xs font-mono text-slate-400">PAYOUT TRANSACTION HASH (TXID):</label>
          <input
            type="text"
            value={txInput}
            onChange={(e) => setTxInput(e.target.value)}
            className="w-full py-2.5 px-3 bg-[#0a0d14] border border-slate-700 rounded-xl text-white font-mono text-xs focus:outline-none focus:border-amber-500"
          />
        </div>
      </div>

      {/* Visual Transaction Flow Diagram */}
      <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-2xl space-y-6">
        
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
          <div>
            <h3 className="text-lg font-bold text-white">Visual On-Chain Trail</h3>
            <p className="text-xs text-slate-400">Transaction hops from victim payout source to Binance exchange cluster</p>
          </div>
          <button
            onClick={() => onGenerateReport && onGenerateReport()}
            className="px-4 py-2 bg-gradient-to-r from-amber-500 to-orange-600 hover:from-amber-400 hover:to-orange-500 text-white font-semibold text-xs rounded-xl transition shadow-lg shadow-amber-500/20 flex items-center space-x-2"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export Law Enforcement Report</span>
          </button>
        </div>

        {/* Node Flow Representation */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 relative">
          
          {/* Step 1: Victim Source */}
          <div className="p-5 rounded-2xl bg-[#0a0d14] border border-sky-500/40 relative shadow-lg shadow-sky-500/5 space-y-3">
            <div className="w-10 h-10 rounded-xl bg-sky-500/15 border border-sky-500/30 flex items-center justify-center text-sky-400">
              <Briefcase className="w-5 h-5" />
            </div>
            <div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-sky-500/10 text-sky-400 border border-sky-500/20">
                ORIGIN (VICTIM SOURCE)
              </span>
              <h4 className="text-base font-bold text-white mt-1">Atlas Capture Platform</h4>
              <p className="text-xs text-slate-400 mt-1">Legitimate contractor payout release</p>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800 text-xs font-mono text-sky-300">
              Transfer: <b>$146.07 USDT</b>
            </div>
          </div>

          {/* Step 2: Scammer Intermediary */}
          <div className="p-5 rounded-2xl bg-[#0a0d14] border border-red-500/50 relative shadow-lg shadow-red-500/10 space-y-3">
            <div className="w-10 h-10 rounded-xl bg-red-500/15 border border-red-500/30 flex items-center justify-center text-red-400">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20">
                SCAMMER INTERCEPT HOP
              </span>
              <h4 className="text-base font-bold text-white mt-1">Attacker Wallet (Swept)</h4>
              <div className="flex items-center space-x-1.5 mt-1">
                <span className="text-xs font-mono text-red-300 truncate">{walletInput.slice(0, 10)}...{walletInput.slice(-6)}</span>
                <button onClick={() => copyToClipboard(walletInput, 'scam-wal')} className="text-slate-400 hover:text-white">
                  {copiedKey === 'scam-wal' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
            </div>
            <div className="p-2.5 rounded-lg bg-red-950/30 border border-red-900/40 text-xs font-mono text-red-300">
              Status: <b>Drained ($0.00) &rarr; Swept to Binance</b>
            </div>
          </div>

          {/* Step 3: Binance KYC Deposit */}
          <div className="p-5 rounded-2xl bg-[#0a0d14] border border-amber-500/50 relative shadow-lg shadow-amber-500/10 space-y-3">
            <div className="w-10 h-10 rounded-xl bg-amber-500/15 border border-amber-500/30 flex items-center justify-center text-amber-400">
              <Building2 className="w-5 h-5" />
            </div>
            <div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">
                CEX ENDPOINT (KYC ATTACHED)
              </span>
              <h4 className="text-base font-bold text-white mt-1">Binance Deposit Account</h4>
              <p className="text-xs text-slate-400 mt-1">Directly tied to verified ID / passport</p>
            </div>
            <div className="p-2.5 rounded-lg bg-amber-950/30 border border-amber-900/40 text-xs font-mono text-amber-300">
              De-Anonymization: <b>Actionable via LER Subpoena</b>
            </div>
          </div>

        </div>

        {/* Forensic Deep Dive Details */}
        <div className="p-4 rounded-xl bg-[#0a0d14] border border-slate-800 space-y-3">
          <h4 className="text-xs font-mono font-bold text-slate-300 uppercase">Forensic Evidence Breakdown:</h4>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
            <div className="space-y-1">
              <span className="text-slate-500">TXID Hash:</span>
              <div className="p-2 rounded bg-slate-900 border border-slate-800 text-slate-300 break-all select-all">
                {txInput}
              </div>
            </div>

            <div className="space-y-1">
              <span className="text-slate-500">Full Scammer Address:</span>
              <div className="p-2 rounded bg-slate-900 border border-slate-800 text-red-300 break-all select-all">
                {walletInput}
              </div>
            </div>
          </div>
        </div>

      </div>

    </div>
  );
}
