import React, { useState, useEffect } from 'react';
import { 
  Activity, Search, ArrowRight, ShieldAlert, Building2, Briefcase, 
  ExternalLink, Copy, Check, Download, AlertTriangle, RefreshCw, 
  CheckCircle2, Coins, Flame, Layers, ShieldCheck, Database, Flag
} from 'lucide-react';
import { 
  SUPPORTED_NETWORKS, DEFAULT_INCIDENT, 
  scanWalletLive, scanTransactionLive, identifyEntity 
} from '../lib/blockchainForensics';
import { dbService } from '../lib/supabase';

export function CryptoForensics({ onGenerateReport, onOpenFlagModal, initialTarget = '' }) {
  const [queryInput, setQueryInput] = useState(initialTarget || DEFAULT_INCIDENT.scammerAddress);
  const [selectedNetwork, setSelectedNetwork] = useState('ethereum');
  const [scanType, setScanType] = useState('wallet');
  const [isScanning, setIsScanning] = useState(false);
  const [walletResult, setWalletResult] = useState(null);
  const [txResult, setTxResult] = useState(null);
  const [flagRecord, setFlagRecord] = useState(null);
  const [errorMsg, setErrorMsg] = useState(null);
  const [copiedKey, setCopiedKey] = useState(null);

  useEffect(() => {
    if (initialTarget) {
      setQueryInput(initialTarget);
      handleRunForensics(initialTarget, 'wallet', selectedNetwork);
    }
  }, [initialTarget]);

  const handleRunForensics = async (targetVal, typeVal, netVal) => {
    const rawTarget = (targetVal || queryInput).trim();
    const type = typeVal || scanType;
    const net = netVal || selectedNetwork;

    if (!rawTarget) return;

    setIsScanning(true);
    setErrorMsg(null);
    setWalletResult(null);
    setTxResult(null);
    setFlagRecord(null);

    try {
      if (type === 'wallet') {
        // 1. Live on-chain query
        const res = await scanWalletLive(rawTarget, net);
        
        // 2. Check if address is flagged in Supabase
        const isFlagged = await dbService.isWalletFlagged(rawTarget);
        if (isFlagged) {
          res.riskScore = 100;
          res.riskLevel = 'CRITICAL';
          res.entity = {
            name: `FLAGGED SCAMMER: ${isFlagged.impersonated_brand || isFlagged.scam_category}`,
            type: 'FLAGGED_SCAMMER',
            riskLevel: 'CRITICAL',
            color: '#ef4444'
          };
          setFlagRecord(isFlagged);
        }

        setWalletResult(res);
      } else {
        const res = await scanTransactionLive(rawTarget, net);
        if (res.found === false) {
          setErrorMsg(res.message);
        } else {
          setTxResult(res);
        }
      }
    } catch (err) {
      setErrorMsg(err.message || 'Scan failed to query live on-chain RPC nodes.');
    } finally {
      setIsScanning(false);
    }
  };

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
          <span>Real-Time Scammer Detection & Multi-Chain Forensics</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          Flagged Scammer Tracker & Forensics
        </h1>
        <p className="text-slate-400 max-w-2xl mx-auto text-sm sm:text-base">
          Scan any cryptocurrency wallet address to identify flagged scammers, verify burner/sweep status, and trace funds to exchange KYC endpoints.
        </p>
      </div>

      {/* Target Search & Filter Controls */}
      <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-2xl space-y-4">
        
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex space-x-2">
            <button
              type="button"
              onClick={() => {
                setScanType('wallet');
                setQueryInput('0xd23Ac29C1e1949D0c5864B4a23a01cc3e4dd236b');
              }}
              className={`px-4 py-1.5 rounded-lg text-xs font-mono font-semibold transition ${
                scanType === 'wallet' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' : 'text-slate-400 hover:text-white'
              }`}
            >
              Scan Wallet Address
            </button>
            <button
              type="button"
              onClick={() => {
                setScanType('tx');
                setQueryInput('0x44e5dbb257694dd3297e3a24808a6098f2bce9816bc9b202879104dccec911e7');
              }}
              className={`px-4 py-1.5 rounded-lg text-xs font-mono font-semibold transition ${
                scanType === 'tx' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' : 'text-slate-400 hover:text-white'
              }`}
            >
              Scan Transaction Hash (TXID)
            </button>
          </div>

          <button
            type="button"
            onClick={() => onOpenFlagModal && onOpenFlagModal(queryInput)}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-red-500/15 hover:bg-red-500/25 border border-red-500/30 text-red-400 text-xs font-mono font-bold transition"
          >
            <Flag className="w-3.5 h-3.5" />
            <span>Flag Address as Scammer</span>
          </button>
        </div>

        {/* Input Form */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleRunForensics();
          }}
          className="grid grid-cols-1 md:grid-cols-4 gap-3"
        >
          <div className="md:col-span-1">
            <select
              value={selectedNetwork}
              onChange={(e) => setSelectedNetwork(e.target.value)}
              className="w-full h-full py-3 px-3 bg-[#0a0d14] border border-slate-700 rounded-xl text-white text-xs font-mono focus:outline-none focus:border-amber-500"
            >
              {Object.entries(SUPPORTED_NETWORKS).map(([key, net]) => (
                <option key={key} value={key}>
                  {net.name}
                </option>
              ))}
            </select>
          </div>

          <div className="md:col-span-2">
            <input
              type="text"
              placeholder={scanType === 'wallet' ? 'Enter 0x address (e.g. 0xd23Ac2...)' : 'Enter 0x transaction hash...'}
              value={queryInput}
              onChange={(e) => setQueryInput(e.target.value)}
              className="w-full py-3 px-4 bg-[#0a0d14] border border-slate-700 rounded-xl text-white font-mono text-xs focus:outline-none focus:border-amber-500"
            />
          </div>

          <div className="md:col-span-1">
            <button
              type="submit"
              disabled={isScanning || !queryInput.trim()}
              className="w-full py-3 bg-gradient-to-r from-amber-500 to-orange-600 hover:from-amber-400 hover:to-orange-500 text-white font-semibold text-xs rounded-xl transition-all shadow-lg shadow-amber-500/25 flex items-center justify-center space-x-2 disabled:opacity-50"
            >
              {isScanning ? (
                <>
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  <span>Querying Nodes...</span>
                </>
              ) : (
                <>
                  <Search className="w-4 h-4" />
                  <span>Run Live Forensics</span>
                </>
              )}
            </button>
          </div>
        </form>

      </div>

      {/* Error Message */}
      {errorMsg && (
        <div className="p-4 rounded-xl bg-red-950/50 border border-red-500/40 text-red-300 flex items-center space-x-3 text-xs">
          <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* ======================================================== */}
      {/* 1. LIVE WALLET SCAN RESULTS */}
      {/* ======================================================== */}
      {walletResult && (
        <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-2xl space-y-6 animate-fadeIn">
          
          {/* Flagged Alert Banner */}
          {flagRecord && (
            <div className="p-5 rounded-2xl bg-gradient-to-r from-red-950/80 to-rose-950/60 border-2 border-red-500/60 shadow-xl shadow-red-950/30 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
              <div className="flex items-start space-x-3">
                <ShieldAlert className="w-8 h-8 text-red-400 shrink-0 mt-0.5 animate-pulse" />
                <div>
                  <span className="px-2.5 py-0.5 rounded-full bg-red-500/20 text-red-300 text-[10px] font-mono font-bold border border-red-500/40 uppercase">
                    CONFIRMED MALICIOUS SCAMMER WALLET
                  </span>
                  <h3 className="text-base font-extrabold text-white mt-1">
                    Indexed in Threat Database: {flagRecord.impersonated_brand || flagRecord.scam_category}
                  </h3>
                  <p className="text-xs text-red-200/90 mt-1">
                    This wallet is actively flagged for <b>{flagRecord.scam_category}</b>. Total verified losses: <b>${Number(flagRecord.total_stolen_usd || 0).toFixed(2)} USD</b>.
                  </p>
                  {flagRecord.destination_entity && (
                    <p className="text-xs text-amber-300 font-mono mt-1">
                      Target Cashout Gateway: <b>{flagRecord.destination_entity}</b>
                    </p>
                  )}
                </div>
              </div>

              <button
                onClick={() => onGenerateReport && onGenerateReport()}
                className="px-4 py-2.5 bg-red-600 hover:bg-red-500 text-white font-bold text-xs rounded-xl transition shadow-lg shadow-red-600/30 flex items-center space-x-2 shrink-0"
              >
                <Download className="w-4 h-4" />
                <span>Export Binance / Police Case</span>
              </button>
            </div>
          )}

          {/* Header Card */}
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
            <div className="space-y-1">
              <div className="flex items-center space-x-2">
                <span className="text-xs font-mono text-slate-400">TARGET WALLET:</span>
                <span className="text-xs font-mono font-bold text-red-400 bg-red-950/40 px-2 py-0.5 rounded border border-red-900/40 select-all">
                  {walletResult.address}
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono">
                Network: <b className="text-slate-200">{walletResult.network}</b> | Type: <b>{walletResult.isContract ? 'Smart Contract' : 'Externally Owned Account (EOA)'}</b>
              </p>
            </div>

            <div className="flex items-center space-x-3">
              <div className={`px-4 py-2 rounded-xl font-bold font-mono text-center border ${
                walletResult.riskLevel === 'CRITICAL' ? 'text-red-400 bg-red-500/10 border-red-500/30' :
                walletResult.riskLevel === 'SUSPICIOUS' ? 'text-amber-400 bg-amber-500/10 border-amber-500/30' :
                'text-emerald-400 bg-emerald-500/10 border-emerald-500/30'
              }`}>
                <div className="text-[10px] uppercase tracking-wider">{walletResult.riskLevel} RISK</div>
                <div className="text-xl font-extrabold">{walletResult.riskScore}/100</div>
              </div>
            </div>
          </div>

          {/* On-Chain Metrics Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="p-4 rounded-xl bg-[#0a0d14] border border-slate-800 space-y-1">
              <span className="text-xs text-slate-500 font-mono">Native Balance:</span>
              <p className="text-lg font-bold text-white font-mono">
                {walletResult.nativeBalance.toFixed(4)} {walletResult.currency}
              </p>
            </div>

            <div className="p-4 rounded-xl bg-[#0a0d14] border border-slate-800 space-y-1">
              <span className="text-xs text-slate-500 font-mono">Activity Count (Nonce):</span>
              <p className="text-lg font-bold text-white font-mono">
                {walletResult.nonce} Transactions
              </p>
            </div>

            <div className="p-4 rounded-xl bg-[#0a0d14] border border-slate-800 space-y-1">
              <span className="text-xs text-slate-500 font-mono">Threat Mapping:</span>
              <p className="text-xs font-bold font-mono truncate" style={{ color: walletResult.entity.color }}>
                {walletResult.entity.name}
              </p>
            </div>

            <div className="p-4 rounded-xl bg-[#0a0d14] border border-slate-800 space-y-1">
              <span className="text-xs text-slate-500 font-mono">Live Explorer:</span>
              <a
                href={walletResult.explorerUrl}
                target="_blank"
                rel="noreferrer"
                className="text-xs text-sky-400 hover:underline flex items-center space-x-1 font-mono pt-1"
              >
                <span>View On-Chain</span>
                <ExternalLink className="w-3 h-3" />
              </a>
            </div>
          </div>

          {/* Token Balances Audit */}
          <div className="p-4 rounded-xl bg-[#0a0d14] border border-slate-800 space-y-2">
            <h4 className="text-xs font-mono font-bold text-slate-300 uppercase flex items-center space-x-2">
              <Coins className="w-4 h-4 text-amber-400" />
              <span>Stablecoin Balances Audit:</span>
            </h4>
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 pt-1">
              {walletResult.tokenBalances.map((tb, idx) => (
                <div key={idx} className="p-3 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-between text-xs font-mono">
                  <span className="text-slate-300 font-semibold">{tb.symbol}</span>
                  <span className={tb.balance > 0 ? "text-emerald-400 font-bold" : "text-slate-500"}>
                    {tb.balance.toFixed(2)}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Actions */}
          <div className="pt-4 border-t border-slate-800 flex flex-wrap items-center justify-between gap-3">
            <button
              onClick={() => onOpenFlagModal && onOpenFlagModal(walletResult.address)}
              className="px-4 py-2 bg-red-950/40 hover:bg-red-900/50 border border-red-500/40 text-red-300 text-xs font-mono font-semibold rounded-xl transition flex items-center space-x-1.5"
            >
              <Flag className="w-3.5 h-3.5" />
              <span>{flagRecord ? 'Update Flagged Intelligence' : 'Flag Address as Malicious'}</span>
            </button>

            <button
              onClick={() => onGenerateReport && onGenerateReport()}
              className="px-4 py-2 bg-gradient-to-r from-amber-500 to-orange-600 hover:from-amber-400 hover:to-orange-500 text-white font-semibold text-xs rounded-xl transition shadow-lg shadow-amber-500/20 flex items-center space-x-2"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Generate Police / Binance Dossier</span>
            </button>
          </div>

        </div>
      )}

      {/* ======================================================== */}
      {/* 2. LIVE TRANSACTION SCAN RESULTS & HOP GRAPH */}
      {/* ======================================================== */}
      {txResult && (
        <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-2xl space-y-6 animate-fadeIn">
          
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3 pb-4 border-b border-slate-800">
            <div className="space-y-1">
              <span className="text-xs font-mono text-slate-400">TRANSACTION HASH:</span>
              <p className="text-xs font-mono text-sky-400 break-all select-all font-bold">
                {txResult.txHash}
              </p>
            </div>
            <span className={`px-3 py-1 rounded-full text-xs font-mono font-bold ${
              txResult.status === 'SUCCESS' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'bg-red-500/20 text-red-400'
            }`}>
              STATUS: {txResult.status}
            </span>
          </div>

          {txResult.isTokenTransfer && txResult.tokenTransferData && (
            <div className="p-4 rounded-xl bg-amber-950/30 border border-amber-500/30 space-y-2">
              <span className="text-xs font-mono font-bold text-amber-300 uppercase">
                Detected ERC-20 Token Transfer:
              </span>
              <div className="flex items-center space-x-3 text-sm font-mono text-white">
                <span className="text-xl font-extrabold text-amber-400">
                  ${txResult.tokenTransferData.amount.toFixed(2)} {txResult.tokenTransferData.tokenSymbol}
                </span>
              </div>
            </div>
          )}

          {/* Dynamic Hop Visualization */}
          <div className="space-y-3">
            <h4 className="text-xs font-mono font-bold text-slate-300 uppercase">On-Chain Hop Diagram:</h4>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {txResult.hops.map((hop, idx) => (
                <div key={idx} className="p-4 rounded-xl bg-[#0a0d14] border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-sky-500/10 text-sky-400 border border-sky-500/20">
                      STEP {hop.step}: {hop.label}
                    </span>
                    <span className="text-xs font-mono font-bold" style={{ color: hop.entity.color }}>
                      {hop.entity.name}
                    </span>
                  </div>
                  <p className="text-xs font-mono text-slate-300 truncate" title={hop.address}>
                    {hop.address}
                  </p>
                  <p className="text-xs text-amber-300/90 font-medium">
                    {hop.action}
                  </p>
                </div>
              ))}
            </div>
          </div>

        </div>
      )}

      {/* Default Visual Hop Flow for Verified Atlas Case */}
      {!walletResult && !txResult && (
        <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-2xl space-y-6">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
            <div>
              <h3 className="text-lg font-bold text-white">Verified Incident Forensics: Atlas Capture</h3>
              <p className="text-xs text-slate-400">On-chain hop sequence leading to Binance de-anonymization</p>
            </div>
            <button
              onClick={() => onGenerateReport && onGenerateReport()}
              className="px-4 py-2 bg-gradient-to-r from-amber-500 to-orange-600 hover:from-amber-400 hover:to-orange-500 text-white font-semibold text-xs rounded-xl transition shadow-lg shadow-amber-500/20 flex items-center space-x-2"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export Dossier</span>
            </button>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 relative">
            <div className="p-5 rounded-2xl bg-[#0a0d14] border border-sky-500/40 space-y-3">
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

            <div className="p-5 rounded-2xl bg-[#0a0d14] border border-red-500/50 space-y-3">
              <div className="w-10 h-10 rounded-xl bg-red-500/15 border border-red-500/30 flex items-center justify-center text-red-400">
                <ShieldAlert className="w-5 h-5" />
              </div>
              <div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20">
                  SCAMMER INTERCEPT HOP
                </span>
                <h4 className="text-base font-bold text-white mt-1">Attacker Wallet (Swept)</h4>
                <p className="text-xs font-mono text-red-300 mt-1">0xd23Ac2...236b</p>
              </div>
              <div className="p-2.5 rounded-lg bg-red-950/30 border border-red-900/40 text-xs font-mono text-red-300">
                Status: <b>Drained ($0.00) &rarr; Swept to Binance</b>
              </div>
            </div>

            <div className="p-5 rounded-2xl bg-[#0a0d14] border border-amber-500/50 space-y-3">
              <div className="w-10 h-10 rounded-xl bg-amber-500/15 border border-amber-500/30 flex items-center justify-center text-amber-400">
                <Building2 className="w-5 h-5" />
              </div>
              <div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">
                  CEX ENDPOINT (KYC ATTACHED)
                </span>
                <h4 className="text-base font-bold text-white mt-1">Binance Deposit Cluster</h4>
                <p className="text-xs text-slate-400 mt-1">Directly tied to verified ID / passport</p>
              </div>
              <div className="p-2.5 rounded-lg bg-amber-950/30 border border-amber-900/40 text-xs font-mono text-amber-300">
                De-Anonymization: <b>Actionable via LER Subpoena</b>
              </div>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
