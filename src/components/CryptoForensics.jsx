import React, { useState, useEffect } from 'react';
import { 
  Activity, Search, ArrowRight, ShieldAlert, Building2, Briefcase, 
  ExternalLink, Copy, Check, Download, AlertTriangle, RefreshCw, 
  CheckCircle2, Coins, Flame, Layers, ShieldCheck, Database, Flag,
  ArrowDownLeft, ArrowUpRight, Clock, History, Filter
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
  const [txFilter, setTxFilter] = useState('ALL'); // ALL, IN, OUT

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
        const res = await scanWalletLive(rawTarget, net);
        
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

  const handleTraceSingleTx = (hash) => {
    setScanType('tx');
    setQueryInput(hash);
    handleRunForensics(hash, 'tx', selectedNetwork);
    window.scrollTo({ top: 100, behavior: 'smooth' });
  };

  const copyToClipboard = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const filteredTransactions = (walletResult?.transactions || []).filter(tx => {
    if (txFilter === 'IN') return tx.direction === 'IN';
    if (txFilter === 'OUT') return tx.direction === 'OUT';
    return true;
  });

  return (
    <div className="space-y-8 max-w-6xl mx-auto">
      
      {/* Top Banner */}
      <div className="text-center space-y-3">
        <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-amber-500/10 text-amber-400 text-xs font-mono border border-amber-500/20">
          <Activity className="w-3.5 h-3.5" />
          <span>Real-Time Scammer Detection, Balance Audit & Transaction History</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          Flagged Scammer Tracker & Forensics
        </h1>
        <p className="text-slate-400 max-w-2xl mx-auto text-sm sm:text-base">
          Scan any cryptocurrency wallet address to view live on-chain balances, audit full transaction histories, verify burner status, and trace funds.
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
                setQueryInput('0x1adaa8a8cec1206ba810c7bd669072971a01fde7d424c9801b0f1cc6b67f1842');
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
                  <span>Querying Nodes & Ledger...</span>
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
      {/* 1. LIVE WALLET SCAN RESULTS & TRANSACTION HISTORY */}
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

          {/* ======================================================== */}
          {/* ON-CHAIN TRANSACTION HISTORY SECTION */}
          {/* ======================================================== */}
          <div className="p-5 rounded-2xl bg-[#0a0d14] border border-slate-800 space-y-4">
            
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
              <div className="flex items-center space-x-2">
                <History className="w-4 h-4 text-amber-400" />
                <h4 className="text-sm font-mono font-bold text-white uppercase">
                  On-Chain Transaction History ({walletResult.transactions.length})
                </h4>
              </div>

              {/* Filter Tabs */}
              <div className="flex space-x-1">
                <button
                  onClick={() => setTxFilter('ALL')}
                  className={`px-3 py-1 rounded-lg text-xs font-mono font-semibold transition ${
                    txFilter === 'ALL' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  All ({walletResult.transactions.length})
                </button>
                <button
                  onClick={() => setTxFilter('IN')}
                  className={`px-3 py-1 rounded-lg text-xs font-mono font-semibold transition ${
                    txFilter === 'IN' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  Inbound (+)
                </button>
                <button
                  onClick={() => setTxFilter('OUT')}
                  className={`px-3 py-1 rounded-lg text-xs font-mono font-semibold transition ${
                    txFilter === 'OUT' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  Outbound (-)
                </button>
              </div>
            </div>

            {filteredTransactions.length === 0 ? (
              <div className="p-6 text-center text-slate-500 text-xs font-mono">
                No recent transaction history recorded on {walletResult.network}.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="text-slate-500 border-b border-slate-800/80 bg-slate-950/60">
                    <tr>
                      <th className="p-3">Type</th>
                      <th className="p-3">Amount & Token</th>
                      <th className="p-3">Counterparty Address</th>
                      <th className="p-3">Transaction Hash</th>
                      <th className="p-3">Time</th>
                      <th className="p-3 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/50 text-slate-300">
                    {filteredTransactions.map((tx, idx) => (
                      <tr key={idx} className="hover:bg-slate-900/60 transition">
                        <td className="p-3">
                          <span className={`inline-flex items-center space-x-1 px-2 py-0.5 rounded font-bold ${
                            tx.direction === 'IN' 
                              ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/25' 
                              : 'bg-rose-500/15 text-rose-400 border border-rose-500/25'
                          }`}>
                            {tx.direction === 'IN' ? <ArrowDownLeft className="w-3 h-3" /> : <ArrowUpRight className="w-3 h-3" />}
                            <span>{tx.direction === 'IN' ? 'RECEIVED' : 'SENT / SWEPT'}</span>
                          </span>
                        </td>

                        <td className="p-3 font-bold">
                          <span className={tx.direction === 'IN' ? 'text-emerald-400' : 'text-rose-400'}>
                            {tx.formattedAmount}
                          </span>
                        </td>

                        <td className="p-3">
                          <div className="flex flex-col">
                            <span className="font-bold text-slate-200 truncate max-w-[200px]" style={{ color: tx.counterpartyEntity.color }}>
                              {tx.counterpartyEntity.name}
                            </span>
                            <span className="text-[11px] text-slate-500 truncate max-w-[200px] select-all">
                              {tx.counterparty}
                            </span>
                          </div>
                        </td>

                        <td className="p-3">
                          <div className="flex items-center space-x-1.5">
                            <a
                              href={tx.explorerUrl}
                              target="_blank"
                              rel="noreferrer"
                              className="text-sky-400 hover:underline font-mono truncate max-w-[120px]"
                            >
                              {tx.hash.slice(0, 10)}...{tx.hash.slice(-6)}
                            </a>
                            <button
                              onClick={() => copyToClipboard(tx.hash, `tx-${idx}`)}
                              className="text-slate-500 hover:text-white p-0.5"
                              title="Copy TXID"
                            >
                              {copiedKey === `tx-${idx}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                            </button>
                          </div>
                        </td>

                        <td className="p-3 text-slate-400 whitespace-nowrap">
                          {new Date(tx.timeStamp).toLocaleDateString()} {new Date(tx.timeStamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                        </td>

                        <td className="p-3 text-right">
                          <button
                            onClick={() => handleTraceSingleTx(tx.hash)}
                            className="px-2.5 py-1 rounded-lg bg-amber-500/15 hover:bg-amber-500/25 text-amber-300 border border-amber-500/30 text-[11px] font-semibold transition inline-flex items-center space-x-1"
                          >
                            <span>Trace TX</span>
                            <ArrowRight className="w-3 h-3" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

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
              <p className="text-xs text-slate-400">On-chain hop sequence leading to de-anonymization</p>
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
                Transfer: <b>$146.07 USDC</b>
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
                Status: <b>Drained ($0.00) &rarr; Swept to 0xdb25...7857</b>
              </div>
            </div>

            <div className="p-5 rounded-2xl bg-[#0a0d14] border border-amber-500/50 space-y-3">
              <div className="w-10 h-10 rounded-xl bg-amber-500/15 border border-amber-500/30 flex items-center justify-center text-amber-400">
                <Building2 className="w-5 h-5" />
              </div>
              <div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">
                  RECEIVER ENDPOINT (KYC ATTACHED)
                </span>
                <h4 className="text-base font-bold text-white mt-1">Receiver Address</h4>
                <p className="text-xs text-slate-400 mt-1">0xdb2543...7857</p>
              </div>
              <div className="p-2.5 rounded-lg bg-amber-950/30 border border-amber-900/40 text-xs font-mono text-amber-300">
                De-Anonymization: <b>Actionable via Subpoena</b>
              </div>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
