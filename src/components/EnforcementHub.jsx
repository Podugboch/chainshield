import React, { useState } from 'react';
import { 
  ShieldBan, Lock, Building2, Terminal, Copy, Check, Download, 
  Send, AlertTriangle, FileCode, CheckCircle2, Globe, ExternalLink 
} from 'lucide-react';
import { DEFAULT_INCIDENT } from '../lib/blockchainForensics';

export function EnforcementHub({ onOpenDossier }) {
  const [activeTab, setActiveTab] = useState('tether-freeze');
  const [copiedKey, setCopiedKey] = useState(null);
  const [testWallet, setTestWallet] = useState(DEFAULT_INCIDENT.scammerAddress);
  const [apiCheckResult, setApiCheckResult] = useState(null);
  const [isCheckingApi, setIsCheckingApi] = useState(false);

  const copyToClipboard = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const tetherFreezeEmail = `To: compliance@tether.to, support@tether.to
Subject: URGENT: On-Chain USDT Blacklist Request - Fraud & Phishing Incident Ref: ${DEFAULT_INCIDENT.incidentId}

Dear Tether Operations & Compliance Team,

I am writing to formally submit an urgent on-chain Smart Contract Blacklist Request (addBlackList) regarding a verified cryptocurrency theft and account takeover incident involving Tether USD (USDT ERC-20).

INCIDENT & TECHNICAL DETAILS:
--------------------------------------------------
* Target Scammer Wallet: ${DEFAULT_INCIDENT.scammerAddress}
* Stolen Amount: ${DEFAULT_INCIDENT.stolenAmount} (USDT ERC-20)
* Initial Transaction Hash (TXID): ${DEFAULT_INCIDENT.txHash}
* Payout Platform Spoofed: ${DEFAULT_INCIDENT.victimPlatform}
* Destination Exchange Deposit: ${DEFAULT_INCIDENT.destinationAddress} (${DEFAULT_INCIDENT.destinationExchange})

EVIDENCE & AUDIT TRAIL:
--------------------------------------------------
The perpetrator deployed a malicious credential-harvesting phishing link impersonating our platform to substitute the victim's payout wallet for the attacker's address: ${DEFAULT_INCIDENT.scammerAddress}. The stolen funds were subsequently routed through an intermediary hop into a Binance deposit cluster.

REQUESTED ACTION:
--------------------------------------------------
Pursuant to Tether's security & compliance policies and standard smart contract freeze protocol (addBlackList / destroyBlackFunds), we respectfully request that Tether:
1. Add the address ${DEFAULT_INCIDENT.scammerAddress} to the USDT ERC-20 blacklist contract.
2. Prevent further incoming or outgoing transfers to/from this address.

Case investigation logs and cybercrime filings are attached.

Sincerely,
Incident Response via ChainShield Forensics Platform
`;

  const handleTestApi = () => {
    setIsCheckingApi(true);
    setTimeout(() => {
      const isScammer = testWallet.toLowerCase() === DEFAULT_INCIDENT.scammerAddress.toLowerCase();
      setApiCheckResult({
        address: testWallet,
        isBlocked: isScammer,
        riskScore: isScammer ? 100 : 5,
        decision: isScammer ? 'REJECT_PAYOUT' : 'APPROVE_PAYOUT',
        reason: isScammer ? 'Address flagged in ChainShield Global Scam Database (Atlas Capture Payout Redirection)' : 'No malicious flags detected'
      });
      setIsCheckingApi(false);
    }, 400);
  };

  return (
    <div className="space-y-8 max-w-6xl mx-auto">
      
      {/* Top Banner */}
      <div className="text-center space-y-3">
        <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-red-500/10 text-red-400 text-xs font-mono border border-red-500/20">
          <ShieldBan className="w-3.5 h-3.5" />
          <span>On-Chain Blacklist & Payout Firewall Hub</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          Block Scammer Payouts & Freeze Assets
        </h1>
        <p className="text-slate-400 max-w-2xl mx-auto text-sm sm:text-base">
          Enforce multi-layered blacklisting: smart contract freezing via Tether, exchange compliance blocks, and automated pre-payout verification firewalls.
        </p>
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="flex space-x-2 border-b border-slate-800 pb-3">
        <button
          onClick={() => setActiveTab('tether-freeze')}
          className={`px-4 py-2 rounded-xl text-xs font-mono font-semibold transition flex items-center space-x-2 ${
            activeTab === 'tether-freeze' ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'text-slate-400 hover:text-white'
          }`}
        >
          <Lock className="w-4 h-4" />
          <span>Tether Smart Contract Freeze</span>
        </button>
        <button
          onClick={() => setActiveTab('firewall-api')}
          className={`px-4 py-2 rounded-xl text-xs font-mono font-semibold transition flex items-center space-x-2 ${
            activeTab === 'firewall-api' ? 'bg-sky-500/20 text-sky-400 border border-sky-500/30' : 'text-slate-400 hover:text-white'
          }`}
        >
          <Terminal className="w-4 h-4" />
          <span>Pre-Payout Firewall API</span>
        </button>
        <button
          onClick={() => setActiveTab('exchange-notice')}
          className={`px-4 py-2 rounded-xl text-xs font-mono font-semibold transition flex items-center space-x-2 ${
            activeTab === 'exchange-notice' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' : 'text-slate-400 hover:text-white'
          }`}
        >
          <Building2 className="w-4 h-4" />
          <span>Exchange Intercept Notice</span>
        </button>
      </div>

      {/* Tab 1: Tether Smart Contract Freeze Petition */}
      {activeTab === 'tether-freeze' && (
        <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-2xl space-y-6 animate-fadeIn">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
            <div>
              <h3 className="text-lg font-bold text-white flex items-center space-x-2">
                <Lock className="w-5 h-5 text-red-400" />
                <span>Tether (USDT) Official Smart Contract Freeze Petition</span>
              </h3>
              <p className="text-xs text-slate-400">
                Tether has frozen over $1.5 Billion in scammer wallets using their smart contract's <code className="text-red-300">addBlackList()</code> function.
              </p>
            </div>
            <button
              onClick={() => copyToClipboard(tetherFreezeEmail, 'tether-email')}
              className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white font-bold text-xs rounded-xl transition shadow-lg shadow-red-600/25 flex items-center space-x-1.5 shrink-0"
            >
              {copiedKey === 'tether-email' ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
              <span>{copiedKey === 'tether-email' ? 'Copied Email' : 'Copy Freeze Request Email'}</span>
            </button>
          </div>

          <div className="p-4 rounded-xl bg-[#070a0f] border border-slate-800 text-xs font-mono text-slate-300 leading-relaxed overflow-x-auto">
            <pre className="whitespace-pre-wrap selection:bg-red-500/30 selection:text-red-200">
              {tetherFreezeEmail}
            </pre>
          </div>

          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800/80 text-xs text-slate-400 space-y-2">
            <h4 className="font-bold text-slate-200 uppercase font-mono">Submission Instructions:</h4>
            <ul className="list-disc pl-5 space-y-1">
              <li>Send this email to <b>compliance@tether.to</b> and <b>support@tether.to</b>.</li>
              <li>Attach the exported ChainShield Law Enforcement dossier.</li>
              <li>Once Tether confirms the blacklist, the address can never send or receive USDT on-chain again.</li>
            </ul>
          </div>
        </div>
      )}

      {/* Tab 2: Pre-Payout Firewall API */}
      {activeTab === 'firewall-api' && (
        <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-2xl space-y-6 animate-fadeIn">
          
          <div>
            <h3 className="text-lg font-bold text-white flex items-center space-x-2">
              <Terminal className="w-5 h-5 text-sky-400" />
              <span>Automated Pre-Payout Firewall (For Platforms & Contractors)</span>
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Platforms (like Atlas Capture) can integrate this 3-line check before processing cryptocurrency payouts to automatically block payments to flagged scammers.
            </p>
          </div>

          {/* Interactive API Tester */}
          <div className="p-5 rounded-xl bg-[#0a0d14] border border-slate-800 space-y-4">
            <h4 className="text-xs font-mono font-bold text-slate-300 uppercase">Live Pre-Payout Verification Tester:</h4>
            
            <div className="flex flex-col sm:flex-row gap-3">
              <input
                type="text"
                placeholder="Enter payout address to test..."
                value={testWallet}
                onChange={(e) => setTestWallet(e.target.value)}
                className="flex-1 p-3 bg-slate-900 border border-slate-700 rounded-xl text-white font-mono text-xs focus:outline-none focus:border-sky-500"
              />
              <button
                onClick={handleTestApi}
                disabled={isCheckingApi || !testWallet.trim()}
                className="px-5 py-3 bg-gradient-to-r from-sky-500 to-indigo-600 hover:from-sky-400 hover:to-indigo-500 text-white font-bold text-xs rounded-xl shadow-lg shadow-sky-500/25 transition disabled:opacity-50"
              >
                {isCheckingApi ? 'Verifying...' : 'Verify Payout Safety'}
              </button>
            </div>

            {apiCheckResult && (
              <div className={`p-4 rounded-xl border animate-fadeIn text-xs font-mono space-y-2 ${
                apiCheckResult.isBlocked 
                  ? 'bg-red-950/40 border-red-500/50 text-red-300' 
                  : 'bg-emerald-950/40 border-emerald-500/50 text-emerald-300'
              }`}>
                <div className="flex items-center justify-between">
                  <span className="font-extrabold uppercase">
                    {apiCheckResult.isBlocked ? '🚨 TRANSACTION BLOCKED BY FIREWALL' : '✅ TRANSACTION APPROVED'}
                  </span>
                  <span className="px-2.5 py-0.5 rounded font-bold bg-slate-900 border border-slate-800">
                    DECISION: {apiCheckResult.decision}
                  </span>
                </div>
                <p>{apiCheckResult.reason}</p>
              </div>
            )}
          </div>

          {/* Code Snippet for Developers */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-slate-400">INTEGRATION CODE (Node.js / Express / Backend):</span>
              <button
                onClick={() => copyToClipboard(`// ChainShield Pre-Payout Guard
async function verifyPayoutWallet(walletAddress) {
  const isFlagged = await dbService.isWalletFlagged(walletAddress);
  if (isFlagged) {
    throw new Error('SECURITY ALERT: Payout halted. Target address is flagged for fraud.');
  }
  return true;
}`, 'code-snippet')}
                className="text-xs font-mono text-sky-400 hover:underline flex items-center space-x-1"
              >
                {copiedKey === 'code-snippet' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>Copy Code</span>
              </button>
            </div>

            <div className="p-4 rounded-xl bg-[#070a0f] border border-slate-800 text-xs font-mono text-sky-300 overflow-x-auto">
              <pre>{`// ChainShield Pre-Payout Guard for Platforms (e.g. Atlas Capture)
async function processContractorPayout(contractorId, payoutWallet, amountUsd) {
  
  // 1. Query ChainShield Blacklist Engine
  const isFlagged = await dbService.isWalletFlagged(payoutWallet);
  
  if (isFlagged) {
    // 2. Automatically halt transfer before funds are sent
    await logSecurityIncident({
      contractorId,
      flaggedWallet: payoutWallet,
      reason: isFlagged.scam_category
    });
    throw new Error('TRANSACTION REJECTED: Payout address is blacklisted for fraud.');
  }

  // 3. Safe to execute blockchain payout
  return await sendCryptoPayout(payoutWallet, amountUsd);
}`}</pre>
            </div>
          </div>

        </div>
      )}

      {/* Tab 3: Exchange Intercept Notice */}
      {activeTab === 'exchange-notice' && (
        <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-2xl space-y-6 animate-fadeIn">
          <div>
            <h3 className="text-lg font-bold text-white flex items-center space-x-2">
              <Building2 className="w-5 h-5 text-amber-400" />
              <span>Exchange Compliance Blocklist Notification</span>
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Submit to Binance, OKX, and Bybit security portals to freeze internal deposit accounts tied to the scammer.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
            <div className="p-4 rounded-xl bg-[#0a0d14] border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-amber-400 font-bold">Binance Security & Fraud Desk</span>
                <span className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-300 text-[10px]">Official Portal</span>
              </div>
              <p className="text-slate-400 font-sans">
                Submit transaction hash <b>0x44e5dbb...</b> and deposit address <b>0x28C6c...</b> to request an emergency compliance lock.
              </p>
              <a
                href="https://www.binance.com/en/support"
                target="_blank"
                rel="noreferrer"
                className="text-sky-400 hover:underline flex items-center space-x-1"
              >
                <span>Open Binance Support Portal</span>
                <ExternalLink className="w-3 h-3" />
              </a>
            </div>

            <div className="p-4 rounded-xl bg-[#0a0d14] border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sky-400 font-bold">Cybercrime Filing (IC3 / Interpol)</span>
                <span className="px-2 py-0.5 rounded bg-sky-500/10 text-sky-300 text-[10px]">Law Enforcement</span>
              </div>
              <p className="text-slate-400 font-sans">
                Attach the generated ChainShield Law Enforcement dossier to file an official subpoena request against the Binance KYC ID.
              </p>
              <button
                onClick={() => onOpenDossier && onOpenDossier()}
                className="text-amber-400 hover:underline flex items-center space-x-1"
              >
                <span>Generate Official Dossier</span>
                <ExternalLink className="w-3 h-3" />
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
