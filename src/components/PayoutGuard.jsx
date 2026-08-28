import React, { useState } from 'react';
import { 
  ShieldCheck, ShieldAlert, Ban, CheckCircle2, AlertTriangle, 
  ArrowRight, Lock, Code2, Copy, Check, Sparkles, Building2
} from 'lucide-react';
import { dbService } from '../lib/supabase';

export function PayoutGuard() {
  const [testAddress, setTestAddress] = useState('0xd23Ac29C1e1949D0c5864B4a23a01cc3e4dd236b');
  const [testAmount, setTestAmount] = useState('146.07');
  const [platformName, setPlatformName] = useState('Atlas Capture');
  const [isVerifying, setIsVerifying] = useState(false);
  const [guardResult, setGuardResult] = useState(null);
  const [copiedSnippet, setCopiedSnippet] = useState(false);

  const sampleAddresses = [
    { label: 'Atlas Scammer (Blacklisted)', address: '0xd23Ac29C1e1949D0c5864B4a23a01cc3e4dd236b' },
    { label: 'Clean Test Wallet', address: '0x71C8F79D3A5d8D3D8Db4D849a6262B54fC6E0123' }
  ];

  const handleVerify = async (addrToTest) => {
    const target = (addrToTest || testAddress).trim();
    if (!target) return;

    setIsVerifying(true);
    setGuardResult(null);

    setTimeout(async () => {
      const res = await dbService.verifyPayoutAddress(target, platformName);
      setGuardResult(res);
      setIsVerifying(false);
    }, 400);
  };

  const integrationCodeSnippet = `// 🛡️ ChainShield Pre-Payout Firewall Integration
// Add to Atlas Capture / Payment Backend before executing withdrawals

async function processContractorPayout(userId, amountUsd, destinationWallet) {
  // 1. Query ChainShield Blacklist Engine
  const response = await fetch("https://uilqrxntdwyvqqjjmqbi.supabase.co/rest/v1/scam_wallets?wallet_address=eq." + destinationWallet, {
    headers: { "apikey": SUPABASE_ANON_KEY }
  });
  const flagged = await response.json();

  // 2. BLOCK PAYMENT IF FLAGGED
  if (flagged.length > 0) {
    throw new Error("🚨 SECURITY ALERT: Payout blocked! Destination wallet is flagged as a malicious scammer.");
  }

  // 3. Proceed with legitimate payment
  return executeCryptoTransfer(destinationWallet, amountUsd);
}`;

  const handleCopyCode = () => {
    navigator.clipboard.writeText(integrationCodeSnippet);
    setCopiedSnippet(true);
    setTimeout(() => setCopiedSnippet(false), 2000);
  };

  return (
    <div className="space-y-8 max-w-6xl mx-auto">
      
      {/* Top Banner */}
      <div className="text-center space-y-3">
        <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-emerald-500/10 text-emerald-400 text-xs font-mono border border-emerald-500/20">
          <Ban className="w-3.5 h-3.5" />
          <span>Automated Payout Interception & Blacklist Enforcement</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          Pre-Payout Security Firewall
        </h1>
        <p className="text-slate-400 max-w-2xl mx-auto text-sm sm:text-base">
          Ensures that flagged scammer addresses are <b>strictly blocked from receiving payments</b> across platforms (like <i>Atlas Capture</i>, payroll gateways, and Web3 payment processors).
        </p>
      </div>

      {/* 3 Enforcement Layers Explanation */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-5 rounded-2xl bg-[#0a0d14] border border-slate-800 space-y-2">
          <div className="w-8 h-8 rounded-lg bg-red-500/20 text-red-400 flex items-center justify-center font-bold text-xs font-mono">
            1
          </div>
          <h4 className="text-sm font-bold text-white">Platform Payout Firewall</h4>
          <p className="text-xs text-slate-400">
            Platforms verify destination wallets against ChainShield before dispatching funds, blocking altered scammer addresses automatically.
          </p>
        </div>

        <div className="p-5 rounded-2xl bg-[#0a0d14] border border-slate-800 space-y-2">
          <div className="w-8 h-8 rounded-lg bg-amber-500/20 text-amber-400 flex items-center justify-center font-bold text-xs font-mono">
            2
          </div>
          <h4 className="text-sm font-bold text-white">Tether & Smart Contract Blacklist</h4>
          <p className="text-xs text-slate-400">
            Tether (USDT) and Circle (USDC) smart contracts contain built-in freeze mechanisms to permanently lock on-chain movement.
          </p>
        </div>

        <div className="p-5 rounded-2xl bg-[#0a0d14] border border-slate-800 space-y-2">
          <div className="w-8 h-8 rounded-lg bg-sky-500/20 text-sky-400 flex items-center justify-center font-bold text-xs font-mono">
            3
          </div>
          <h4 className="text-sm font-bold text-white">Exchange Deposit Inbound Freeze</h4>
          <p className="text-xs text-slate-400">
            Reporting the address to Binance/CEX compliance ensures incoming deposits from the scammer cluster are seized upon receipt.
          </p>
        </div>
      </div>

      {/* Live Payment Interception Simulator */}
      <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-2xl space-y-6">
        
        <div className="pb-4 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h3 className="text-lg font-bold text-white flex items-center space-x-2">
              <Lock className="w-5 h-5 text-emerald-400" />
              <span>Live Payout Interception Simulator</span>
            </h3>
            <p className="text-xs text-slate-400">Simulate how Atlas Capture or payment processors prevent scammer payouts</p>
          </div>
        </div>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleVerify();
          }}
          className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs font-mono"
        >
          <div className="space-y-1 md:col-span-1">
            <label className="text-slate-400">SOURCE PLATFORM:</label>
            <input
              type="text"
              value={platformName}
              onChange={(e) => setPlatformName(e.target.value)}
              className="w-full p-2.5 bg-[#0a0d14] border border-slate-700 rounded-xl text-white focus:outline-none focus:border-emerald-500"
            />
          </div>

          <div className="space-y-1 md:col-span-2">
            <label className="text-slate-400">PAYOUT DESTINATION WALLET (0x):</label>
            <input
              type="text"
              value={testAddress}
              onChange={(e) => setTestAddress(e.target.value)}
              className="w-full p-2.5 bg-[#0a0d14] border border-slate-700 rounded-xl text-white focus:outline-none focus:border-emerald-500 select-all"
            />
          </div>

          <div className="space-y-1 md:col-span-1 flex flex-col justify-end">
            <button
              type="submit"
              disabled={isVerifying || !testAddress.trim()}
              className="w-full py-2.5 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-bold rounded-xl shadow-lg shadow-emerald-600/25 transition disabled:opacity-50 flex items-center justify-center space-x-1.5"
            >
              {isVerifying ? (
                <>
                  <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  <span>Checking...</span>
                </>
              ) : (
                <>
                  <ShieldCheck className="w-4 h-4" />
                  <span>Test Payout Firewall</span>
                </>
              )}
            </button>
          </div>
        </form>

        {/* Quick test buttons */}
        <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-slate-800/60">
          <span className="text-xs text-slate-500">Test sample addresses:</span>
          {sampleAddresses.map((sample, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => {
                setTestAddress(sample.address);
                handleVerify(sample.address);
              }}
              className="text-xs font-mono px-2.5 py-1 rounded-md bg-slate-800 text-slate-300 hover:bg-slate-700 hover:text-white transition"
            >
              {sample.label}
            </button>
          ))}
        </div>

        {/* Firewall Output Result */}
        {guardResult && (
          <div className="space-y-4 animate-fadeIn">
            {guardResult.status === 'BLOCKED' ? (
              <div className="p-6 rounded-2xl bg-gradient-to-r from-red-950/90 to-rose-950/70 border-2 border-red-500 shadow-2xl space-y-4">
                <div className="flex items-start space-x-3">
                  <Ban className="w-8 h-8 text-red-400 shrink-0 mt-0.5 animate-pulse" />
                  <div>
                    <span className="px-2.5 py-0.5 rounded-full bg-red-500/20 text-red-300 text-[10px] font-mono font-bold border border-red-500/40 uppercase">
                      PAYMENT REJECTED & INTERCEPTED
                    </span>
                    <h3 className="text-lg font-extrabold text-white mt-1">
                      🛑 Payout of ${testAmount} USDT Blocked Successfully
                    </h3>
                    <p className="text-xs text-red-200/90 mt-1">
                      {guardResult.reason}
                    </p>
                  </div>
                </div>

                <div className="p-3.5 rounded-xl bg-black/40 border border-red-900/50 text-xs font-mono space-y-1.5 text-red-200">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">Enforcement Action:</span>
                    <span className="font-bold text-red-400">TRANSFER_ABORTED</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">Target Address:</span>
                    <span className="truncate max-w-xs">{testAddress}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">Security Recommendation:</span>
                    <span className="text-amber-300">Prompt contractor to verify identity via 2FA before updating address</span>
                  </div>
                </div>
              </div>
            ) : (
              <div className="p-6 rounded-2xl bg-gradient-to-r from-emerald-950/80 to-teal-950/60 border-2 border-emerald-500/60 shadow-xl space-y-3">
                <div className="flex items-start space-x-3">
                  <CheckCircle2 className="w-8 h-8 text-emerald-400 shrink-0 mt-0.5" />
                  <div>
                    <span className="px-2.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 text-[10px] font-mono font-bold border border-emerald-500/40 uppercase">
                      PAYMENT APPROVED
                    </span>
                    <h3 className="text-lg font-extrabold text-white mt-1">
                      ✅ Address Verified Clean — Payout Permitted
                    </h3>
                    <p className="text-xs text-emerald-200/90 mt-1">
                      {guardResult.reason}
                    </p>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

      </div>

      {/* 1-Line Code Integration for Platforms */}
      <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Code2 className="w-5 h-5 text-sky-400" />
            <h3 className="text-base font-bold text-white">Embed Payout Firewall into Any Platform</h3>
          </div>
          <button
            onClick={handleCopyCode}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono flex items-center space-x-1.5 transition"
          >
            {copiedSnippet ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedSnippet ? 'Copied' : 'Copy Backend Code'}</span>
          </button>
        </div>

        <p className="text-xs text-slate-400">
          Paste this snippet into platform payout / withdrawal scripts (Node.js / Python / Go) to automatically block flagged addresses before payments are signed.
        </p>

        <div className="p-4 rounded-xl bg-[#06090e] border border-slate-800 text-xs font-mono text-slate-300 overflow-x-auto">
          <pre className="whitespace-pre">{integrationCodeSnippet}</pre>
        </div>
      </div>

    </div>
  );
}
