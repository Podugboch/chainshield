import React, { useState } from 'react';
import {
  ShieldCheck, ShieldAlert, Ban, CheckCircle2, AlertTriangle,
  Lock, Code2, Copy, Check
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
    // Correct EIP-55 form. This was previously written with an invalid checksum,
    // so the address labelled "clean" was one no wallet would have accepted.
    { label: 'Unreported Wallet', address: '0x71c8F79D3a5d8d3d8dB4D849A6262b54fC6e0123' },
    // Same address with two characters transposed -- shows the check refusing to
    // answer rather than approving a destination it cannot verify.
    { label: 'Mistyped Address', address: '0x71c8F79D3a5d8d3d8dB4D849A6262b54fC6e0132' },
  ];

  const handleVerify = async (addrToTest) => {
    const target = (addrToTest || testAddress).trim();
    if (!target) return;

    setIsVerifying(true);
    setGuardResult(null);
    try {
      const res = await dbService.verifyPayoutAddress(target, platformName);
      setGuardResult(res);
    } catch (e) {
      // A thrown lookup is not a clean address. Say so instead of falling
      // through to the approved branch.
      setGuardResult({
        status: 'ERROR',
        decision: 'CHECK_FAILED',
        reason: `The blocklist could not be reached: ${e.message}. Treat this as unknown, not safe.`,
      });
    } finally {
      setIsVerifying(false);
    }
  };

  const integrationCodeSnippet = `// ChainShield pre-payout screen.
// Point SUPABASE_URL at your own project -- this table is yours, not a
// hosted service, and the row you rely on has to be in the database you query.

async function processContractorPayout(userId, amountUsd, destinationWallet) {
  // ilike, not eq: addresses are stored lowercase and Postgres string
  // comparison is case-sensitive, so eq. against a checksummed address
  // silently matches nothing and every payout looks clean.
  const url = SUPABASE_URL + "/rest/v1/scam_wallets"
    + "?select=wallet_address,verified,scam_category"
    + "&wallet_address=ilike." + encodeURIComponent(destinationWallet.toLowerCase());

  let flagged;
  try {
    const response = await fetch(url, {
      headers: { apikey: SUPABASE_ANON_KEY, Authorization: "Bearer " + SUPABASE_ANON_KEY },
    });
    if (!response.ok) throw new Error("blocklist HTTP " + response.status);
    flagged = await response.json();
    if (!Array.isArray(flagged)) throw new Error("unexpected blocklist response");
  } catch (err) {
    // Fail closed. The original version read .length off whatever came back,
    // so an outage or an error object made the check pass and the payout went
    // out unscreened -- exactly when you least want that.
    return holdForManualReview({ userId, destinationWallet, reason: err.message });
  }

  const verifiedHit = flagged.find((row) => row.verified === true);
  if (verifiedHit) {
    throw new Error("Payout blocked: destination is a verified fraud address ("
      + verifiedHit.scam_category + ").");
  }

  // An unverified community report is not proof. Do not auto-reject it, and do
  // not ignore it either.
  if (flagged.length > 0) {
    return holdForManualReview({ userId, destinationWallet, reason: "unverified report" });
  }

  // No match is not a clean bill of health. Keep your address-change cooldown
  // and 2FA-on-payout-edit controls regardless of what this returns.
  return executeCryptoTransfer(destinationWallet, amountUsd);
}`;

  // One row per status returned by verifyPayoutAddress, plus ERROR for a thrown
  // lookup. Nothing falls through to the approved styling by default.
  const OUTCOMES = {
    BLOCKED: {
      container: 'bg-gradient-to-r from-red-950/90 to-rose-950/70 border-red-500',
      badge: 'bg-red-500/20 text-red-300 border-red-500/40',
      icon: 'text-red-400 animate-pulse',
      body: 'text-red-200/90',
      Icon: Ban,
      heading: '🛑 Payout blocked — destination is a verified fraud address',
      nextStep: 'Do not release. Require 2FA re-verification before any payout address change is accepted.',
    },
    REVIEW: {
      container: 'bg-gradient-to-r from-amber-950/80 to-yellow-950/60 border-amber-500/70',
      badge: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
      icon: 'text-amber-400',
      body: 'text-amber-200/90',
      Icon: ShieldAlert,
      heading: '⚠️ Held for review — unverified community report',
      nextStep: 'Hold and confirm the address with the contractor over a channel you initiated.',
    },
    INVALID: {
      container: 'bg-gradient-to-r from-orange-950/80 to-amber-950/60 border-orange-500/70',
      badge: 'bg-orange-500/20 text-orange-300 border-orange-500/40',
      icon: 'text-orange-400',
      body: 'text-orange-200/90',
      Icon: AlertTriangle,
      heading: '⛔ Not a valid address — no check was performed',
      nextStep: 'Re-copy the destination from its source. A payout to a malformed address is unrecoverable.',
    },
    ERROR: {
      container: 'bg-slate-900 border-slate-600',
      badge: 'bg-slate-800 text-slate-300 border-slate-700',
      icon: 'text-slate-400',
      body: 'text-slate-300',
      Icon: AlertTriangle,
      heading: '⚠️ Check failed — result unknown',
      nextStep: 'Retry, or hold the payout. An unreachable blocklist is not a clean result.',
    },
    APPROVED: {
      container: 'bg-gradient-to-r from-emerald-950/80 to-teal-950/60 border-emerald-500/60',
      badge: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
      icon: 'text-emerald-400',
      body: 'text-emerald-200/90',
      Icon: CheckCircle2,
      heading: '✅ No blocklist match — payout not stopped',
      nextStep: 'Proceed under your normal controls. This screen found nothing; it did not clear the address.',
    },
  };
  const outcome = OUTCOMES[guardResult?.status] || OUTCOMES.ERROR;

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
          A destination-address screen for payout platforms, payroll gateways and Web3
          payment processors to run <b>before</b> funds are signed away. It reports what is
          on the blocklist; the platform integrating it decides whether to send.
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
            A platform that integrates this check can screen the destination wallet
            before dispatching funds, and decline when a reported address appears.
            ChainShield cannot stop a transfer itself — the platform does.
          </p>
        </div>

        <div className="p-5 rounded-2xl bg-[#0a0d14] border border-slate-800 space-y-2">
          <div className="w-8 h-8 rounded-lg bg-amber-500/20 text-amber-400 flex items-center justify-center font-bold text-xs font-mono">
            2
          </div>
          <h4 className="text-sm font-bold text-white">Issuer Contract Blacklist</h4>
          <p className="text-xs text-slate-400">
            USDT and USDC contracts carry a blacklist function, but only the issuer
            can call it — Tether for USDT, Circle for USDC — and only at their
            discretion. It does not apply to ETH or most other tokens.
          </p>
        </div>

        <div className="p-5 rounded-2xl bg-[#0a0d14] border border-slate-800 space-y-2">
          <div className="w-8 h-8 rounded-lg bg-sky-500/20 text-sky-400 flex items-center justify-center font-bold text-xs font-mono">
            3
          </div>
          <h4 className="text-sm font-bold text-white">Exchange Deposit Report</h4>
          <p className="text-xs text-slate-400">
            Reporting the address to an exchange's compliance desk puts it on record
            before the funds arrive. Whether they freeze the deposit is their call,
            and usually follows a law-enforcement referral rather than your report alone.
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
            <p className="text-xs text-slate-400">
              Runs the real blocklist query a payout backend would run. The platform
              name and amount are only used to label the result.
            </p>
          </div>
        </div>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleVerify();
          }}
          className="grid grid-cols-1 md:grid-cols-5 gap-3 text-xs font-mono"
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

          <div className="space-y-1 md:col-span-1">
            {/* This value was previously fixed in state with no way to change it,
                yet the blocked banner quoted it back as if it had been entered. */}
            <label className="text-slate-400">AMOUNT (USD):</label>
            <input
              type="text"
              inputMode="decimal"
              value={testAmount}
              onChange={(e) => setTestAmount(e.target.value)}
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

        {/* Firewall output. Four outcomes, deliberately: only a verified report
            blocks, an unverified one holds, a malformed address is refused
            without any lookup, and a failed lookup is not an approval. This used
            to be a single BLOCKED/else branch, so REVIEW, INVALID and ERROR all
            rendered as "Address Verified Clean - Payout Permitted". */}
        {guardResult && (
          <div className="space-y-4 animate-fadeIn">
            <div className={`p-6 rounded-2xl border-2 shadow-2xl space-y-4 ${
              outcome.container
            }`}>
              <div className="flex items-start space-x-3">
                <outcome.Icon className={`w-8 h-8 shrink-0 mt-0.5 ${outcome.icon}`} />
                <div>
                  <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold border uppercase ${outcome.badge}`}>
                    {guardResult.decision || guardResult.status}
                  </span>
                  <h3 className="text-lg font-extrabold text-white mt-1">
                    {outcome.heading}
                  </h3>
                  <p className={`text-xs mt-1 ${outcome.body}`}>
                    {guardResult.reason}
                  </p>
                  {guardResult.checksumSuggestion && (
                    <p className="text-xs font-mono text-amber-300 mt-1 break-all">
                      Nearest valid checksum: {guardResult.checksumSuggestion} — re-copy the
                      address from its source rather than assuming this is the one you meant.
                    </p>
                  )}
                </div>
              </div>

              <div className="p-3.5 rounded-xl bg-black/40 border border-slate-800 text-xs font-mono space-y-1.5 text-slate-300">
                <div className="flex items-center justify-between gap-3">
                  <span className="text-slate-400">Amount withheld:</span>
                  <span className="font-bold">
                    {guardResult.isAllowed === false
                      ? `$${testAmount || '0.00'} (USD equivalent, as entered)`
                      : 'none — payout not stopped'}
                  </span>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <span className="text-slate-400">Target address:</span>
                  <span className="truncate max-w-xs">{guardResult.address || testAddress}</span>
                </div>
                {guardResult.flaggedRecord && (
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-slate-400">Report status:</span>
                    <span className={guardResult.verified ? 'text-red-300' : 'text-amber-300'}>
                      {guardResult.verified ? 'verified by a reviewer' : 'unverified community submission'}
                      {guardResult.flaggedRecord.created_at
                        ? ` · filed ${new Date(guardResult.flaggedRecord.created_at).toLocaleDateString()}`
                        : ''}
                    </span>
                  </div>
                )}
                <div className="flex items-start justify-between gap-3">
                  <span className="text-slate-400 shrink-0">Next step:</span>
                  <span className="text-amber-300 text-right">{outcome.nextStep}</span>
                </div>
              </div>
            </div>
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
          Drop this into a payout or withdrawal path to screen the destination before
          the transfer is signed. It fails closed: if the blocklist cannot be reached,
          the payout is held rather than allowed through unscreened.
        </p>

        <div className="p-4 rounded-xl bg-[#06090e] border border-slate-800 text-xs font-mono text-slate-300 overflow-x-auto">
          <pre className="whitespace-pre">{integrationCodeSnippet}</pre>
        </div>
      </div>

    </div>
  );
}
