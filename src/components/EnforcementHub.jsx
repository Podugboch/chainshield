import React, { useState } from 'react';
import {
  ShieldBan, Lock, Building2, Terminal, Copy, Check,
  AlertTriangle, ExternalLink
} from 'lucide-react';
import { DEFAULT_INCIDENT, issuerForToken } from '../lib/blockchainForensics';
import { dbService } from '../lib/supabase';

export function EnforcementHub({ onOpenDossier, incident = DEFAULT_INCIDENT }) {
  const [activeTab, setActiveTab] = useState('issuer-freeze');
  const [copiedKey, setCopiedKey] = useState(null);
  const [testWallet, setTestWallet] = useState(incident.scammerAddress);
  const [apiCheckResult, setApiCheckResult] = useState(null);
  const [isCheckingApi, setIsCheckingApi] = useState(false);

  const copyToClipboard = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Only the token's own issuer can freeze it. Deriving this from the incident's
  // token contract replaces a letter that was addressed to Tether no matter
  // which asset was stolen.
  const issuer = issuerForToken(incident.tokenContract);
  const assetLabel = incident.token || 'the stolen asset';

  const freezeLetter = issuer?.canFreeze ? `To: ${issuer.contact || `[confirm current compliance address at ${issuer.portal}]`}
Subject: URGENT: On-Chain ${issuer.token} Blacklist Request - Fraud & Phishing Incident Ref: ${incident.incidentId}

Dear ${issuer.issuer} Operations & Compliance Team,

I am submitting an on-chain blacklist request regarding a cryptocurrency theft
involving ${assetLabel}, issued by ${issuer.issuer}.

INCIDENT & TECHNICAL DETAILS:
--------------------------------------------------
* Target Wallet: ${incident.scammerAddress}
* Amount: ${incident.stolenAmount}
* Token Contract: ${incident.tokenContract}
* Transaction Hash (TXID): ${incident.txHash}
* Platform Impersonated: ${incident.victimPlatform}
${incident.destinationAddress ? `* Onward Destination Observed: ${incident.destinationAddress} (${incident.destinationExchange})` : ''}

EVIDENCE & AUDIT TRAIL:
--------------------------------------------------
A credential-harvesting phishing page impersonating the payout platform was used
to substitute the payout wallet with ${incident.scammerAddress}. The transaction
above records the transfer of ${incident.stolenAmount} to that address. Onward
movement of the funds is documented in the attached dossier; where the dossier
marks a hop as inferred rather than confirmed, it says so.

REQUESTED ACTION:
--------------------------------------------------
1. Add ${incident.scammerAddress} to the ${issuer.token} blacklist${issuer.freezeFunction ? ` (${issuer.freezeFunction})` : ''}.
2. Prevent further transfers to or from this address in the ${issuer.token} contract.

I can provide the full case file, phishing URL evidence and timeline on request.

Sincerely,
[Your name and contact details]
Prepared with the ChainShield forensics tool
` : `No issuer freeze request can be generated for this incident.

${incident.tokenContract
    ? `The token at ${incident.tokenContract} is not a centrally-issued asset with a known freeze mechanism, or it is not in ChainShield's issuer registry.`
    : 'The incident does not record which token contract the funds moved on, so the issuer cannot be identified.'}

A freeze is only possible where a single issuer controls the contract -- USDT
(Tether) and USDC (Circle) are the common cases. For anything else, including
ETH and most DeFi tokens, no party can reverse or block a transfer, and the
realistic routes are the exchange notice and law-enforcement filing in the other
tabs.`;

  const handleTestApi = async () => {
    setIsCheckingApi(true);
    setApiCheckResult(null);
    try {
      // The real blocklist check, the same call a platform would integrate.
      // This used to be a setTimeout that compared the input against one
      // hardcoded address and reported a fixed "risk score" of 100 or 5.
      const verdict = await dbService.verifyPayoutAddress(testWallet.trim());
      setApiCheckResult(verdict);
    } catch (e) {
      setApiCheckResult({
        status: 'ERROR',
        decision: 'CHECK_FAILED',
        reason: `The blocklist could not be reached: ${e.message}. Treat this as "unknown", not "safe".`,
      });
    } finally {
      setIsCheckingApi(false);
    }
  };

  const verdictStyle = {
    BLOCKED: 'bg-red-950/40 border-red-500/50 text-red-300',
    REVIEW: 'bg-amber-950/40 border-amber-500/50 text-amber-300',
    APPROVED: 'bg-emerald-950/40 border-emerald-500/50 text-emerald-300',
    ERROR: 'bg-slate-900 border-slate-600 text-slate-300',
  };
  const verdictHeading = {
    BLOCKED: '🚨 PAYOUT BLOCKED - ADDRESS IS ON THE BLOCKLIST',
    REVIEW: '⚠️ HOLD FOR REVIEW - UNVERIFIED COMMUNITY REPORT',
    APPROVED: '✅ NO BLOCKLIST MATCH',
    ERROR: '⚠️ CHECK FAILED',
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
          Request Asset Freezes & Screen Payouts
        </h1>
        <p className="text-slate-400 max-w-2xl mx-auto text-sm sm:text-base">
          Three routes, in order of how often they work: a freeze request to the token's
          issuer, a compliance notice to the receiving exchange, and a pre-payout blocklist
          check so the next payment is not lost the same way.
        </p>
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="flex flex-wrap gap-2 border-b border-slate-800 pb-3">
        <button
          onClick={() => setActiveTab('issuer-freeze')}
          className={`px-4 py-2 rounded-xl text-xs font-mono font-semibold transition flex items-center space-x-2 ${
            activeTab === 'issuer-freeze' ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'text-slate-400 hover:text-white'
          }`}
        >
          <Lock className="w-4 h-4" />
          <span>{issuer?.canFreeze ? `${issuer.issuer} (${issuer.token}) Freeze` : 'Issuer Freeze'}</span>
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

      {/* Tab 1: Issuer freeze petition */}
      {activeTab === 'issuer-freeze' && (
        <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-2xl space-y-6 animate-fadeIn">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
            <div>
              <h3 className="text-lg font-bold text-white flex items-center space-x-2">
                <Lock className="w-5 h-5 text-red-400" />
                <span>
                  {issuer?.canFreeze
                    ? `${issuer.issuer} (${issuer.token}) Smart Contract Freeze Request`
                    : 'Issuer Freeze Request'}
                </span>
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                {issuer?.canFreeze
                  ? `${issuer.issuer} controls the ${issuer.token} contract and is the only party who can freeze these funds. A request sent to any other issuer has no effect.`
                  : 'No issuer with a freeze mechanism was identified for this incident.'}
              </p>
            </div>
            <button
              onClick={() => copyToClipboard(freezeLetter, 'freeze-letter')}
              className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white font-bold text-xs rounded-xl transition shadow-lg shadow-red-600/25 flex items-center space-x-1.5 shrink-0"
            >
              {copiedKey === 'freeze-letter' ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
              <span>{copiedKey === 'freeze-letter' ? 'Copied' : 'Copy Text'}</span>
            </button>
          </div>

          <div className="p-4 rounded-xl bg-[#070a0f] border border-slate-800 text-xs font-mono text-slate-300 leading-relaxed overflow-x-auto">
            <pre className="whitespace-pre-wrap selection:bg-red-500/30 selection:text-red-200">
              {freezeLetter}
            </pre>
          </div>

          <div className="p-4 rounded-xl bg-amber-950/20 border border-amber-500/30 text-xs text-amber-200/90 space-y-2">
            <h4 className="font-bold uppercase font-mono flex items-center space-x-1.5">
              <AlertTriangle className="w-3.5 h-3.5" />
              <span>Before you send this</span>
            </h4>
            <ul className="list-disc pl-5 space-y-1">
              <li>
                Confirm the current compliance channel on{' '}
                {issuer ? (
                  <a href={issuer.portal} target="_blank" rel="noreferrer" className="text-sky-400 hover:underline">
                    {issuer.portal}
                  </a>
                ) : "the issuer's own site"}
                . Addresses in this tool can go stale.
              </li>
              <li>Fill in your real name and contact details. An anonymous request is not actioned.</li>
              <li>Attach the exported dossier and the phishing URL evidence.</li>
              <li>
                A freeze is discretionary. Issuers generally act on law-enforcement
                referrals, so file the police / IC3 report as well rather than instead.
              </li>
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
              <span>Pre-Payout Blocklist Check (For Platforms & Contractors)</span>
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              A payout platform can screen the destination address against the ChainShield
              blocklist before releasing funds. A clean result means no report matched --
              it is not a statement that the address is safe.
            </p>
          </div>

          {/* Interactive checker -- runs the real query */}
          <div className="p-5 rounded-xl bg-[#0a0d14] border border-slate-800 space-y-4">
            <h4 className="text-xs font-mono font-bold text-slate-300 uppercase">Blocklist lookup:</h4>

            <div className="flex flex-col sm:flex-row gap-3">
              <input
                type="text"
                placeholder="Enter payout address to check..."
                value={testWallet}
                onChange={(e) => setTestWallet(e.target.value)}
                className="flex-1 p-3 bg-slate-900 border border-slate-700 rounded-xl text-white font-mono text-xs focus:outline-none focus:border-sky-500"
              />
              <button
                onClick={handleTestApi}
                disabled={isCheckingApi || !testWallet.trim()}
                className="px-5 py-3 bg-gradient-to-r from-sky-500 to-indigo-600 hover:from-sky-400 hover:to-indigo-500 text-white font-bold text-xs rounded-xl shadow-lg shadow-sky-500/25 transition disabled:opacity-50"
              >
                {isCheckingApi ? 'Checking...' : 'Check Address'}
              </button>
            </div>

            {apiCheckResult && (
              <div className={`p-4 rounded-xl border animate-fadeIn text-xs font-mono space-y-2 ${
                verdictStyle[apiCheckResult.status] || verdictStyle.ERROR
              }`}>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-extrabold uppercase">
                    {verdictHeading[apiCheckResult.status] || apiCheckResult.status}
                  </span>
                  <span className="px-2.5 py-0.5 rounded font-bold bg-slate-900 border border-slate-800">
                    {apiCheckResult.decision}
                  </span>
                </div>
                <p className="font-sans leading-relaxed">{apiCheckResult.reason}</p>
                {apiCheckResult.flaggedRecord && (
                  <p className="text-[11px] opacity-80">
                    Report filed {new Date(apiCheckResult.flaggedRecord.created_at).toLocaleDateString()}
                    {' · '}
                    {apiCheckResult.verified ? 'verified' : 'unverified'}
                    {apiCheckResult.flaggedRecord.impersonated_brand
                      ? ` · impersonating ${apiCheckResult.flaggedRecord.impersonated_brand}`
                      : ''}
                  </p>
                )}
              </div>
            )}
          </div>

          {/* Code Snippet for Developers */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-slate-400">INTEGRATION CODE (Node.js / backend):</span>
              <button
                onClick={() => copyToClipboard(`// ChainShield pre-payout screen
async function processContractorPayout(contractorId, payoutWallet, amountUsd) {
  const check = await dbService.verifyPayoutAddress(payoutWallet);

  if (check.status === 'BLOCKED') {
    await logSecurityIncident({ contractorId, payoutWallet, reason: check.reason });
    throw new Error('Payout rejected: destination is on the fraud blocklist.');
  }

  if (check.status === 'REVIEW') {
    // An unverified community report. Not proof of fraud, but not nothing --
    // queue for a human rather than auto-approving or auto-rejecting.
    return queueForManualReview({ contractorId, payoutWallet, check });
  }

  // APPROVED means "no report matched", not "verified safe". Keep your other
  // controls (address change cooldowns, 2FA on payout edits) in place.
  return sendCryptoPayout(payoutWallet, amountUsd);
}`, 'code-snippet')}
                className="text-xs font-mono text-sky-400 hover:underline flex items-center space-x-1"
              >
                {copiedKey === 'code-snippet' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>Copy Code</span>
              </button>
            </div>

            <div className="p-4 rounded-xl bg-[#070a0f] border border-slate-800 text-xs font-mono text-sky-300 overflow-x-auto">
              <pre>{`// ChainShield pre-payout screen
async function processContractorPayout(contractorId, payoutWallet, amountUsd) {
  const check = await dbService.verifyPayoutAddress(payoutWallet);

  if (check.status === 'BLOCKED') {
    await logSecurityIncident({ contractorId, payoutWallet, reason: check.reason });
    throw new Error('Payout rejected: destination is on the fraud blocklist.');
  }

  if (check.status === 'REVIEW') {
    // An unverified community report. Not proof of fraud, but not nothing --
    // queue for a human rather than auto-approving or auto-rejecting.
    return queueForManualReview({ contractorId, payoutWallet, check });
  }

  // APPROVED means "no report matched", not "verified safe". Keep your other
  // controls (address change cooldowns, 2FA on payout edits) in place.
  return sendCryptoPayout(payoutWallet, amountUsd);
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
              <span>Exchange Compliance Notification</span>
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              If the funds reached an exchange deposit address, that exchange holds KYC
              records for the account behind it. They will not release those to you --
              they release them to law enforcement, which is why both filings matter.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
            <div className="p-4 rounded-xl bg-[#0a0d14] border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-amber-400 font-bold">Exchange Security & Fraud Desk</span>
                <span className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-300 text-[10px]">Support Portal</span>
              </div>
              <p className="text-slate-400 font-sans">
                Submit transaction hash{' '}
                <b className="break-all">{incident.txHash?.slice(0, 12)}...</b>
                {incident.destinationAddress ? (
                  <> and destination address <b className="break-all">{incident.destinationAddress.slice(0, 10)}...</b></>
                ) : null}{' '}
                and ask them to preserve records pending a law-enforcement request.
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
                <span className="text-sky-400 font-bold">Cybercrime Filing (IC3 / local police)</span>
                <span className="px-2 py-0.5 rounded bg-sky-500/10 text-sky-300 text-[10px]">Law Enforcement</span>
              </div>
              <p className="text-slate-400 font-sans">
                File the report yourself and attach the dossier. Only law enforcement can
                compel KYC disclosure; an exchange cannot act on a private request alone.
              </p>
              <button
                onClick={() => onOpenDossier && onOpenDossier()}
                className="text-amber-400 hover:underline flex items-center space-x-1"
              >
                <span>Generate Dossier</span>
                <ExternalLink className="w-3 h-3" />
              </button>
            </div>
          </div>

          <p className="text-[11px] text-slate-500 leading-relaxed">
            Recovery is not the common outcome. Filing quickly and completely is what
            improves the odds, and the filings also feed the blocklist that stops the next
            payout going the same way.
          </p>
        </div>
      )}

    </div>
  );
}
