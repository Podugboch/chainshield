import React, { useState } from 'react';
import {
  Search, ShieldCheck, ShieldAlert, Globe, CheckCircle2, ArrowRight, Ruler,
} from 'lucide-react';
import { analyzeUrl } from '../lib/phishingDetector';
import { dbService } from '../lib/supabase';

export function UrlScanner({ onInspectCase }) {
  const [urlInput, setUrlInput] = useState('');
  const [result, setResult] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [savedSuccess, setSavedSuccess] = useState(false);

  const sampleUrls = [
    { label: 'Atlas Capture lookalike', url: 'https://atlas-capture-support.top/payout-verify' },
    { label: 'Homoglyph squat', url: 'https://binancé.com/login' },
    { label: 'Brand in subdomain', url: 'http://coinbase.com-login-security.icu/authenticate' },
    { label: 'Legitimate ccTLD site', url: 'https://www.google.co.uk' },
    { label: 'Legitimate platform', url: 'https://atlascapture.com/dashboard' },
  ];

  const handleScan = async (targetToScan) => {
    const raw = targetToScan || urlInput;
    if (!raw.trim()) return;

    setIsScanning(true);
    setResult(null);
    setSavedSuccess(false);

    setTimeout(async () => {
      const scanResult = analyzeUrl(raw);
      setResult(scanResult);
      setIsScanning(false);

      try {
        await dbService.saveScan({
          scan_type: 'url',
          input_content: scanResult.url,
          target_domain: scanResult.hostname,
          risk_score: scanResult.riskScore,
          risk_level: scanResult.riskLevel,
          threat_reasons: scanResult.reasons
        });
        setSavedSuccess(true);
      } catch (err) {
        console.error('Save scan error:', err);
      }
    }, 450);
  };

  const getScoreColor = (result_) => {
    if (result_.riskLevel === 'UNKNOWN') return 'text-slate-300 bg-slate-500/10 border-slate-500/30';
    if (result_.riskScore >= 60) return 'text-red-500 bg-red-500/10 border-red-500/30';
    if (result_.riskScore >= 30) return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
    return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
  };

  const severityStyle = (severity) => {
    if (severity === 'critical') return 'bg-red-500/20 text-red-400';
    if (severity === 'high') return 'bg-orange-500/20 text-orange-400';
    if (severity === 'medium') return 'bg-amber-500/20 text-amber-400';
    return 'bg-slate-500/20 text-slate-400';
  };

  return (
    <div className="space-y-8 max-w-5xl mx-auto">

      {/* Header Banner */}
      <div className="text-center space-y-3">
        <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-sky-500/10 text-sky-400 text-xs font-mono border border-sky-500/20">
          <Ruler className="w-3.5 h-3.5" />
          <span>Brand-impersonation &amp; URL structure analysis</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          Inspect &amp; Neutralize Malicious Links
        </h1>
        <p className="text-slate-400 max-w-2xl mx-auto text-sm sm:text-base">
          Resolves the real registrable domain through the Public Suffix List, decodes
          internationalised hostnames, folds homoglyphs, and checks the result against a
          verified-brand registry — so <b>google.co.uk</b> passes and <b>coinbase.com-login.icu</b> does not.
        </p>
      </div>

      {/* Input Box */}
      <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-2xl space-y-4">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleScan();
          }}
          className="flex flex-col sm:flex-row gap-3"
        >
          <div className="relative flex-1">
            <Globe className="w-5 h-5 absolute left-3.5 top-3.5 text-slate-500" />
            <input
              type="text"
              placeholder="Paste suspicious link here (e.g. https://atlas-capture-payout.top)..."
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              className="w-full pl-11 pr-4 py-3 bg-[#0a0d14] border border-slate-700 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500 font-mono text-sm"
            />
          </div>
          <button
            type="submit"
            disabled={isScanning || !urlInput.trim()}
            className="px-6 py-3 bg-gradient-to-r from-sky-500 to-indigo-600 hover:from-sky-400 hover:to-indigo-500 text-white font-semibold rounded-xl transition-all shadow-lg shadow-sky-500/25 flex items-center justify-center space-x-2 disabled:opacity-50"
          >
            {isScanning ? (
              <>
                <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                <span>Analyzing…</span>
              </>
            ) : (
              <>
                <Search className="w-4 h-4" />
                <span>Scan URL</span>
              </>
            )}
          </button>
        </form>

        {/* Quick Sample Links */}
        <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-slate-800/60">
          <span className="text-xs text-slate-500">Test quick vectors:</span>
          {sampleUrls.map((sample, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => {
                setUrlInput(sample.url);
                handleScan(sample.url);
              }}
              className="text-xs font-mono px-2.5 py-1 rounded-md bg-slate-800 text-slate-300 hover:bg-slate-700 hover:text-white transition"
            >
              {sample.label}
            </button>
          ))}
        </div>
      </div>

      {/* Scan Results View */}
      {result && (
        <div className="space-y-6 animate-fadeIn">
          
          {/* Main Risk Card */}
          <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl relative overflow-hidden space-y-6">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-6 border-b border-slate-800">
              
              <div className="space-y-1">
                <div className="flex items-center space-x-2">
                  <span className="text-xs font-mono text-slate-400">TARGET DOMAIN:</span>
                  <span className="text-sm font-mono font-bold text-white bg-slate-800 px-2 py-0.5 rounded">
                    {result.displayHost || result.hostname || '—'}
                  </span>
                </div>
                {result.registrableDomain && (
                  <p className="text-xs text-slate-400 font-mono">
                    Resolves to <b className="text-slate-200">{result.registrableDomain}</b>
                    {' — this is the part that decides where you connect.'}
                  </p>
                )}
                <p className="text-xs text-slate-400 font-mono break-all">{result.url}</p>
              </div>

              <div className="flex items-center space-x-4">
                <div className={`px-4 py-2 rounded-xl font-bold font-mono text-center border ${getScoreColor(result)}`}>
                  <div className="text-xs uppercase tracking-wider">{result.riskLevel}</div>
                  <div className="text-2xl font-extrabold">{result.riskScore}/100</div>
                </div>
              </div>

            </div>

            {/* Brand relationship banner */}
            {result.impersonatedBrand && result.brandStatus !== 'path-mention' && (
              <div className="p-4 rounded-xl bg-red-950/40 border border-red-500/40 flex items-start space-x-3">
                <ShieldAlert className="w-6 h-6 text-red-400 shrink-0 mt-0.5" />
                <div>
                  <h4 className="text-sm font-bold text-red-200">
                    This is not {result.impersonatedBrand}
                  </h4>
                  <p className="text-xs text-red-300/80 mt-1">
                    The name is built to read as <b>{result.impersonatedBrand}</b>, but{' '}
                    <b className="font-mono">{result.registrableDomain}</b> is registered by
                    someone else. Credentials, seed phrases or wallet approvals entered here go
                    to whoever controls that domain.
                  </p>
                </div>
              </div>
            )}

            {result.brandStatus === 'brand-elsewhere' && (
              <div className="p-4 rounded-xl bg-sky-950/40 border border-sky-500/30 flex items-start space-x-3">
                <ShieldCheck className="w-5 h-5 text-sky-400 shrink-0 mt-0.5" />
                <p className="text-xs text-sky-200/90">
                  <b className="font-mono">{result.registrableDomain}</b> carries the{' '}
                  {result.impersonatedBrand || 'brand'} name on a suffix outside the verified
                  list. Large brands run country domains that look exactly like this, so it is
                  not treated as an attack — confirm it if you were not expecting it.
                </p>
              </div>
            )}

            {/* What was actually measured */}
            {result.heuristics && (
              <div className="p-4 rounded-xl bg-[#0a0d14] border border-sky-500/30 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2 text-sky-400 font-mono text-xs font-bold uppercase">
                    <Ruler className="w-4 h-4" />
                    <span>Measured URL structure</span>
                  </div>
                  <span className="text-xs font-mono text-slate-400">
                    Structural score: <b>{result.heuristics.score}</b>/100
                  </span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 space-y-0.5">
                    <span className="text-slate-500 text-[10px]">Registered name entropy</span>
                    <p className="text-slate-200 font-bold">{result.heuristics.features.labelEntropy} bits</p>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 space-y-0.5">
                    <span className="text-slate-500 text-[10px]">Digits in host</span>
                    <p className="text-slate-200 font-bold">{(result.heuristics.features.digitRatioHost * 100).toFixed(1)}%</p>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 space-y-0.5">
                    <span className="text-slate-500 text-[10px]">Subdomain depth</span>
                    <p className="text-slate-200 font-bold">{result.heuristics.features.subdomainDepth}</p>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 space-y-0.5">
                    <span className="text-slate-500 text-[10px]">Public suffix</span>
                    <p className="text-slate-200 font-bold">.{result.heuristics.features.publicSuffix || '—'}</p>
                  </div>
                </div>
              </div>
            )}

            {/* Risk Breakdown Reasons */}
            <div className="space-y-3">
              <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider font-mono">
                What was found
              </h3>

              {result.reasons.length === 0 ? (
                <div className="p-4 rounded-xl bg-emerald-950/30 border border-emerald-500/30 flex items-center space-x-3 text-emerald-300 text-sm">
                  <ShieldCheck className="w-5 h-5 text-emerald-400" />
                  <span>Nothing flagged: the domain is not a lookalike of any brand on the list and its structure is unremarkable.</span>
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {result.reasons.map((reason, i) => (
                    <div key={i} className="p-3.5 rounded-xl bg-[#0a0d14] border border-slate-800 space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-mono text-sky-400 font-medium">{reason.category}</span>
                        <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono uppercase ${severityStyle(reason.severity)}`}>
                          {reason.severity}
                        </span>
                      </div>
                      <p className="text-xs text-slate-300">{reason.text}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Safety Steps */}
            <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2">
              <h4 className="text-xs font-mono font-semibold text-slate-300 uppercase">Actionable Recommendations:</h4>
              <ul className="space-y-1 text-xs text-slate-400">
                {result.recommendations.map((rec, i) => (
                  <li key={i} className="flex items-center space-x-2">
                    <span>{rec}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Action Bar */}
            <div className="pt-4 border-t border-slate-800 flex flex-wrap items-center justify-between gap-3 text-xs text-slate-400">
              {savedSuccess ? (
                <div className="flex items-center space-x-1.5 text-emerald-400">
                  <CheckCircle2 className="w-4 h-4" />
                  <span>Scan logged to threat database</span>
                </div>
              ) : (
                <span className="text-slate-500">Scan not logged</span>
              )}
              <button
                onClick={() => onInspectCase && onInspectCase()}
                className="flex items-center space-x-1.5 text-sky-400 hover:text-sky-300 font-semibold transition"
              >
                <span>View Related Atlas Capture Case</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>

          </div>

        </div>
      )}

    </div>
  );
}
