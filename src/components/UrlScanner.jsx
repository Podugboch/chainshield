import React, { useState } from 'react';
import { 
  Search, AlertTriangle, ShieldCheck, ShieldAlert, ExternalLink, 
  Globe, Sparkles, CheckCircle2, ArrowRight, BrainCircuit, Cpu, Layers 
} from 'lucide-react';
import { analyzeUrl } from '../lib/phishingDetector';
import { dbService } from '../lib/supabase';

export function UrlScanner({ onInspectCase }) {
  const [urlInput, setUrlInput] = useState('');
  const [result, setResult] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [savedSuccess, setSavedSuccess] = useState(false);

  const sampleUrls = [
    { label: 'Atlas Capture Fake Phish', url: 'https://atlas-capture-support.top/payout-verify' },
    { label: 'PhiUSIIL High-Entropy DGA', url: 'https://secure-login.auth-93821a.xyz/verify?user=84920' },
    { label: 'Binance Typosquat', url: 'https://binance-security-auth.xyz/login' },
    { label: 'Legitimate Platform', url: 'https://atlascapture.com/dashboard' }
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

  const getScoreColor = (score) => {
    if (score >= 60) return 'text-red-500 bg-red-500/10 border-red-500/30';
    if (score >= 25) return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
    return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
  };

  return (
    <div className="space-y-8 max-w-5xl mx-auto">
      
      {/* Header Banner */}
      <div className="text-center space-y-3">
        <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-sky-500/10 text-sky-400 text-xs font-mono border border-sky-500/20">
          <BrainCircuit className="w-3.5 h-3.5" />
          <span>PhiUSIIL Machine Learning & Heuristic Phishing Engine</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          Inspect & Neutralize Malicious Links
        </h1>
        <p className="text-slate-400 max-w-2xl mx-auto text-sm sm:text-base">
          Evaluates URLs using 134+ structural, lexical, and Shannon entropy features from the <b>PhiUSIIL benchmark</b>, combined with real-time brand protection.
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
                <span>Running ML Model...</span>
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
                    {result.hostname}
                  </span>
                </div>
                <p className="text-xs text-slate-400 font-mono break-all">{result.url}</p>
              </div>

              <div className="flex items-center space-x-4">
                <div className={`px-4 py-2 rounded-xl font-bold font-mono text-center border ${getScoreColor(result.riskScore)}`}>
                  <div className="text-xs uppercase tracking-wider">{result.riskLevel}</div>
                  <div className="text-2xl font-extrabold">{result.riskScore}/100</div>
                </div>
              </div>

            </div>

            {/* Impersonation Banner Alert */}
            {result.impersonatedBrand && (
              <div className="p-4 rounded-xl bg-red-950/40 border border-red-500/40 flex items-start space-x-3">
                <ShieldAlert className="w-6 h-6 text-red-400 shrink-0 mt-0.5" />
                <div>
                  <h4 className="text-sm font-bold text-red-200">
                    High Alert: Unofficial Impersonation of {result.impersonatedBrand}
                  </h4>
                  <p className="text-xs text-red-300/80 mt-1">
                    This domain attempts to spoof legitimate contractors/users of <b>{result.impersonatedBrand}</b> to harvest credentials or modify payout cryptocurrency wallets.
                  </p>
                </div>
              </div>
            )}

            {/* PhiUSIIL ML Model Feature Card */}
            {result.mlResult && result.mlResult.features && (
              <div className="p-4 rounded-xl bg-[#0a0d14] border border-sky-500/30 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2 text-sky-400 font-mono text-xs font-bold uppercase">
                    <BrainCircuit className="w-4 h-4" />
                    <span>PhiUSIIL Machine Learning Feature Extraction:</span>
                  </div>
                  <span className="text-xs font-mono text-slate-400">
                    ML Model Confidence: <b>{(result.mlResult.confidence * 100).toFixed(0)}%</b>
                  </span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 space-y-0.5">
                    <span className="text-slate-500 text-[10px]">Domain Entropy</span>
                    <p className="text-slate-200 font-bold">{result.mlResult.features.domainEntropy} bits</p>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 space-y-0.5">
                    <span className="text-slate-500 text-[10px]">Digit Density Ratio</span>
                    <p className="text-slate-200 font-bold">{(result.mlResult.features.digitRatio * 100).toFixed(1)}%</p>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 space-y-0.5">
                    <span className="text-slate-500 text-[10px]">Subdomain Count</span>
                    <p className="text-slate-200 font-bold">{result.mlResult.features.noOfSubdomains}</p>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 space-y-0.5">
                    <span className="text-slate-500 text-[10px]">Special Char Ratio</span>
                    <p className="text-slate-200 font-bold">{(result.mlResult.features.spcharRatio * 100).toFixed(1)}%</p>
                  </div>
                </div>
              </div>
            )}

            {/* Risk Breakdown Reasons */}
            <div className="space-y-3">
              <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider font-mono">
                Threat Breakdown & Heuristic Indicators
              </h3>
              
              {result.reasons.length === 0 ? (
                <div className="p-4 rounded-xl bg-emerald-950/30 border border-emerald-500/30 flex items-center space-x-3 text-emerald-300 text-sm">
                  <ShieldCheck className="w-5 h-5 text-emerald-400" />
                  <span>No malicious signatures found. Domain structure complies with security standards.</span>
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {result.reasons.map((reason, i) => (
                    <div key={i} className="p-3.5 rounded-xl bg-[#0a0d14] border border-slate-800 space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-mono text-sky-400 font-medium">{reason.category}</span>
                        <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono uppercase ${
                          reason.severity === 'critical' ? 'bg-red-500/20 text-red-400' : 'bg-amber-500/20 text-amber-400'
                        }`}>
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
              <div className="flex items-center space-x-1.5 text-emerald-400">
                <CheckCircle2 className="w-4 h-4" />
                <span>Scan logged to threat database</span>
              </div>
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
