import React, { useState } from 'react';
import { ShieldAlert, AlertTriangle, Sparkles, Mail, Send, CheckCircle2, Shield } from 'lucide-react';
import { analyzeMessage } from '../lib/phishingDetector';
import { dbService } from '../lib/supabase';

export function MessageScanner() {
  const [messageText, setMessageText] = useState('');
  const [analysis, setAnalysis] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  const sampleMessages = [
    {
      label: 'Atlas Capture Fake Notice',
      text: "Urgent Notification from Atlas Capture Support: Immediate action required! Your contractor payout of $146.07 has been temporarily withheld due to billing verification failure. Please update payout address and verify your USDT ERC-20 wallet within 12 hours via: https://atlas-capture-support.top/payout-verify to avoid total suspension."
    },
    {
      label: 'Generic Crypto Phishing',
      text: "Action required: Your wallet connection has expired. Re-link wallet and confirm authorization within 24 hours at https://binance-security-auth.xyz/login to protect your funds."
    }
  ];

  const handleAnalyze = () => {
    if (!messageText.trim()) return;
    setIsAnalyzing(true);
    setAnalysis(null);

    setTimeout(async () => {
      const res = analyzeMessage(messageText);
      setAnalysis(res);
      setIsAnalyzing(false);

      if (res) {
        await dbService.saveScan({
          scan_type: 'message',
          input_content: messageText.slice(0, 300),
          target_domain: res.extractedUrls[0]?.hostname || 'Text Message',
          risk_score: res.riskScore,
          risk_level: res.riskLevel,
          threat_reasons: res.reasons
        });
      }
    }, 500);
  };

  return (
    <div className="space-y-8 max-w-5xl mx-auto">
      
      <div className="text-center space-y-3">
        <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-indigo-500/10 text-indigo-400 text-xs font-mono border border-indigo-500/20">
          <Sparkles className="w-3.5 h-3.5" />
          <span>Social Engineering & Coercion Analyzer</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          Email & Direct Message Threat Inspector
        </h1>
        <p className="text-slate-400 max-w-2xl mx-auto text-sm sm:text-base">
          Paste suspicious emails, Telegram DMs, or Discord messages to detect artificial urgency, fake payout updates, and phishing intent.
        </p>
      </div>

      {/* Input Form */}
      <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-2xl space-y-4">
        <div className="space-y-2">
          <label className="text-xs font-mono text-slate-400 flex items-center justify-between">
            <span>PASTE RAW MESSAGE OR EMAIL CONTENT:</span>
            <span>{messageText.length} chars</span>
          </label>
          <textarea
            rows={5}
            placeholder="Paste email text, SMS, or DM message here..."
            value={messageText}
            onChange={(e) => setMessageText(e.target.value)}
            className="w-full p-4 bg-[#0a0d14] border border-slate-700 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 text-sm font-sans"
          />
        </div>

        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-2">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs text-slate-500">Load sample:</span>
            {sampleMessages.map((sample, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => {
                  setMessageText(sample.text);
                }}
                className="text-xs font-mono px-2.5 py-1 rounded-md bg-slate-800 text-slate-300 hover:bg-slate-700 hover:text-white transition"
              >
                {sample.label}
              </button>
            ))}
          </div>

          <button
            onClick={handleAnalyze}
            disabled={isAnalyzing || !messageText.trim()}
            className="w-full sm:w-auto px-6 py-2.5 bg-gradient-to-r from-indigo-500 to-sky-600 hover:from-indigo-400 hover:to-sky-500 text-white font-semibold rounded-xl transition-all shadow-lg shadow-indigo-500/25 flex items-center justify-center space-x-2 disabled:opacity-50"
          >
            {isAnalyzing ? (
              <>
                <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                <span>Evaluating...</span>
              </>
            ) : (
              <>
                <ShieldAlert className="w-4 h-4" />
                <span>Analyze Message</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Analysis Output */}
      {analysis && (
        <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-6 animate-fadeIn">
          
          <div className="flex items-center justify-between pb-4 border-b border-slate-800">
            <div>
              <h3 className="text-lg font-bold text-white flex items-center space-x-2">
                <Mail className="w-5 h-5 text-indigo-400" />
                <span>Message Threat Assessment</span>
              </h3>
              <p className="text-xs text-slate-400">Social engineering & scam pattern breakdown</p>
            </div>

            <div className={`px-4 py-1.5 rounded-xl font-mono text-xs font-bold border ${
              analysis.riskLevel === 'MALICIOUS' ? 'text-red-400 bg-red-500/10 border-red-500/30' :
              analysis.riskLevel === 'SUSPICIOUS' ? 'text-amber-400 bg-amber-500/10 border-amber-500/30' :
              'text-emerald-400 bg-emerald-500/10 border-emerald-500/30'
            }`}>
              {analysis.riskLevel} ({analysis.riskScore}/100)
            </div>
          </div>

          {/* Reasons */}
          <div className="space-y-3">
            <h4 className="text-xs font-mono font-semibold text-slate-400 uppercase">Identified Red Flags:</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {analysis.reasons.map((r, i) => (
                <div key={i} className="p-3.5 rounded-xl bg-[#0a0d14] border border-slate-800 space-y-1">
                  <span className="text-xs font-mono text-indigo-400 font-semibold">{r.category}</span>
                  <p className="text-xs text-slate-300">{r.text}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Embedded URL Scan preview */}
          {analysis.extractedUrls.length > 0 && (
            <div className="space-y-3 pt-2">
              <h4 className="text-xs font-mono font-semibold text-slate-400 uppercase">
                Embedded Link Inspection ({analysis.extractedUrls.length}):
              </h4>
              {analysis.extractedUrls.map((u, i) => (
                <div key={i} className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between text-xs">
                  <span className="font-mono text-sky-300 truncate max-w-md">{u.url}</span>
                  <span className={`px-2 py-0.5 rounded font-mono font-bold ${
                    u.riskLevel === 'MALICIOUS' ? 'text-red-400 bg-red-500/20'
                      : u.riskLevel === 'SUSPICIOUS' ? 'text-amber-400 bg-amber-500/20'
                        : 'text-emerald-400 bg-emerald-500/20'
                  }`}>
                    {u.riskLevel} ({u.riskScore}/100)
                  </span>
                </div>
              ))}
            </div>
          )}

        </div>
      )}

    </div>
  );
}
