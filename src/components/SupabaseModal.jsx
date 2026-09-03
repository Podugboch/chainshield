import React, { useState, useEffect } from 'react';
import { X, DatabaseZap, CheckCircle2, Key, Globe, AlertTriangle, HardDrive, Loader2 } from 'lucide-react';
import { getCloudStatus } from '../lib/supabase';

/**
 * How each cloud state is presented. The 'anonymous-disabled' case is the one
 * that matters: the project connects, the modal said "Refreshing connection...",
 * and every scan and case file silently stayed in this browser because no
 * session could be created. Nothing in the UI reported that.
 */
const STATUS_VIEW = {
  active: {
    tone: 'bg-emerald-950/50 border-emerald-500/40 text-emerald-300',
    Icon: CheckCircle2,
    label: 'Connected — cloud sync active',
  },
  'anonymous-disabled': {
    tone: 'bg-amber-950/50 border-amber-500/40 text-amber-200',
    Icon: AlertTriangle,
    label: 'Connected, but no session — running on browser storage',
  },
  error: {
    tone: 'bg-red-950/50 border-red-500/40 text-red-200',
    Icon: AlertTriangle,
    label: 'Cloud unreachable',
  },
  none: {
    tone: 'bg-slate-950 border-slate-700 text-slate-300',
    Icon: HardDrive,
    label: 'Local only',
  },
  unknown: {
    tone: 'bg-slate-950 border-slate-700 text-slate-400',
    Icon: Loader2,
    label: 'Checking connection…',
  },
};

export function SupabaseModal({ isOpen, onClose }) {
  // Hooks before the isOpen guard -- see the note in ReportModal. Returning
  // first meant the hook count changed when the modal opened, which React
  // treats as a fatal error.
  const [url, setUrl] = useState(localStorage.getItem('chainshield_supabase_url') || '');
  const [anonKey, setAnonKey] = useState(localStorage.getItem('chainshield_supabase_key') || '');
  const [saved, setSaved] = useState(false);
  const [status, setStatus] = useState(null);
  const [formError, setFormError] = useState('');

  useEffect(() => {
    if (!isOpen) return;
    let cancelled = false;
    setStatus(null);
    getCloudStatus().then((s) => {
      if (!cancelled) setStatus(s);
    });
    return () => { cancelled = true; };
  }, [isOpen]);

  if (!isOpen) return null;

  const view = STATUS_VIEW[status?.configured ? status.session : 'none']
    || STATUS_VIEW[status ? 'unknown' : 'unknown'];

  const handleSave = () => {
    const trimmedUrl = url.trim();
    const trimmedKey = anonKey.trim();
    // Saving one half of a credential pair leaves the app configured-but-broken,
    // and the old handler accepted it without a word.
    if (!trimmedUrl || !trimmedKey) {
      setFormError('Both the project URL and the anon key are required. Use "Reset to Local Offline Mode" to disconnect instead.');
      return;
    }
    if (!/^https?:\/\/[^\s]+$/i.test(trimmedUrl)) {
      setFormError('The project URL should look like https://your-project-ref.supabase.co');
      return;
    }
    setFormError('');
    localStorage.setItem('chainshield_supabase_url', trimmedUrl);
    localStorage.setItem('chainshield_supabase_key', trimmedKey);
    setSaved(true);
    setTimeout(() => {
      window.location.reload();
    }, 800);
  };

  const handleClear = () => {
    localStorage.removeItem('chainshield_supabase_url');
    localStorage.removeItem('chainshield_supabase_key');
    window.location.reload();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
      <div className="w-full max-w-lg bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl overflow-hidden space-y-4">
        
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 rounded-lg bg-emerald-500/20 text-emerald-400 flex items-center justify-center">
              <DatabaseZap className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white">Supabase Cloud Connection</h3>
              <p className="text-xs text-slate-400">Sync intelligence and investigation dossiers live</p>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white p-1 rounded-lg">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 space-y-4 text-xs font-mono">
          <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-slate-300 leading-relaxed font-sans">
            ChainShield ships its PostgreSQL schema and row-level-security policies in{' '}
            <code className="text-sky-300">supabase/schema.sql</code>. Apply that file to your
            project first, then connect below. Case files stay private to your session; the
            wallet blocklist is shared.
          </div>

          {/* Live state, read from the same source the data layer uses. */}
          <div className={`p-3 rounded-xl border flex items-start space-x-2 font-sans ${view.tone}`}>
            <view.Icon className={`w-4 h-4 shrink-0 mt-0.5 ${!status ? 'animate-spin' : ''}`} />
            <div className="space-y-0.5">
              <p className="font-bold">{status ? view.label : 'Checking connection…'}</p>
              {status?.detail && <p className="text-[11px] opacity-90">{status.detail}</p>}
              {status?.session === 'anonymous-disabled' && (
                <p className="text-[11px] opacity-90">
                  Supabase → Authentication → Sign In / Providers → enable <b>Anonymous</b>,
                  then reload this page.
                </p>
              )}
            </div>
          </div>

          <div className="space-y-1">
            <label className="text-slate-400 flex items-center space-x-1.5 font-semibold">
              <Globe className="w-3.5 h-3.5 text-sky-400" />
              <span>SUPABASE PROJECT URL:</span>
            </label>
            <input
              type="text"
              placeholder="https://xyzcompany.supabase.co"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="w-full p-2.5 bg-[#0a0d14] border border-slate-700 rounded-xl text-white focus:outline-none focus:border-emerald-500 font-mono text-xs"
            />
          </div>

          <div className="space-y-1">
            <label className="text-slate-400 flex items-center space-x-1.5 font-semibold">
              <Key className="w-3.5 h-3.5 text-emerald-400" />
              <span>SUPABASE ANON PUBLIC KEY:</span>
            </label>
            <input
              type="password"
              placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
              value={anonKey}
              onChange={(e) => setAnonKey(e.target.value)}
              className="w-full p-2.5 bg-[#0a0d14] border border-slate-700 rounded-xl text-white focus:outline-none focus:border-emerald-500 font-mono text-xs"
            />
          </div>

          {formError && (
            <div className="p-2.5 rounded-lg bg-red-950/50 border border-red-500/40 text-red-200 flex items-start space-x-2 font-sans">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
              <span>{formError}</span>
            </div>
          )}

          {saved && (
            <div className="p-2.5 rounded-lg bg-emerald-950/60 border border-emerald-500/40 text-emerald-300 flex items-start space-x-2 font-sans">
              <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5" />
              {/* Reloading is not the same as connecting. The banner used to
                  imply the credentials had been accepted; the panel above
                  reports what actually happened after the reload. */}
              <span>Credentials stored. Reloading — the status panel above will show whether the connection works.</span>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-slate-800 bg-slate-950 flex items-center justify-between">
          <button
            onClick={handleClear}
            className="text-xs font-mono text-red-400 hover:underline"
          >
            Reset to Local Offline Mode
          </button>
          <div className="flex space-x-3">
            <button
              onClick={onClose}
              className="px-4 py-2 bg-slate-800 text-slate-300 text-xs font-semibold rounded-xl hover:bg-slate-700"
            >
              Cancel
            </button>
            <button
              onClick={handleSave}
              className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold rounded-xl shadow-lg shadow-emerald-600/25"
            >
              Save & Connect
            </button>
          </div>
        </div>

      </div>
    </div>
  );
}
