import React, { useState } from 'react';
import { X, DatabaseZap, CheckCircle2, Key, Globe, ExternalLink } from 'lucide-react';
import { isSupabaseConfigured } from '../lib/supabase';

export function SupabaseModal({ isOpen, onClose }) {
  if (!isOpen) return null;

  const [url, setUrl] = useState(localStorage.getItem('chainshield_supabase_url') || '');
  const [anonKey, setAnonKey] = useState(localStorage.getItem('chainshield_supabase_key') || '');
  const [saved, setSaved] = useState(false);

  const handleSave = () => {
    localStorage.setItem('chainshield_supabase_url', url.trim());
    localStorage.setItem('chainshield_supabase_key', anonKey.trim());
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
            ChainShield has a built-in PostgreSQL schema in <code className="text-sky-300">supabase/schema.sql</code>. 
            Connect your Supabase project below to synchronize live threat intelligence across all devices.
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

          {saved && (
            <div className="p-2.5 rounded-lg bg-emerald-950/60 border border-emerald-500/40 text-emerald-300 flex items-center space-x-2">
              <CheckCircle2 className="w-4 h-4" />
              <span>Saved! Refreshing connection...</span>
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
