import React from 'react';
import { Shield, ShieldAlert, Activity, Database, FileText, DatabaseZap } from 'lucide-react';
import { isSupabaseConfigured } from '../lib/supabase';

export function Navbar({ activeTab, setActiveTab, onOpenSupabaseModal }) {
  const navItems = [
    { id: 'url-scanner', label: 'Link Scanner', icon: Shield },
    { id: 'message-scanner', label: 'Message & Email AI', icon: ShieldAlert },
    { id: 'forensics', label: 'Crypto Forensics', icon: Activity },
    { id: 'cases', label: 'Investigation Cases', icon: FileText },
    { id: 'threat-db', label: 'Threat Database', icon: Database },
  ];

  return (
    <header className="sticky top-0 z-40 bg-[#0a0d14]/90 backdrop-blur-md border-b border-slate-800">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          
          {/* Logo & Branding */}
          <div className="flex items-center space-x-3 cursor-pointer" onClick={() => setActiveTab('url-scanner')}>
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-sky-500 to-indigo-600 flex items-center justify-center shadow-lg shadow-sky-500/20">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-xl font-bold bg-gradient-to-r from-sky-400 to-indigo-300 bg-clip-text text-transparent">
                  ChainShield
                </span>
                <span className="text-xs px-2 py-0.5 rounded-full font-mono bg-sky-500/10 text-sky-400 border border-sky-500/20">
                  v1.0
                </span>
              </div>
              <p className="text-[11px] text-slate-400 hidden sm:block">AI Phishing Scanner & Crypto Forensics</p>
            </div>
          </div>

          {/* Nav Tabs */}
          <nav className="hidden md:flex space-x-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`flex items-center space-x-2 px-3.5 py-2 rounded-lg text-sm font-medium transition-all ${
                    isActive
                      ? 'bg-sky-500/15 text-sky-400 border border-sky-500/30 shadow-sm'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                  }`}
                >
                  <Icon className={`w-4 h-4 ${isActive ? 'text-sky-400' : 'text-slate-400'}`} />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>

          {/* Right Action: Supabase Status */}
          <div className="flex items-center space-x-3">
            <button
              onClick={onOpenSupabaseModal}
              className="flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-mono border transition-all bg-slate-900/80 hover:bg-slate-800 border-slate-700 text-slate-300"
              title="Configure Supabase Database"
            >
              <DatabaseZap className="w-3.5 h-3.5 text-emerald-400" />
              <span className="hidden sm:inline">Supabase:</span>
              <span className={`inline-block w-2 h-2 rounded-full ${isSupabaseConfigured ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`} />
              <span>{isSupabaseConfigured ? 'Connected' : 'Local Mode'}</span>
            </button>
          </div>

        </div>

        {/* Mobile Navigation Row */}
        <div className="flex md:hidden overflow-x-auto py-2 space-x-1 border-t border-slate-800/60">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs whitespace-nowrap font-medium transition-all ${
                  isActive
                    ? 'bg-sky-500/20 text-sky-400 border border-sky-500/30'
                    : 'text-slate-400 hover:bg-slate-800'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{item.label}</span>
              </button>
            );
          })}
        </div>

      </div>
    </header>
  );
}
