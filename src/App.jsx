import React, { useState } from 'react';
import { Navbar } from './components/Navbar';
import { UrlScanner } from './components/UrlScanner';
import { MessageScanner } from './components/MessageScanner';
import { CryptoForensics } from './components/CryptoForensics';
// PayoutGuard existed as a 274-line component that nothing imported, so the
// pre-payout screen it implements was unreachable. It has its own tab now.
import { PayoutGuard } from './components/PayoutGuard';
import { EnforcementHub } from './components/EnforcementHub';
import { CaseManager } from './components/CaseManager';
import { ThreatDatabase } from './components/ThreatDatabase';
import { ReportModal } from './components/ReportModal';
import { SupabaseModal } from './components/SupabaseModal';
import { FlagScammerModal } from './components/FlagScammerModal';

export default function App() {
  const [activeTab, setActiveTab] = useState('url-scanner');
  const [isReportModalOpen, setIsReportModalOpen] = useState(false);
  const [isSupabaseModalOpen, setIsSupabaseModalOpen] = useState(false);
  const [isFlagModalOpen, setIsFlagModalOpen] = useState(false);
  const [selectedWalletForScan, setSelectedWalletForScan] = useState('');
  // Bumped after a successful flag so the threat table remounts and reloads.
  // Nothing refreshed it before, so a newly reported address stayed invisible
  // until the user pressed refresh themselves.
  const [dbRefreshKey, setDbRefreshKey] = useState(0);

  const handleScanFromDb = (address) => {
    setSelectedWalletForScan(address);
    setActiveTab('forensics');
  };

  return (
    <div className="min-h-screen bg-[#0a0d14] text-slate-100 flex flex-col selection:bg-sky-500/30 selection:text-sky-200">
      
      {/* Top Navbar */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onOpenSupabaseModal={() => setIsSupabaseModalOpen(true)}
      />

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === 'url-scanner' && (
          <UrlScanner onInspectCase={() => setActiveTab('cases')} />
        )}

        {activeTab === 'message-scanner' && (
          <MessageScanner />
        )}

        {activeTab === 'forensics' && (
          <CryptoForensics 
            onGenerateReport={() => setIsReportModalOpen(true)} 
            onOpenFlagModal={(addr) => {
              setSelectedWalletForScan(addr || '');
              setIsFlagModalOpen(true);
            }}
            initialTarget={selectedWalletForScan}
          />
        )}

        {activeTab === 'payout-guard' && (
          <PayoutGuard />
        )}

        {activeTab === 'enforcement' && (
          <EnforcementHub onOpenDossier={() => setIsReportModalOpen(true)} />
        )}

        {activeTab === 'cases' && (
          <CaseManager onOpenDossier={() => setIsReportModalOpen(true)} />
        )}

        {activeTab === 'threat-db' && (
          <ThreatDatabase
            key={dbRefreshKey}
            onOpenFlagModal={() => setIsFlagModalOpen(true)}
            onScanAddress={handleScanFromDb}
          />
        )}
      </main>

      {/* Modals */}
      <ReportModal
        isOpen={isReportModalOpen}
        onClose={() => setIsReportModalOpen(false)}
      />

      <SupabaseModal
        isOpen={isSupabaseModalOpen}
        onClose={() => setIsSupabaseModalOpen(false)}
      />

      <FlagScammerModal
        isOpen={isFlagModalOpen}
        initialAddress={selectedWalletForScan}
        onClose={() => setIsFlagModalOpen(false)}
        onFlaggedSuccess={() => setDbRefreshKey((k) => k + 1)}
      />

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-950/60 py-6 text-center text-xs text-slate-500 font-mono">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>ChainShield &copy; 2026 | URL, Message &amp; Blockchain Forensics</span>
          <span>Designed for incident remediation & law enforcement reporting</span>
        </div>
      </footer>

    </div>
  );
}
