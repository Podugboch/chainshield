import React, { useState } from 'react';
import { X, ShieldAlert, CheckCircle2, AlertTriangle, Database } from 'lucide-react';
import { dbService } from '../lib/supabase';

export function FlagScammerModal({ isOpen, onClose, initialAddress = '', onFlaggedSuccess }) {
  if (!isOpen) return null;

  const [address, setAddress] = useState(initialAddress);
  const [network, setNetwork] = useState('Ethereum (ERC-20)');
  const [category, setCategory] = useState('Phishing / Account Takeover');
  const [impersonatedBrand, setImpersonatedBrand] = useState('Atlas Capture');
  const [stolenAmount, setStolenAmount] = useState('146.07');
  const [destinationEntity, setDestinationEntity] = useState('Binance');
  const [destinationAddress, setDestinationAddress] = useState('');
  const [notes, setNotes] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [success, setSuccess] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!address.trim()) return;

    setIsSubmitting(true);
    try {
      await dbService.addScamWallet({
        wallet_address: address.trim(),
        network,
        scam_category: category,
        impersonated_brand: impersonatedBrand.trim() || 'Generic Scam',
        total_stolen_usd: parseFloat(stolenAmount) || 0.00,
        destination_entity: destinationEntity.trim() || 'Unknown',
        destination_address: destinationAddress.trim() || null,
        notes: notes.trim() || 'Reported via ChainShield Threat Portal'
      });

      setSuccess(true);
      if (onFlaggedSuccess) onFlaggedSuccess();
      setTimeout(() => {
        setSuccess(false);
        onClose();
      }, 1200);
    } catch (err) {
      console.error('Failed to flag scammer:', err);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
      <div className="w-full max-w-xl bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl overflow-hidden space-y-4">
        
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 rounded-lg bg-red-500/20 text-red-400 flex items-center justify-center">
              <ShieldAlert className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white">Flag Malicious Scammer Address</h3>
              <p className="text-xs text-slate-400">Add address to global threat intelligence database</p>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white p-1 rounded-lg">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="p-6 space-y-4 text-xs font-mono">
          
          <div className="space-y-1">
            <label className="text-slate-300 font-semibold flex items-center justify-between">
              <span>SCAMMER WALLET ADDRESS (0x or Tron): *</span>
              <span className="text-red-400 font-normal text-[10px]">Required</span>
            </label>
            <input
              type="text"
              required
              placeholder="0x..."
              value={address}
              onChange={(e) => setAddress(e.target.value)}
              className="w-full p-2.5 bg-[#0a0d14] border border-slate-700 rounded-xl text-red-300 font-bold focus:outline-none focus:border-red-500 text-xs select-all"
            />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            
            <div className="space-y-1">
              <label className="text-slate-400">NETWORK:</label>
              <select
                value={network}
                onChange={(e) => setNetwork(e.target.value)}
                className="w-full p-2.5 bg-[#0a0d14] border border-slate-700 rounded-xl text-white focus:outline-none focus:border-red-500 text-xs"
              >
                <option>Ethereum (ERC-20)</option>
                <option>BNB Smart Chain (BEP-20)</option>
                <option>Polygon (PoS)</option>
                <option>Arbitrum One</option>
                <option>Base</option>
                <option>Tron (TRC-20)</option>
              </select>
            </div>

            <div className="space-y-1">
              <label className="text-slate-400">SCAM CATEGORY:</label>
              <select
                value={category}
                onChange={(e) => setCategory(e.target.value)}
                className="w-full p-2.5 bg-[#0a0d14] border border-slate-700 rounded-xl text-white focus:outline-none focus:border-red-500 text-xs"
              >
                <option>Phishing / Account Takeover</option>
                <option>Payout Redirection Fraud</option>
                <option>Fake Support Impersonation</option>
                <option>DEX Drainer / Malicious Contract</option>
                <option>Ponzi / Investment Fraud</option>
              </select>
            </div>

          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            
            <div className="space-y-1">
              <label className="text-slate-400">IMPERSONATED BRAND / PLATFORM:</label>
              <input
                type="text"
                placeholder="e.g. Atlas Capture, Binance"
                value={impersonatedBrand}
                onChange={(e) => setImpersonatedBrand(e.target.value)}
                className="w-full p-2.5 bg-[#0a0d14] border border-slate-700 rounded-xl text-white focus:outline-none focus:border-red-500 text-xs"
              />
            </div>

            <div className="space-y-1">
              <label className="text-slate-400">AMOUNT STOLEN (USD):</label>
              <input
                type="number"
                step="0.01"
                placeholder="146.07"
                value={stolenAmount}
                onChange={(e) => setStolenAmount(e.target.value)}
                className="w-full p-2.5 bg-[#0a0d14] border border-slate-700 rounded-xl text-white focus:outline-none focus:border-red-500 text-xs font-bold"
              />
            </div>

          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            
            <div className="space-y-1">
              <label className="text-slate-400">DESTINATION EXCHANGE (CEX):</label>
              <input
                type="text"
                placeholder="e.g. Binance Deposit Cluster, OKX"
                value={destinationEntity}
                onChange={(e) => setDestinationEntity(e.target.value)}
                className="w-full p-2.5 bg-[#0a0d14] border border-slate-700 rounded-xl text-amber-300 focus:outline-none focus:border-red-500 text-xs"
              />
            </div>

            <div className="space-y-1">
              <label className="text-slate-400">DESTINATION DEPOSIT ADDRESS (OPTIONAL):</label>
              <input
                type="text"
                placeholder="0x... (CEX deposit address)"
                value={destinationAddress}
                onChange={(e) => setDestinationAddress(e.target.value)}
                className="w-full p-2.5 bg-[#0a0d14] border border-slate-700 rounded-xl text-white focus:outline-none focus:border-red-500 text-xs"
              />
            </div>

          </div>

          <div className="space-y-1">
            <label className="text-slate-400">INCIDENT NOTES & EVIDENCE:</label>
            <textarea
              rows={2}
              placeholder="e.g. Link sent mimicking Atlas Capture login, substituted user wallet before payout..."
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              className="w-full p-2.5 bg-[#0a0d14] border border-slate-700 rounded-xl text-slate-200 focus:outline-none focus:border-red-500 text-xs font-sans"
            />
          </div>

          {success && (
            <div className="p-3 rounded-xl bg-emerald-950/60 border border-emerald-500/40 text-emerald-300 flex items-center space-x-2">
              <CheckCircle2 className="w-4 h-4" />
              <span>Address flagged and saved to Supabase Scam Database!</span>
            </div>
          )}

          {/* Footer Actions */}
          <div className="pt-3 border-t border-slate-800 flex items-center justify-end space-x-3">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 bg-slate-800 text-slate-300 rounded-xl hover:bg-slate-700 text-xs"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting || !address.trim()}
              className="px-5 py-2 bg-gradient-to-r from-red-600 to-rose-700 hover:from-red-500 hover:to-rose-600 text-white font-bold rounded-xl shadow-lg shadow-red-600/25 flex items-center space-x-1.5 text-xs disabled:opacity-50"
            >
              <ShieldAlert className="w-3.5 h-3.5" />
              <span>{isSubmitting ? 'Flagging...' : 'Confirm & Flag Address'}</span>
            </button>
          </div>

        </form>

      </div>
    </div>
  );
}
