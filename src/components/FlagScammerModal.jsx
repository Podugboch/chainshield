import React, { useState, useEffect } from 'react';
import { X, ShieldAlert, CheckCircle2, AlertTriangle } from 'lucide-react';
import { dbService } from '../lib/supabase';
import { validateAddress } from '../lib/evm';

/** Tron addresses are base58, not hex, so the EIP-55 check does not apply. */
function checkTronAddress(value) {
  if (!/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(value)) {
    return { ok: false, reason: 'A Tron address is 34 characters starting with T.' };
  }
  return { ok: true, address: value };
}

export function FlagScammerModal({ isOpen, onClose, initialAddress = '', onFlaggedSuccess }) {
  // Hooks run before the isOpen guard. This modal is mounted for the life of the
  // app and toggled by prop, so an early return changed the hook count from 0 to
  // 10 the moment it opened -- React aborts on that.
  const [address, setAddress] = useState(initialAddress);
  const [network, setNetwork] = useState('Ethereum (ERC-20)');
  const [category, setCategory] = useState('Phishing / Account Takeover');
  // These used to default to this repo's own case -- 'Atlas Capture', '146.07',
  // 'Binance' -- so anyone flagging an unrelated address submitted that incident's
  // details with it unless they noticed. They are placeholders now, not values.
  const [impersonatedBrand, setImpersonatedBrand] = useState('');
  const [stolenAmount, setStolenAmount] = useState('');
  const [destinationEntity, setDestinationEntity] = useState('');
  const [destinationAddress, setDestinationAddress] = useState('');
  const [notes, setNotes] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [success, setSuccess] = useState(null);
  const [errorMsg, setErrorMsg] = useState('');

  // A useState initialiser runs once for the component's whole life, so opening
  // the modal a second time from a different row kept showing the first address.
  useEffect(() => {
    if (isOpen) {
      setAddress(initialAddress || '');
      setErrorMsg('');
      setSuccess(null);
    }
  }, [isOpen, initialAddress]);

  if (!isOpen) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    const raw = address.trim();
    if (!raw) return;
    setErrorMsg('');

    // Validate before writing. An unchecked address goes into the blocklist as
    // typed: a malformed one can never match a real lookup, and a valid typo
    // blocks a wallet belonging to someone uninvolved.
    const parsed = network.startsWith('Tron') ? checkTronAddress(raw) : validateAddress(raw);
    if (!parsed.ok) {
      setErrorMsg(
        parsed.checksum
          ? `${parsed.reason} Nearest valid checksum: ${parsed.checksum}`
          : parsed.reason
      );
      return;
    }

    const destination = destinationAddress.trim();
    if (destination && !network.startsWith('Tron')) {
      const parsedDest = validateAddress(destination);
      if (!parsedDest.ok) {
        setErrorMsg(`Destination address: ${parsedDest.reason}`);
        return;
      }
    }

    const amount = stolenAmount.trim();
    const parsedAmount = amount === '' ? null : Number(amount);
    if (parsedAmount !== null && !Number.isFinite(parsedAmount)) {
      setErrorMsg('Amount stolen must be a number, or left blank if unknown.');
      return;
    }

    setIsSubmitting(true);
    try {
      const record = await dbService.addScamWallet({
        wallet_address: parsed.address,
        network,
        scam_category: category,
        // Blank fields are stored as null rather than invented. 'Generic Scam',
        // 'Unknown' and 0.00 all read as recorded findings downstream -- the
        // threat table rendered a missing amount as "$0.00".
        impersonated_brand: impersonatedBrand.trim() || null,
        total_stolen_usd: parsedAmount,
        destination_entity: destinationEntity.trim() || null,
        destination_address: destination || null,
        notes: notes.trim() || null,
      });

      setSuccess(record?.storage === 'cloud' ? 'cloud' : 'local');
      if (onFlaggedSuccess) onFlaggedSuccess();
      setTimeout(() => {
        setSuccess(null);
        onClose();
      }, 2200);
    } catch (err) {
      console.error('Failed to flag scammer:', err);
      setErrorMsg(`The report could not be saved: ${err.message}`);
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
              <p className="text-xs text-slate-400">
                Submitted as an <b>unverified</b> report until a reviewer confirms it
              </p>
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
                placeholder="e.g. Atlas Capture, Binance (leave blank if unknown)"
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
                placeholder="e.g. Binance Deposit Cluster, OKX (blank if unknown)"
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

          {/* The old message claimed a Supabase save unconditionally, but
              addScamWallet falls back to this browser's storage whenever the
              cloud write is unavailable. */}
          {success === 'cloud' && (
            <div className="p-3 rounded-xl bg-emerald-950/60 border border-emerald-500/40 text-emerald-300 flex items-start space-x-2">
              <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5" />
              <span>
                Saved to the shared blocklist as an unverified report. It will screen
                payouts immediately and stays unverified until a reviewer confirms it.
              </span>
            </div>
          )}
          {success === 'local' && (
            <div className="p-3 rounded-xl bg-amber-950/50 border border-amber-500/40 text-amber-200 flex items-start space-x-2">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
              <span>
                Saved <b>in this browser only</b> — the shared database was not reachable,
                so no one else can see this report. Configure Supabase to publish it.
              </span>
            </div>
          )}
          {errorMsg && (
            <div className="p-3 rounded-xl bg-red-950/50 border border-red-500/40 text-red-200 flex items-start space-x-2">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
              <span className="break-all font-sans">{errorMsg}</span>
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
