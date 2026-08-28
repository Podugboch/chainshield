import { createClient } from '@supabase/supabase-js';

// Read config from env or localStorage if user configured it dynamically
const getSupabaseConfig = () => {
  const localUrl = localStorage.getItem('chainshield_supabase_url');
  const localKey = localStorage.getItem('chainshield_supabase_key');

  const supabaseUrl = localUrl || import.meta.env.VITE_SUPABASE_URL || '';
  const supabaseAnonKey = localKey || import.meta.env.VITE_SUPABASE_ANON_KEY || '';

  return { supabaseUrl, supabaseAnonKey };
};

const { supabaseUrl, supabaseAnonKey } = getSupabaseConfig();

export const isSupabaseConfigured = Boolean(supabaseUrl && supabaseAnonKey);

export const supabase = isSupabaseConfigured 
  ? createClient(supabaseUrl, supabaseAnonKey)
  : null;

// Local fallback store to allow instant offline/zero-config operation
const LOCAL_STORAGE_KEYS = {
  SCANS: 'chainshield_scans',
  WALLETS: 'chainshield_wallets',
  CASES: 'chainshield_cases'
};

const INITIAL_CASES = [
  {
    id: 'case-atlas-001',
    created_at: '2026-08-28T12:00:00Z',
    title: 'Atlas Capture Unauthorized Payout Redirection',
    platform_name: 'Atlas Capture',
    victim_name: 'Platform Contractor',
    amount_lost_usd: 146.07,
    token_symbol: 'USDT (ERC-20)',
    scammer_intermediary_wallet: '0xd23Ac29C1e1949D0c5864B4a23a01cc3e4dd236b',
    destination_wallet: '0x28C6c06298d514Db089934071355E5743bf21d60', // Binance Hot/Deposit Wallet
    destination_entity: 'Binance (KYC Deposit)',
    tx_hash: '0x44e5dbb257694dd3297e3a24808a6098f2bce9816bc9b202879104dccec911e7',
    phishing_url: 'https://atlas-capture-support.top/payout-verify',
    status: 'EVIDENCE_COLLECTED',
    dossier_notes: 'Attacker phished contractor credentials via impersonation link, modified ERC-20 payout wallet, received $146.07 USDT, and swept funds directly to Binance.'
  }
];

const INITIAL_WALLETS = [
  {
    id: 'wal-001',
    created_at: '2026-08-28T12:00:00Z',
    wallet_address: '0xd23Ac29C1e1949D0c5864B4a23a01cc3e4dd236b',
    network: 'Ethereum (ERC-20)',
    scam_category: 'Phishing / Payout Redirection',
    impersonated_brand: 'Atlas Capture',
    total_stolen_usd: 146.07,
    destination_entity: 'Binance',
    destination_address: '0x28C6c06298d514Db089934071355E5743bf21d60',
    notes: 'Used as intermediary collector for stolen Atlas Capture contract payouts.'
  }
];

export const dbService = {
  // Save a new scan record
  async saveScan(scanData) {
    if (supabase) {
      try {
        const { data, error } = await supabase.from('threat_scans').insert([scanData]).select();
        if (!error) return data[0];
      } catch (e) {
        console.warn('Supabase insert error, saving locally:', e);
      }
    }
    const current = JSON.parse(localStorage.getItem(LOCAL_STORAGE_KEYS.SCANS) || '[]');
    const record = { ...scanData, id: `scan-${Date.now()}`, created_at: new Date().toISOString() };
    localStorage.setItem(LOCAL_STORAGE_KEYS.SCANS, JSON.stringify([record, ...current]));
    return record;
  },

  // Get all threat scans
  async getScans() {
    if (supabase) {
      try {
        const { data, error } = await supabase.from('threat_scans').select('*').order('created_at', { ascending: false });
        if (!error && data?.length) return data;
      } catch (e) {
        console.warn('Supabase query error:', e);
      }
    }
    return JSON.parse(localStorage.getItem(LOCAL_STORAGE_KEYS.SCANS) || '[]');
  },

  // Get flagged scam wallets
  async getScamWallets() {
    if (supabase) {
      try {
        const { data, error } = await supabase.from('scam_wallets').select('*').order('created_at', { ascending: false });
        if (!error && data?.length) return data;
      } catch (e) {
        console.warn('Supabase query error:', e);
      }
    }
    const local = localStorage.getItem(LOCAL_STORAGE_KEYS.WALLETS);
    if (!local) {
      localStorage.setItem(LOCAL_STORAGE_KEYS.WALLETS, JSON.stringify(INITIAL_WALLETS));
      return INITIAL_WALLETS;
    }
    return JSON.parse(local);
  },

  // Add a scam wallet
  async addScamWallet(walletData) {
    if (supabase) {
      try {
        const { data, error } = await supabase.from('scam_wallets').insert([walletData]).select();
        if (!error) return data[0];
      } catch (e) {
        console.warn('Supabase insert error:', e);
      }
    }
    const current = await this.getScamWallets();
    const record = { ...walletData, id: `wal-${Date.now()}`, created_at: new Date().toISOString() };
    localStorage.setItem(LOCAL_STORAGE_KEYS.WALLETS, JSON.stringify([record, ...current]));
    return record;
  },

  // Get incident investigation cases
  async getCases() {
    if (supabase) {
      try {
        const { data, error } = await supabase.from('incident_cases').select('*').order('created_at', { ascending: false });
        if (!error && data?.length) return data;
      } catch (e) {
        console.warn('Supabase query error:', e);
      }
    }
    const local = localStorage.getItem(LOCAL_STORAGE_KEYS.CASES);
    if (!local) {
      localStorage.setItem(LOCAL_STORAGE_KEYS.CASES, JSON.stringify(INITIAL_CASES));
      return INITIAL_CASES;
    }
    return JSON.parse(local);
  },

  // Add/update case
  async saveCase(caseData) {
    if (supabase) {
      try {
        const { data, error } = await supabase.from('incident_cases').upsert([caseData]).select();
        if (!error) return data[0];
      } catch (e) {
        console.warn('Supabase upsert error:', e);
      }
    }
    const current = await this.getCases();
    const existsIndex = current.findIndex(c => c.id === caseData.id);
    let updated;
    if (existsIndex >= 0) {
      updated = [...current];
      updated[existsIndex] = { ...updated[existsIndex], ...caseData, updated_at: new Date().toISOString() };
    } else {
      const record = { ...caseData, id: caseData.id || `case-${Date.now()}`, created_at: new Date().toISOString(), updated_at: new Date().toISOString() };
      updated = [record, ...current];
    }
    localStorage.setItem(LOCAL_STORAGE_KEYS.CASES, JSON.stringify(updated));
    return caseData;
  }
};
