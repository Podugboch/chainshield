import { createClient } from '@supabase/supabase-js';
import { validateAddress } from './evm.js';

const cleanUrl = (url) => {
  if (!url) return '';
  return url.trim().replace(/\/rest\/v1\/?$/, '').replace(/\/+$/, '');
};

const getSupabaseConfig = () => {
  const localUrl = localStorage.getItem('chainshield_supabase_url');
  const localKey = localStorage.getItem('chainshield_supabase_key');

  const rawUrl = localUrl || import.meta.env.VITE_SUPABASE_URL || '';
  const supabaseUrl = cleanUrl(rawUrl);
  const supabaseAnonKey = (localKey || import.meta.env.VITE_SUPABASE_ANON_KEY || '').trim();

  return { supabaseUrl, supabaseAnonKey };
};

const { supabaseUrl, supabaseAnonKey } = getSupabaseConfig();

export const isSupabaseConfigured = Boolean(supabaseUrl && supabaseAnonKey);

export const supabase = isSupabaseConfigured
  ? createClient(supabaseUrl, supabaseAnonKey)
  : null;

/**
 * Every cloud row is owned by an auth uid, because that is what the RLS
 * policies in supabase/schema.sql match on. Without a session the anon key can
 * read the public blocklist and nothing else -- scans and case files stay in
 * this browser. That is the intended failure mode, not a broken one: a case
 * file names a real victim and a real loss.
 *
 * Anonymous sign-in gives a durable uid with no login screen. It has to be
 * switched on once per project (Authentication -> Sign In / Providers ->
 * Anonymous). If it is off, this resolves to null and the app runs local-only.
 */
export const cloudStatus = {
  configured: isSupabaseConfigured,
  session: 'unknown', // 'active' | 'anonymous-disabled' | 'error' | 'none'
  ownerId: null,
  detail: isSupabaseConfigured ? '' : 'No Supabase URL/key set - running on browser storage.',
};

let ownerIdPromise = null;

/** Resolve (once) to this browser's auth uid, or null if there is no session. */
function resolveOwnerId() {
  if (!supabase) return Promise.resolve(null);
  if (ownerIdPromise) return ownerIdPromise;

  ownerIdPromise = (async () => {
    try {
      const { data: { session } } = await supabase.auth.getSession();
      if (session?.user?.id) {
        cloudStatus.session = 'active';
        cloudStatus.ownerId = session.user.id;
        cloudStatus.detail = 'Signed in - cloud sync active.';
        return session.user.id;
      }

      const { data, error } = await supabase.auth.signInAnonymously();
      if (error || !data?.user?.id) {
        cloudStatus.session = 'anonymous-disabled';
        cloudStatus.detail =
          'Connected, but no session could be created. Enable Anonymous sign-in in '
          + 'Supabase (Authentication -> Sign In / Providers) or add a real login. '
          + 'Scans and cases stay in this browser until then.';
        return null;
      }

      cloudStatus.session = 'active';
      cloudStatus.ownerId = data.user.id;
      cloudStatus.detail = 'Anonymous session - cloud sync active.';
      return data.user.id;
    } catch (e) {
      cloudStatus.session = 'error';
      cloudStatus.detail = `Auth unreachable: ${e.message}`;
      return null;
    }
  })();

  return ownerIdPromise;
}

/** True only when a write can actually satisfy the owner_id RLS check. */
async function canWriteCloud() {
  return Boolean(supabase && (await resolveOwnerId()));
}

export async function getCloudStatus() {
  await resolveOwnerId();
  return { ...cloudStatus };
}

const LOCAL_STORAGE_KEYS = {
  SCANS: 'chainshield_scans',
  WALLETS: 'chainshield_wallets',
  CASES: 'chainshield_cases',
};

function readLocal(key, fallback = []) {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : fallback;
  } catch {
    // Corrupt or hand-edited storage should not take the page down.
    return fallback;
  }
}

function writeLocal(key, value) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch (e) {
    console.warn(`Local persist failed for ${key}:`, e.message);
  }
}

/**
 * Local demo data. This is the project's own showcase case, kept so the
 * forensics views have something to render before a real scan is run. It ships
 * in the JS bundle, so treat it as published: do not add a real victim's name,
 * email or anything else you would not put on the repo's front page.
 */
const INITIAL_CASES = [
  {
    id: 'case-atlas-001',
    created_at: '2026-08-28T12:00:00Z',
    title: 'Atlas Capture Unauthorized Payout Redirection',
    platform_name: 'Atlas Capture',
    victim_name: 'Platform Contractor',
    amount_lost_usd: 146.07,
    // USDC, not USDT. The receipt for the tx below carries the Transfer log on
    // 0xA0b8...eB48 (Circle's USDC). The distinction decides which issuer a
    // freeze request has to go to -- Tether cannot act on USDC.
    token_symbol: 'USDC (ERC-20)',
    scammer_intermediary_wallet: '0xd23Ac29C1e1949D0c5864B4a23a01cc3e4dd236b',
    destination_wallet: '0x28C6c06298d514Db089934071355E5743bf21d60',
    destination_entity: 'Binance (KYC Deposit)',
    tx_hash: '0x44e5dbb257694dd3297e3a24808a6098f2bce9816bc9b202879104dccec911e7',
    phishing_url: 'https://atlas-capture-support.top/payout-verify',
    status: 'EVIDENCE_COLLECTED',
    dossier_notes: 'Attacker phished contractor credentials via impersonation link, modified ERC-20 payout wallet, received 146.07 USDC, and moved the funds onward. The onward hop is recorded below as observed, not confirmed by the exchange.',
    is_local_demo: true,
  },
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
    verified: true,
    notes: 'Used as intermediary collector for stolen Atlas Capture contract payouts.',
  },
];

export const dbService = {
  async saveScan(scanData) {
    if (await canWriteCloud()) {
      try {
        const { data, error } = await supabase
          .from('threat_scans')
          .insert([{ ...scanData, owner_id: cloudStatus.ownerId }])
          .select();
        if (!error && data?.[0]) return { ...data[0], storage: 'cloud' };
        if (error) console.warn('Supabase scan insert rejected, saving locally:', error.message);
      } catch (e) {
        console.warn('Supabase insert error, saving locally:', e.message);
      }
    }
    const current = readLocal(LOCAL_STORAGE_KEYS.SCANS) || [];
    const record = {
      ...scanData,
      id: `scan-${Date.now()}`,
      created_at: new Date().toISOString(),
      storage: 'local',
    };
    writeLocal(LOCAL_STORAGE_KEYS.SCANS, [record, ...current]);
    return record;
  },

  async getScans() {
    if (await canWriteCloud()) {
      try {
        const { data, error } = await supabase
          .from('threat_scans')
          .select('*')
          .order('created_at', { ascending: false })
          .limit(200);
        // An empty cloud result is an answer, not a miss. Falling through to
        // local storage here used to resurrect stale rows after a cloud wipe.
        if (!error) return data ?? [];
        console.warn('Supabase scan query failed:', error.message);
      } catch (e) {
        console.warn('Supabase query error:', e.message);
      }
    }
    return readLocal(LOCAL_STORAGE_KEYS.SCANS) || [];
  },

  /** The blocklist is world-readable, so this works without a session. */
  async getScamWallets() {
    if (supabase) {
      try {
        const { data, error } = await supabase
          .from('scam_wallets')
          .select('*')
          .order('created_at', { ascending: false })
          .limit(500);
        if (!error) return data ?? [];
        console.warn('Supabase wallet query failed:', error.message);
      } catch (e) {
        console.warn('Supabase query error:', e.message);
      }
    }
    const local = readLocal(LOCAL_STORAGE_KEYS.WALLETS);
    if (!local) {
      writeLocal(LOCAL_STORAGE_KEYS.WALLETS, INITIAL_WALLETS);
      return INITIAL_WALLETS;
    }
    return local;
  },

  async isWalletFlagged(address) {
    if (!address) return null;
    const clean = address.trim().toLowerCase();

    if (supabase) {
      try {
        const { data, error } = await supabase
          .from('scam_wallets')
          .select('*')
          .ilike('wallet_address', clean)
          .maybeSingle();
        if (!error && data) return data;
      } catch (e) {
        console.warn('Supabase flag check error:', e.message);
      }
    }

    const all = await this.getScamWallets();
    return all.find((w) => w.wallet_address?.toLowerCase() === clean) || null;
  },

  /**
   * Pre-payout check. Returns one of four statuses -- INVALID (the address is
   * not well-formed, nothing was checked), BLOCKED (verified report), REVIEW
   * (unverified community report) or APPROVED (no match, which is not the same
   * as safe). An unverified report is a reason to slow down, not proof of
   * fraud, and the caller needs to be able to tell the difference.
   */
  async verifyPayoutAddress(address, platformName = 'Platform Payout') {
    // Check the address is well-formed before checking who it belongs to. A
    // truncated or mis-typed destination used to fall through to "no matching
    // blocklist record" and come back PAYMENT_PERMITTED -- which is the wrong
    // answer twice over: the blocklist was never meaningfully queried, and
    // sending to a bad address loses the funds with no fraud involved at all.
    const parsed = validateAddress(address);
    if (!parsed.ok) {
      return {
        isAllowed: false,
        status: 'INVALID',
        decision: 'PAYMENT_HELD_INVALID_ADDRESS',
        verified: false,
        platformName,
        reason: `${parsed.reason} No blocklist check was performed.`,
        checksumSuggestion: parsed.checksum || null,
        timestamp: new Date().toISOString(),
      };
    }

    const flaggedRecord = await this.isWalletFlagged(parsed.address);
    if (flaggedRecord) {
      const verified = flaggedRecord.verified !== false;
      return {
        isAllowed: false,
        status: verified ? 'BLOCKED' : 'REVIEW',
        decision: verified ? 'PAYMENT_INTERCEPTED_AND_BLOCKED' : 'PAYMENT_HELD_FOR_REVIEW',
        verified,
        platformName,
        reason: verified
          ? `Address is blacklisted in ChainShield for ${flaggedRecord.scam_category}`
            + `${flaggedRecord.impersonated_brand ? ` (impersonating ${flaggedRecord.impersonated_brand})` : ''}.`
          : `Address has an unverified community report for ${flaggedRecord.scam_category}. `
            + 'Confirm independently before releasing funds.',
        flaggedRecord,
        timestamp: new Date().toISOString(),
      };
    }

    return {
      isAllowed: true,
      status: 'APPROVED',
      decision: 'PAYMENT_PERMITTED',
      verified: false,
      platformName,
      address: parsed.address,
      // An all-lowercase address carries no EIP-55 checksum, so nothing here
      // could have caught a single wrong character in it.
      checksumVerified: parsed.checksumVerified,
      // Absence of evidence, stated as such. The previous wording implied the
      // address had been cleared.
      reason: parsed.checksumVerified
        ? 'No matching blocklist record. This is not a guarantee the address is safe.'
        : 'No matching blocklist record. This is not a guarantee the address is safe, and '
          + 'the address is all-lowercase so it carries no checksum - a mistyped character '
          + 'in it cannot be detected.',
      timestamp: new Date().toISOString(),
    };
  },

  async addScamWallet(walletData) {
    if (await canWriteCloud()) {
      try {
        // verified is forced false: the RLS policy rejects a submission that
        // arrives pre-marked as verified, and it should.
        const { data, error } = await supabase
          .from('scam_wallets')
          .insert([{ ...walletData, owner_id: cloudStatus.ownerId, verified: false }])
          .select();
        // `storage` is returned so the UI can stop claiming a shared save when
        // the row only reached this browser.
        if (!error && data?.[0]) return { ...data[0], storage: 'cloud' };
        if (error) console.warn('Supabase wallet insert rejected, saving locally:', error.message);
      } catch (e) {
        console.warn('Supabase insert error:', e.message);
      }
    }
    const current = await this.getScamWallets();
    const record = {
      ...walletData,
      id: `wal-${Date.now()}`,
      created_at: new Date().toISOString(),
      verified: false,
      storage: 'local',
    };
    writeLocal(LOCAL_STORAGE_KEYS.WALLETS, [record, ...current]);
    return record;
  },

  async getCases() {
    if (await canWriteCloud()) {
      try {
        const { data, error } = await supabase
          .from('incident_cases')
          .select('*')
          .order('created_at', { ascending: false })
          .limit(200);
        if (!error) return data ?? [];
        console.warn('Supabase case query failed:', error.message);
      } catch (e) {
        console.warn('Supabase query error:', e.message);
      }
    }
    const local = readLocal(LOCAL_STORAGE_KEYS.CASES);
    if (!local) {
      writeLocal(LOCAL_STORAGE_KEYS.CASES, INITIAL_CASES);
      return INITIAL_CASES;
    }
    return local;
  },

  async saveCase(caseData) {
    // The local demo row has a string id, not a uuid, and no owner. Sending it
    // to Postgres fails the uuid cast; keep it local.
    const cloudEligible = !caseData.is_local_demo
      && (!caseData.id || /^[0-9a-f-]{36}$/i.test(caseData.id));

    if (cloudEligible && (await canWriteCloud())) {
      try {
        const { data, error } = await supabase
          .from('incident_cases')
          .upsert([{ ...caseData, owner_id: cloudStatus.ownerId }])
          .select();
        if (!error && data?.[0]) return data[0];
        if (error) console.warn('Supabase case upsert rejected, saving locally:', error.message);
      } catch (e) {
        console.warn('Supabase upsert error:', e.message);
      }
    }

    const current = await this.getCases();
    const existsIndex = current.findIndex((c) => c.id === caseData.id);
    let updated;
    if (existsIndex >= 0) {
      updated = [...current];
      updated[existsIndex] = {
        ...updated[existsIndex],
        ...caseData,
        updated_at: new Date().toISOString(),
      };
    } else {
      updated = [{
        ...caseData,
        id: caseData.id || `case-${Date.now()}`,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      }, ...current];
    }
    writeLocal(LOCAL_STORAGE_KEYS.CASES, updated);
    return updated[existsIndex >= 0 ? existsIndex : 0];
  },

  /**
   * Aggregate, k-anonymised domain intel. Backed by the threat_domain_stats
   * SECURITY DEFINER function, which is the only path that sees other people's
   * scans -- and it returns counts, never scan bodies.
   */
  async getDomainStats(minReports = 3) {
    if (!supabase) return [];
    try {
      const { data, error } = await supabase.rpc('threat_domain_stats', { min_reports: minReports });
      if (!error) return data ?? [];
      console.warn('Domain stats unavailable:', error.message);
    } catch (e) {
      console.warn('Domain stats error:', e.message);
    }
    return [];
  },
};

