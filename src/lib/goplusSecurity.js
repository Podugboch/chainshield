/**
 * GoPlus Security Multi-Chain Client
 * Live Token & Address Security Scanner with False-Positive Prevention Tiers
 */

export const GOPLUS_CHAINS = {
  ethereum: { id: '1', name: 'Ethereum Mainnet' },
  bsc: { id: '56', name: 'BNB Smart Chain (BSC)' },
  polygon: { id: '137', name: 'Polygon (PoS)' },
  arbitrum: { id: '42161', name: 'Arbitrum One' },
  avalanche: { id: '43114', name: 'Avalanche C-Chain' },
  base: { id: '8453', name: 'Base' },
  optimism: { id: '10', name: 'Optimism' }
};

const GOPLUS_TIMEOUT_MS = 8000;

/**
 * Fetch JSON with a deadline, returning `{ payload, error }`.
 *
 * The error is returned rather than swallowed. Both queries used to answer
 * `null` for "the API said this address is clean" and for "the API never
 * replied", and the caller could not tell them apart -- so an outage scored
 * every address as SAFE. There is no default on fetch, either, so a stalled
 * endpoint hung the whole scan.
 */
async function fetchGoPlus(url, label) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), GOPLUS_TIMEOUT_MS);
  try {
    const resp = await fetch(url, {
      headers: { Accept: 'application/json' },
      signal: controller.signal,
    });
    if (!resp.ok) return { payload: null, error: `${label} returned HTTP ${resp.status}` };
    const data = await resp.json();
    // GoPlus signals its own errors in the body with a non-1 code.
    if (data?.code !== undefined && Number(data.code) !== 1) {
      return { payload: null, error: `${label}: ${data.message || `code ${data.code}`}` };
    }
    return { payload: data, error: null };
  } catch (err) {
    const reason = err.name === 'AbortError' ? 'timed out' : err.message;
    return { payload: null, error: `${label} unreachable (${reason})` };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Query GoPlus Token Security (Honeypot, Buy/Sell Tax, Open Source, Ownership)
 */
export async function queryGoPlusTokenSecurity(chainId, contractAddress) {
  const cleanAddr = contractAddress.trim().toLowerCase();
  const url = `https://api.gopluslabs.io/api/v1/token_security/${chainId}?contract_addresses=${cleanAddr}`;
  const { payload, error } = await fetchGoPlus(url, 'GoPlus token security');
  return { data: payload?.result?.[cleanAddr] || null, error };
}

/**
 * Query GoPlus Address Security (Phishing, Theft, Blacklists, Mixers)
 */
export async function queryGoPlusAddressSecurity(chainId, walletAddress) {
  const cleanAddr = walletAddress.trim().toLowerCase();
  const url = `https://api.gopluslabs.io/api/v1/address_security/${cleanAddr}?chain_id=${chainId}`;
  const { payload, error } = await fetchGoPlus(url, 'GoPlus address security');
  return { data: payload?.result || null, error };
}

/**
 * Comprehensive Multi-Chain GoPlus Audit with Granular False-Positive Prevention
 */
export async function scanGoPlusAsset(rawTarget, networkKey = 'ethereum') {
  const target = rawTarget.trim();
  const net = GOPLUS_CHAINS[networkKey] || GOPLUS_CHAINS.ethereum;
  const chainId = net.id;

  if (!target.startsWith('0x') || target.length !== 42) {
    return null;
  }

  // Run both checks in parallel
  const [tokenResult, addressResult] = await Promise.all([
    queryGoPlusTokenSecurity(chainId, target),
    queryGoPlusAddressSecurity(chainId, target)
  ]);

  const tokenData = tokenResult.data;
  const addressData = addressResult.data;
  const dataGaps = [tokenResult.error, addressResult.error].filter(Boolean);

  const flags = [];
  let riskScore = 0;
  const isContract = Boolean(tokenData && (tokenData.token_name || tokenData.token_symbol));

  const metrics = {
    isContract,
    // Whether each feed actually returned a body. Without these the UI cannot
    // tell "the honeypot test passed" from "the honeypot test never ran", and
    // it rendered a green tick for both.
    hasTokenData: Boolean(tokenData),
    hasAddressData: Boolean(addressData),
    isHoneypot: false,
    isOpenSource: true,
    buyTax: 0,
    sellTax: 0,
    buyTaxPct: 0,
    sellTaxPct: 0,
    isMintable: false,
    cannotSellAll: false,
    isPhishing: false,
    isStealingAttack: false,
    isBlacklistDoubt: false,
    isMixerAssociated: false,
    tokenName: tokenData?.token_name || null,
    tokenSymbol: tokenData?.token_symbol || null
  };

  // 1. Token Security Evaluation
  if (tokenData) {
    metrics.isHoneypot = tokenData.is_honeypot === '1';
    metrics.isOpenSource = tokenData.is_open_source === '1';
    // GoPlus reports tax as a fraction: "0.05" is 5%, not 5. The comparison
    // below used to be `> 10`, which only fired at a 1000% tax -- so every
    // ordinary scam tax passed as clean. Both forms are kept: the fraction for
    // comparisons, the percentage for anything shown to a person.
    metrics.buyTax = parseFloat(tokenData.buy_tax || '0');
    metrics.sellTax = parseFloat(tokenData.sell_tax || '0');
    metrics.buyTaxPct = Number.isFinite(metrics.buyTax) ? metrics.buyTax * 100 : 0;
    metrics.sellTaxPct = Number.isFinite(metrics.sellTax) ? metrics.sellTax * 100 : 0;
    metrics.cannotSellAll = tokenData.cannot_sell_all === '1';
    metrics.isMintable = tokenData.is_mintable === '1';

    if (metrics.isHoneypot) {
      riskScore += 90;
      flags.push({
        type: 'HONEYPOT',
        severity: 'CRITICAL',
        title: 'Honeypot Contract Detected',
        description: 'Contract code prevents token holders from executing sell orders.'
      });
    }

    if (metrics.cannotSellAll) {
      riskScore += 50;
      flags.push({
        type: 'RESTRICTED_SELL',
        severity: 'HIGH',
        title: 'Restricted Token Liquidity',
        description: 'Contract imposes artificial constraints on selling token balances.'
      });
    }

    if (!metrics.isOpenSource && isContract) {
      riskScore += 25;
      flags.push({
        type: 'UNVERIFIED_SOURCE',
        severity: 'MEDIUM',
        title: 'Unverified Contract Source Code',
        description: 'Bytecode is hidden or not verified on block explorers.'
      });
    }

    if (metrics.buyTax > 0.10 || metrics.sellTax > 0.10) {
      riskScore += 30;
      flags.push({
        type: 'EXCESSIVE_TAX',
        severity: 'MEDIUM',
        title: 'Excessive Trading Tax',
        description: `Buy tax ${metrics.buyTaxPct.toFixed(1)}%, sell tax `
          + `${metrics.sellTaxPct.toFixed(1)}%. Above roughly 10% the token is `
          + 'usually extracting value from every trade.'
      });
    }
  }

  // 2. Address Threat Evaluation
  if (addressData) {
    metrics.isPhishing = addressData.phishing_activities === '1';
    metrics.isStealingAttack = addressData.stealing_attack === '1';
    metrics.isBlacklistDoubt = addressData.blacklist_doubt === '1';
    metrics.isMixerAssociated = addressData.money_laundering === '1' || addressData.mixer === '1';

    if (metrics.isPhishing) {
      riskScore += 85;
      flags.push({
        type: 'PHISHING_ACTIVITY',
        severity: 'CRITICAL',
        title: 'Reported Phishing Operator',
        description: 'Address has confirmed associations with malicious phishing websites.'
      });
    }

    if (metrics.isStealingAttack) {
      riskScore += 90;
      flags.push({
        type: 'STEALING_ATTACK',
        severity: 'CRITICAL',
        title: 'Exploit / Wallet Drainer Signature',
        description: 'Address involved in automated asset theft or sweep scripts.'
      });
    }

    if (metrics.isBlacklistDoubt) {
      riskScore += 75;
      flags.push({
        type: 'ISSUER_BLACKLIST',
        severity: 'HIGH',
        title: 'Stablecoin Issuer Flag',
        description: 'Address flagged or blacklisted by centralized asset issuers.'
      });
    }

    if (metrics.isMixerAssociated) {
      riskScore += 35;
      flags.push({
        type: 'MIXER_ASSOCIATED',
        severity: 'MEDIUM',
        title: 'Privacy Mixer / Laundering Link',
        description: 'Direct transaction interactions with Tornado Cash or crypto mixers.'
      });
    }
  }

  // 3. Granular Risk Tiers to Guard Against False Positives
  riskScore = Math.min(100, Math.max(0, riskScore));

  // A zero here means "nothing in these feeds matched", which is not the same
  // claim as "safe" -- and if a feed did not answer at all, not even that much
  // has been established.
  const degraded = dataGaps.length > 0;
  let riskLevel = degraded ? 'UNKNOWN' : 'NO THREATS FOUND';
  let riskBadgeColor = degraded ? 'slate' : 'emerald';

  if (riskScore >= 75) {
    riskLevel = 'CRITICAL MALICIOUS';
    riskBadgeColor = 'red';
  } else if (riskScore >= 45) {
    riskLevel = 'HIGH RISK';
    riskBadgeColor = 'orange';
  } else if (riskScore >= 20) {
    riskLevel = 'SUSPICIOUS';
    riskBadgeColor = 'amber';
  } else if (riskScore > 0) {
    riskLevel = 'LOW RISK';
    riskBadgeColor = 'sky';
  }

  return {
    target,
    networkName: net.name,
    chainId,
    isContract,
    riskScore,
    riskLevel,
    riskBadgeColor,
    flags,
    metrics,
    hasThreats: flags.length > 0,
    dataGaps,
    degraded,
    caveat: degraded
      ? 'One or more GoPlus feeds did not answer, so this audit is incomplete.'
      : 'No match in the GoPlus feeds queried. That is not a guarantee the asset is safe.',
  };
}
