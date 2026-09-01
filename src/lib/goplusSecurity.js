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

/**
 * Query GoPlus Token Security (Honeypot, Buy/Sell Tax, Open Source, Ownership)
 */
export async function queryGoPlusTokenSecurity(chainId, contractAddress) {
  const cleanAddr = contractAddress.trim().toLowerCase();
  const url = `https://api.gopluslabs.io/api/v1/token_security/${chainId}?contract_addresses=${cleanAddr}`;

  try {
    const resp = await fetch(url, { headers: { 'Accept': 'application/json' } });
    if (!resp.ok) return null;
    const data = await resp.json();
    return data?.result?.[cleanAddr] || null;
  } catch (err) {
    console.warn('GoPlus token security check note:', err.message);
    return null;
  }
}

/**
 * Query GoPlus Address Security (Phishing, Theft, Blacklists, Mixers)
 */
export async function queryGoPlusAddressSecurity(chainId, walletAddress) {
  const cleanAddr = walletAddress.trim().toLowerCase();
  const url = `https://api.gopluslabs.io/api/v1/address_security/${cleanAddr}?chain_id=${chainId}`;

  try {
    const resp = await fetch(url, { headers: { 'Accept': 'application/json' } });
    if (!resp.ok) return null;
    const data = await resp.json();
    return data?.result || null;
  } catch (err) {
    console.warn('GoPlus address security check note:', err.message);
    return null;
  }
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
  const [tokenData, addressData] = await Promise.all([
    queryGoPlusTokenSecurity(chainId, target),
    queryGoPlusAddressSecurity(chainId, target)
  ]);

  const flags = [];
  let riskScore = 0;
  const isContract = Boolean(tokenData && (tokenData.token_name || tokenData.token_symbol));

  const metrics = {
    isContract,
    isHoneypot: false,
    isOpenSource: true,
    buyTax: 0,
    sellTax: 0,
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
    metrics.buyTax = parseFloat(tokenData.buy_tax || '0');
    metrics.sellTax = parseFloat(tokenData.sell_tax || '0');
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

    if (metrics.buyTax > 10 || metrics.sellTax > 10) {
      riskScore += 30;
      flags.push({
        type: 'EXCESSIVE_TAX',
        severity: 'MEDIUM',
        title: 'Excessive Trading Tax',
        description: `High slippage fee: Buy Tax ${metrics.buyTax}%, Sell Tax ${metrics.sellTax}%.`
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
  let riskLevel = 'SAFE';
  let riskBadgeColor = 'emerald';

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
    hasThreats: flags.length > 0
  };
}
