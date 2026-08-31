import { classifyUrlML } from './mlPhishingClassifier';

export const KNOWN_TRUSTED_BRANDS = [
  { name: 'Atlas Capture', domains: ['atlascapture.com', 'atlascapture.io', 'app.atlascapture.com'] },
  { name: 'Binance', domains: ['binance.com', 'binance.us'] },
  { name: 'MetaMask', domains: ['metamask.io', 'metamask.app'] },
  { name: 'Coinbase', domains: ['coinbase.com'] },
  { name: 'Tether / USDT', domains: ['tether.to'] },
  { name: 'Google', domains: ['google.com', 'accounts.google.com'] },
  { name: 'Microsoft', domains: ['microsoft.com', 'login.microsoftonline.com'] },
  { name: 'PayPal', domains: ['paypal.com'] }
];

export const SUSPICIOUS_TLDS = [
  '.top', '.xyz', '.icu', '.cam', '.cfd', '.sbs', '.buzz', '.monster', '.rest', '.tk', '.ml', '.ga', '.cf', '.gq', '.work', '.click'
];

export const PHISHING_KEYWORDS = [
  'verify', 'urgent', 'update-wallet', 'payout-verify', 'suspended', 
  'claim', 'kyc-update', 'login-security', 'authenticate', 'bonus-claim',
  'wallet-connect', 'action-required', 'account-blocked', 'billing-confirm'
];

export function levenshteinDistance(s1, s2) {
  if (s1.length < s2.length) return levenshteinDistance(s2, s1);
  if (s2.length === 0) return s1.length;
  
  let previousRow = Array.from({ length: s2.length + 1 }, (_, i) => i);
  for (let i = 0; i < s1.length; i++) {
    const currentRow = [i + 1];
    for (let j = 0; j < s2.length; j++) {
      const insertions = previousRow[j + 1] + 1;
      const deletions = currentRow[j] + 1;
      const substitutions = previousRow[j] + (s1[i] !== s2[j] ? 1 : 0);
      currentRow.push(Math.min(insertions, deletions, substitutions));
    }
    previousRow = currentRow;
  }
  return previousRow[previousRow.length - 1];
}

export function analyzeUrl(rawUrl) {
  let formattedUrl = rawUrl.trim();
  if (!formattedUrl.startsWith('http://') && !formattedUrl.startsWith('https://')) {
    formattedUrl = 'https://' + formattedUrl;
  }

  let parsed;
  try {
    parsed = new URL(formattedUrl);
  } catch {
    return {
      isValid: false,
      riskScore: 100,
      riskLevel: 'MALICIOUS',
      reasons: [{ category: 'Structure', severity: 'critical', text: 'Malformed URL structure' }],
      recommendations: ['Do NOT navigate to this address.']
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  const fullUrl = parsed.toString().toLowerCase();

  // 1. Run PhiUSIIL ML Ensemble Classifier
  const mlResult = classifyUrlML(formattedUrl);

  let riskScore = mlResult.mlRiskScore;
  const reasons = [];
  const flags = [];
  let impersonatedBrand = null;

  // Add ML Key Drivers
  mlResult.keyDrivers.forEach(driver => {
    reasons.push({
      category: 'PhiUSIIL ML Feature',
      severity: 'medium',
      text: driver
    });
  });

  // 2. High-Precision Brand Impersonation & Typosquatting Check
  const cleanHost = hostname.replace(/[-_.]/g, '');
  for (const brand of KNOWN_TRUSTED_BRANDS) {
    const isOfficial = brand.domains.some(d => hostname === d || hostname.endsWith('.' + d));
    const brandSlug = brand.name.toLowerCase().replace(/[^a-z0-9]/g, '');

    if (!isOfficial) {
      if (hostname.includes(brandSlug) || cleanHost.includes(brandSlug)) {
        riskScore = Math.max(riskScore, 95);
        impersonatedBrand = brand.name;
        reasons.unshift({
          category: 'Brand Impersonation',
          severity: 'critical',
          text: `Critical: URL claims to be '${brand.name}' but is hosted on an unofficial rogue domain (${hostname})!`
        });
        flags.push('BRAND_IMPERSONATION');
      } else {
        const dist = levenshteinDistance(brandSlug, cleanHost.slice(0, brandSlug.length + 3));
        if (dist > 0 && dist <= 2) {
          riskScore = Math.max(riskScore, 85);
          impersonatedBrand = brand.name;
          reasons.unshift({
            category: 'Typosquatting',
            severity: 'critical',
            text: `Typosquatting detected: '${hostname}' visually mimics '${brand.name}' with slight character mutations.`
          });
          flags.push('TYPOSQUATTING');
        }
      }
    }
  }

  // 3. TLD Verification
  const matchedTld = SUSPICIOUS_TLDS.find(tld => hostname.endsWith(tld));
  if (matchedTld) {
    riskScore = Math.min(100, riskScore + 15);
    reasons.push({
      category: 'Domain Registry',
      severity: 'medium',
      text: `High-risk throwaway TLD (${matchedTld}) associated with disposable phishing campaigns.`
    });
    flags.push('SUSPICIOUS_TLD');
  }

  // 4. Keyword Triggers
  const foundKeywords = PHISHING_KEYWORDS.filter(kw => fullUrl.includes(kw));
  if (foundKeywords.length > 0) {
    riskScore = Math.min(100, riskScore + 15);
    reasons.push({
      category: 'Deceptive Path',
      severity: 'medium',
      text: `Deceptive call-to-action keywords detected: [${foundKeywords.join(', ')}]`
    });
    flags.push('DECEPTIVE_KEYWORDS');
  }

  riskScore = Math.min(100, Math.max(0, riskScore));

  let riskLevel = 'SAFE';
  if (riskScore >= 60) riskLevel = 'MALICIOUS';
  else if (riskScore >= 25) riskLevel = 'SUSPICIOUS';

  const recommendations = [];
  if (riskLevel === 'MALICIOUS') {
    recommendations.push('🚨 DO NOT click or enter credentials/passwords on this link.');
    recommendations.push('🔒 If you already entered login details, immediately reset your password on the legitimate platform.');
    recommendations.push('🛡️ Inspect and remove any unauthorized wallet address modifications on your profile.');
  } else if (riskLevel === 'SUSPICIOUS') {
    recommendations.push('⚠️ Verify the sender domain with official support before proceeding.');
    recommendations.push('🔎 Avoid connecting Web3 wallets or approving signature requests.');
  } else {
    recommendations.push('✅ No obvious automated phishing heuristics or ML risk signatures triggered.');
  }

  return {
    isValid: true,
    url: formattedUrl,
    hostname,
    protocol: parsed.protocol,
    riskScore,
    riskLevel,
    impersonatedBrand,
    reasons,
    flags,
    recommendations,
    mlResult,
    timestamp: new Date().toISOString()
  };
}

export function analyzeMessage(text) {
  if (!text || text.trim().length === 0) return null;

  let riskScore = 0;
  const reasons = [];
  const flags = [];
  const lowerText = text.toLowerCase();

  const urgencyTriggers = [
    'immediate action', 'suspended within 24 hours', 'within 12 hours', 'urgent update', 
    'account termination', 'verify immediately', 'funds frozen', 'failure to respond'
  ];
  const matchedUrgency = urgencyTriggers.filter(t => lowerText.includes(t));
  if (matchedUrgency.length > 0) {
    riskScore += 35;
    reasons.push({
      category: 'Urgency Manipulation',
      severity: 'high',
      text: `High-pressure psychological urgency detected: "${matchedUrgency[0]}"`
    });
    flags.push('URGENCY_MANIPULATION');
  }

  const walletTriggers = [
    'update payout address', 'change wallet', 'usdt address', 'erc-20', 'erc20', 
    'connect metamask', 're-link wallet', 'pending withdrawal', 'payment hold'
  ];
  const matchedWallet = walletTriggers.filter(t => lowerText.includes(t));
  if (matchedWallet.length > 0) {
    riskScore += 35;
    reasons.push({
      category: 'Payment Redirection Attempt',
      severity: 'critical',
      text: `Attempts to solicit or alter payout / cryptocurrency wallet credentials: [${matchedWallet.join(', ')}]`
    });
    flags.push('PAYOUT_MANIPULATION');
  }

  const urlRegex = /(https?:\/\/[^\s]+)/g;
  const extractedUrls = text.match(urlRegex) || [];
  let urlScans = [];
  if (extractedUrls.length > 0) {
    urlScans = extractedUrls.map(u => analyzeUrl(u));
    const highestUrlScore = Math.max(...urlScans.map(s => s.riskScore));
    riskScore += Math.floor(highestUrlScore * 0.5);
    if (highestUrlScore >= 60) {
      reasons.push({
        category: 'Malicious Embedded Links',
        severity: 'critical',
        text: `Message contains ${extractedUrls.length} link(s) with high phishing probability.`
      });
      flags.push('MALICIOUS_EMBEDDED_LINK');
    }
  }

  if (lowerText.includes('atlas capture') || lowerText.includes('atlascapture')) {
    if (matchedWallet.length > 0 || matchedUrgency.length > 0 || extractedUrls.length > 0) {
      riskScore += 25;
      reasons.push({
        category: 'Platform Impersonation',
        severity: 'high',
        text: 'Explicitly targets Atlas Capture contractors/users with credential/payout modification prompts.'
      });
      flags.push('ATLAS_CAPTURE_TARGETED');
    }
  }

  riskScore = Math.min(100, riskScore);
  let riskLevel = 'SAFE';
  if (riskScore >= 60) riskLevel = 'MALICIOUS';
  else if (riskScore >= 25) riskLevel = 'SUSPICIOUS';

  return {
    rawLength: text.length,
    riskScore,
    riskLevel,
    reasons,
    flags,
    extractedUrls: urlScans,
    timestamp: new Date().toISOString()
  };
}
