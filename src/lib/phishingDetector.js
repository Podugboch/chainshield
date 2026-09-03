/**
 * URL and message phishing analysis.
 *
 * Order of reasoning matters here. The brand relationship is resolved first,
 * against the registrable domain: a host the brand actually owns cannot be a
 * brand-impersonation attack however its structure scores, and a host that
 * places a brand name where the brand has no control is malicious however tidy
 * its structure looks. Structural heuristics only decide the cases in between.
 */
import { parseTarget, levenshtein } from './domainUtils.js';
import {
  detectBrandAbuse, KNOWN_TRUSTED_BRANDS, HIGH_RISK_SUFFIXES,
} from './brands.js';
import { scoreHeuristics, PHISHING_KEYWORDS } from './urlHeuristics.js';

export { KNOWN_TRUSTED_BRANDS, PHISHING_KEYWORDS };

/** Legacy dotted form kept for callers that expect ".xyz" rather than "xyz". */
export const SUSPICIOUS_TLDS = HIGH_RISK_SUFFIXES.map((s) => `.${s}`);
export const levenshteinDistance = levenshtein;

const MALICIOUS_AT = 60;
const SUSPICIOUS_AT = 30;

/** A domain on the verified list cannot be talked above this by structure alone. */
const VERIFIED_CEILING = 8;

export function riskLevelFor(score) {
  if (score >= MALICIOUS_AT) return 'MALICIOUS';
  if (score >= SUSPICIOUS_AT) return 'SUSPICIOUS';
  return 'SAFE';
}

function recommendationsFor(riskLevel, brand) {
  if (riskLevel === 'MALICIOUS') {
    return [
      'Do not enter credentials, seed phrases or wallet approvals on this page.',
      brand
        ? `Reach ${brand} by typing its address yourself, not through this link.`
        : 'Navigate to the service by typing its address yourself.',
      'If you already signed in, change that password now and revoke active sessions.',
      'If you approved a wallet transaction, revoke the token allowance before anything else.',
    ];
  }
  if (riskLevel === 'SUSPICIOUS') {
    return [
      'Confirm the domain with the service through a channel you already trust.',
      'Do not connect a wallet or approve signature requests from this page.',
    ];
  }
  return ['No brand-impersonation or structural phishing signals were found in this URL.'];
}

/** Score floors by brand-abuse class. A floor is a claim about the domain, not a tally. */
const BRAND_VERDICTS = {
  impersonation: { floor: 85, category: 'Brand Impersonation', flag: 'BRAND_IMPERSONATION' },
  confusable: { floor: 85, category: 'Homoglyph Lookalike', flag: 'HOMOGLYPH_SQUAT' },
  typo: { floor: 75, category: 'Typosquat', flag: 'TYPOSQUAT' },
};

export function analyzeUrl(rawUrl) {
  const target = parseTarget(rawUrl);

  if (!target.ok) {
    return {
      isValid: false,
      url: target.input,
      hostname: '',
      riskScore: 0,
      riskLevel: 'UNKNOWN',
      impersonatedBrand: null,
      reasons: [{
        category: 'Input',
        severity: 'medium',
        text: 'This is not a parseable web address, so there is nothing to check. '
          + 'Paste the full link, including the part before the first slash.',
      }],
      flags: ['UNPARSEABLE'],
      recommendations: ['Check the link for missing or extra characters and paste it again.'],
      heuristics: null,
      timestamp: new Date().toISOString(),
    };
  }

  const heuristics = scoreHeuristics(target);
  const abuse = detectBrandAbuse(target);

  const reasons = [];
  const flags = [];
  let riskScore = heuristics.score;
  let impersonatedBrand = null;

  if (abuse.status === 'official') {
    riskScore = Math.min(riskScore, VERIFIED_CEILING);
    reasons.push({
      category: 'Domain Ownership',
      severity: 'low',
      text: `${target.hostname} sits on ${abuse.brand}'s verified domain list, so no `
        + 'amount of odd-looking structure makes it an impersonation of itself.',
    });
    flags.push('VERIFIED_DOMAIN');
  } else if (abuse.status === 'brand-elsewhere') {
    reasons.push({ category: 'Domain Ownership', severity: 'low', text: `${abuse.evidence}.` });
    flags.push('BRAND_ON_OTHER_SUFFIX');
  } else if (abuse.status === 'impersonation' || abuse.status === 'squat') {
    const verdict = BRAND_VERDICTS[abuse.status === 'squat' ? abuse.kind : 'impersonation'];
    riskScore = Math.max(riskScore, verdict.floor);
    impersonatedBrand = abuse.brand;
    reasons.unshift({
      category: verdict.category,
      severity: 'critical',
      text: `Presents itself as ${abuse.brand} without being ${abuse.brand}: ${abuse.evidence}.`,
    });
    flags.push(verdict.flag);
  } else if (abuse.status === 'path-mention') {
    riskScore += 20;
    impersonatedBrand = abuse.brand;
    reasons.unshift({
      category: 'Unsupported Brand Claim',
      severity: 'high',
      text: `Invokes ${abuse.brand} from a host that has no connection to it — ${abuse.evidence}.`,
    });
    flags.push('BRAND_IN_PATH');
  }

  for (const signal of heuristics.signals) {
    reasons.push({
      category: 'URL Structure',
      severity: signal.severity,
      text: signal.text,
      id: signal.id,
      weight: signal.weight,
    });
    flags.push(signal.id);
  }

  riskScore = Math.min(100, Math.max(0, Math.round(riskScore)));
  const riskLevel = riskLevelFor(riskScore);

  return {
    isValid: true,
    url: target.href,
    hostname: target.hostname,
    displayHost: target.unicodeHost,
    registrableDomain: target.registrableDomain,
    protocol: `${target.scheme}:`,
    riskScore,
    riskLevel,
    impersonatedBrand,
    brandStatus: abuse.status,
    reasons,
    flags,
    recommendations: recommendationsFor(riskLevel, impersonatedBrand),
    heuristics,
    timestamp: new Date().toISOString(),
  };
}

const URGENCY_TRIGGERS = [
  'immediate action', 'suspended within 24 hours', 'within 12 hours', 'urgent update',
  'account termination', 'verify immediately', 'funds frozen', 'failure to respond',
  'final warning', 'act now', 'within the next hour', 'permanently closed',
];

const WALLET_TRIGGERS = [
  'update payout address', 'change wallet', 'usdt address', 'erc-20', 'erc20',
  'connect metamask', 're-link wallet', 'pending withdrawal', 'payment hold',
  'seed phrase', 'recovery phrase', 'private key', 'validate your wallet',
];

export function analyzeMessage(text) {
  if (!text || text.trim().length === 0) return null;

  const lowerText = text.toLowerCase();
  const reasons = [];
  const flags = [];
  let riskScore = 0;

  const matchedUrgency = URGENCY_TRIGGERS.filter((t) => lowerText.includes(t));
  if (matchedUrgency.length > 0) {
    riskScore += 35;
    reasons.push({
      category: 'Urgency Manipulation',
      severity: 'high',
      text: `Manufactured time pressure: "${matchedUrgency[0]}". A deadline is what stops `
        + 'someone checking the domain.',
    });
    flags.push('URGENCY_MANIPULATION');
  }

  const matchedWallet = WALLET_TRIGGERS.filter((t) => lowerText.includes(t));
  if (matchedWallet.length > 0) {
    riskScore += 40;
    reasons.push({
      category: 'Payment Redirection Attempt',
      severity: 'critical',
      text: `Solicits or rewrites payout credentials: [${matchedWallet.join(', ')}]. No `
        + 'legitimate platform asks for a seed phrase, and none needs you to change a '
        + 'payout address from a message.',
    });
    flags.push('PAYOUT_MANIPULATION');
  }

  const extractedUrls = text.match(/(https?:\/\/[^\s<>"')]+)/gi) || [];
  const urlScans = extractedUrls.map((u) => analyzeUrl(u));
  if (urlScans.length > 0) {
    const worst = urlScans.reduce((a, b) => (b.riskScore > a.riskScore ? b : a));
    riskScore += Math.floor(worst.riskScore * 0.6);
    if (worst.riskScore >= MALICIOUS_AT) {
      reasons.push({
        category: 'Malicious Embedded Link',
        severity: 'critical',
        text: `${worst.hostname} scores ${worst.riskScore}/100 on its own`
          + `${worst.impersonatedBrand ? ` and impersonates ${worst.impersonatedBrand}` : ''}.`,
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
        text: 'Targets Atlas Capture contractors specifically, combined with a credential '
          + 'or payout prompt — the pattern behind the case already on file here.',
      });
      flags.push('ATLAS_CAPTURE_TARGETED');
    }
  }

  riskScore = Math.min(100, riskScore);
  const riskLevel = riskLevelFor(riskScore);

  return {
    rawLength: text.length,
    riskScore,
    riskLevel,
    reasons,
    flags,
    extractedUrls: urlScans,
    recommendations: recommendationsFor(riskLevel, null),
    timestamp: new Date().toISOString(),
  };
}
