/**
 * Structural URL heuristics.
 *
 * These are hand-weighted rules, not a trained model, and the output is
 * deliberately named as such. Every weight below is justified by where the
 * signal sits in the URL: a digit run in the hostname is worth something, the
 * same digits in a path are worth nothing, and the previous version of this
 * file could not tell the difference.
 */
import {
  parseTarget, hasMixedScripts, shannonEntropy,
} from './domainUtils.js';
import { highRiskSuffix, freeHostingSuffix } from './brands.js';

export const PHISHING_KEYWORDS = [
  'verify', 'verification', 'urgent', 'suspended', 'blocked', 'restricted',
  'authenticate', 'signin', 'kyc', 'payout', 'bonus', 'airdrop', 'claim',
  'unlock', 'validate', 'recovery', 'restore', 'confirm', 'billing',
  'wallet-connect', 'connect-wallet', 'update-wallet', 'login-security',
  'secure-login', 'account-blocked', 'action-required', 'billing-confirm',
  'kyc-update', 'payout-verify', 'seed-phrase', 'private-key',
];

const NON_WORD = /[^\p{L}\p{N}]+/u;
const NON_WORD_GLOBAL = /[^\p{L}\p{N}]+/gu;

/**
 * Words that assert trustworthiness. Meaningless in a name anyone can register
 * for free, which is the only place they are scored.
 */
export const TRUST_WORDS = [
  'secure', 'service', 'services', 'support', 'account', 'accounts', 'official',
  'auth', 'portal', 'helpdesk', 'wallet', 'safe', 'protect', 'center', 'centre',
];

/** Split a string into comparable word tokens. */
function words(str) {
  return str.toLowerCase().split(NON_WORD).filter(Boolean);
}

/** Collapse every separator to a hyphen so multi-word keywords can be found. */
function hyphenated(str) {
  return str.toLowerCase().replace(NON_WORD_GLOBAL, '-');
}

/**
 * Keywords are matched as whole words, so "claim" no longer fires on
 * "proclaimed"; hyphenated phrases are matched against the separator-collapsed
 * form, so "wallet-connect" still fires on "/wallet_connect".
 */
function matchKeywords(str) {
  const bag = new Set(words(str));
  const joined = hyphenated(str);
  return PHISHING_KEYWORDS.filter((kw) => (
    kw.includes('-') ? joined.includes(kw) : bag.has(kw)
  ));
}

function ratio(count, total) {
  return total > 0 ? Number((count / total).toFixed(3)) : 0;
}

function countOf(str, re) {
  return (str.match(re) || []).length;
}

/** Measurable properties of a parsed URL. No judgement applied yet. */
export function extractFeatures(target) {
  const { hostname, path, query, publicSuffix, registrableLabel } = target;

  // The part of the host the registrant chose, suffix removed. Digits and
  // entropy only mean something here — never across the whole URL.
  const hostCore = publicSuffix && hostname.endsWith(`.${publicSuffix}`)
    ? hostname.slice(0, -(publicSuffix.length + 1))
    : hostname;

  const authority = hostname + path + query;
  const labels = [...target.subdomainLabels, target.registrableLabel];

  return {
    scheme: target.scheme,
    isHttps: target.scheme === 'https',
    urlLength: target.href.length,
    hostLength: hostname.length,
    hostCore,
    registrableDomain: target.registrableDomain,
    registrableLabel,
    publicSuffix,
    subdomainDepth: target.subdomainLabels.length,
    pathDepth: path.split('/').filter(Boolean).length,
    queryParams: target.url.searchParams ? [...target.url.searchParams.keys()].length : 0,
    hyphenCount: countOf(registrableLabel, /-/g),
    digitRatioHost: ratio(countOf(hostCore, /\d/g), hostCore.length),
    specialCharRatio: ratio(countOf(authority, /[^a-z0-9./-]/gi), authority.length),
    labelEntropy: shannonEntropy(registrableLabel),
    isIp: target.isIp,
    isPunycode: target.isPunycode,
    hasCredentials: Boolean(target.credentials),
    mixedScriptLabels: labels.filter((l) => l && hasMixedScripts(l)),
  };
}

/**
 * Score the structural signals. Returns an additive score capped at 100 plus
 * the individual signals so the UI can show what was actually measured.
 */
export function scoreHeuristics(target) {
  const f = extractFeatures(target);
  const signals = [];
  let score = 0;

  const add = (weight, severity, id, text) => {
    score += weight;
    signals.push({ id, weight, severity, text });
  };

  if (f.isIp) {
    add(40, 'critical', 'IP_HOST',
      'Connects to a bare IP address instead of a named host, so there is no '
      + 'certificate or registration record tying it to any organisation.');
  }
  if (f.hasCredentials) {
    add(30, 'high', 'AUTHORITY_CREDENTIALS',
      `Everything before the "@" is discarded by the browser: this request goes to ${target.hostname}.`);
  }
  if (f.mixedScriptLabels.length > 0) {
    add(25, 'high', 'MIXED_SCRIPT',
      `Hostname label "${f.mixedScriptLabels[0]}" mixes Latin with another alphabet, `
      + 'the standard way to build a name that reads as a brand but resolves elsewhere.');
  } else if (f.isPunycode) {
    add(12, 'medium', 'PUNYCODE',
      `Internationalised hostname; it renders as "${target.unicodeHost}".`);
  }

  if (f.subdomainDepth >= 3) {
    add(15, 'medium', 'DEEP_SUBDOMAIN',
      `${f.subdomainDepth} subdomain levels in front of ${f.registrableDomain} — depth is `
      + 'commonly used to push the real domain off the end of a phone address bar.');
  } else if (f.subdomainDepth === 2) {
    add(6, 'low', 'SUBDOMAIN_DEPTH', `Two subdomain levels in front of ${f.registrableDomain}.`);
  }

  if (f.hyphenCount >= 3) {
    add(14, 'medium', 'HYPHENATED_DOMAIN',
      `The registered name "${f.registrableLabel}" is built from ${f.hyphenCount + 1} hyphen-joined words.`);
  } else if (f.hyphenCount === 2) {
    add(6, 'low', 'HYPHENATED_DOMAIN', `Hyphen-joined registered name "${f.registrableLabel}".`);
  }

  if (f.hostCore.length >= 6 && f.digitRatioHost > 0.35) {
    add(12, 'medium', 'DIGIT_HEAVY_HOST',
      `${(f.digitRatioHost * 100).toFixed(0)}% of the registered host is digits, typical of `
      + 'bulk-generated or auto-assigned hostnames.');
  }
  if (f.registrableLabel.length >= 12 && f.labelEntropy > 3.6) {
    add(14, 'medium', 'HIGH_ENTROPY_LABEL',
      `"${f.registrableLabel}" carries ${f.labelEntropy} bits of entropy per character — `
      + 'closer to random output than to a chosen name.');
  }

  if (f.urlLength > 200) {
    add(18, 'medium', 'VERY_LONG_URL', `${f.urlLength} characters long.`);
  } else if (f.urlLength > 120) {
    add(10, 'low', 'LONG_URL', `${f.urlLength} characters long.`);
  }

  const risky = highRiskSuffix(target);
  if (risky) {
    add(12, 'medium', 'HIGH_RISK_SUFFIX',
      `.${risky} is among the suffixes with the highest measured abuse rates and the `
      + 'weakest registration checks.');
  }
  const free = freeHostingSuffix(target);
  if (free) {
    add(20, 'medium', 'FREE_HOSTING',
      `Hosted under ${free}, where anyone can claim a hostname in seconds and no part of `
      + 'the name is verified by anyone.');
    const claimed = TRUST_WORDS.filter((w) => words(f.hostCore).includes(w));
    if (claimed.length > 0) {
      add(12, 'medium', 'UNVERIFIED_TRUST_CLAIM',
        `The hostname asserts "${claimed.join('", "')}" on infrastructure that verifies `
        + 'none of it — the words are free, exactly like the hostname.');
    }
  }

  if (!f.isHttps) {
    add(10, 'medium', 'NO_TLS', 'Plain HTTP: anything submitted travels unencrypted.');
  }
  if (target.path.includes('//')) {
    add(8, 'low', 'DOUBLE_SLASH_PATH', 'Doubled slashes in the path, often left by URL stitching.');
  }
  const hostWords = words(f.hostCore);
  if (hostWords.includes('http') || hostWords.includes('https')
      || /https?:\/\//i.test(target.path + target.query)) {
    add(15, 'medium', 'EMBEDDED_SCHEME',
      'A second URL is embedded in this one — the destination shown is not the destination reached.');
  }

  const hostKeywords = matchKeywords(f.hostCore);
  if (hostKeywords.length > 0) {
    add(Math.min(30, 18 * hostKeywords.length), 'high', 'HOST_KEYWORDS',
      `Action words baked into the domain name itself: ${hostKeywords.join(', ')}. `
      + 'Real services do not register a new domain per prompt.');
  }
  const pathKeywords = matchKeywords(target.path + target.query);
  if (pathKeywords.length > 0) {
    add(Math.min(16, 8 * pathKeywords.length), 'low', 'PATH_KEYWORDS',
      `Urgency or credential wording in the path: ${pathKeywords.join(', ')}.`);
  }
  if (f.pathDepth > 6) {
    add(6, 'low', 'DEEP_PATH', `${f.pathDepth} path segments.`);
  }

  return { score: Math.min(100, score), signals, features: f };
}

/** Convenience wrapper for callers that only have a raw string. */
export function scoreUrlHeuristics(rawUrl) {
  const target = parseTarget(rawUrl);
  if (!target.ok) return null;
  return scoreHeuristics(target);
}
