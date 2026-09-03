/**
 * Brand registry and the brand-abuse matcher.
 *
 * The rule that matters: a brand name appearing anywhere in a hostname is not
 * evidence of anything on its own. "googleapis.com" and "paypal.me" contain
 * brand names and are legitimate; "coinbase.com-login-security.icu" contains
 * one in a position that cannot be legitimate. Position, delimiters and the
 * registrable-domain boundary are what separate the two.
 */
import { skeleton, levenshtein } from './domainUtils.js';

export const BRANDS = [
  {
    name: 'Atlas Capture',
    tokens: ['atlascapture'],
    official: ['atlascapture.com', 'atlascapture.io'],
  },
  {
    name: 'Binance',
    tokens: ['binance'],
    official: ['binance.com', 'binance.us', 'binance.info', 'bnbchain.org'],
  },
  {
    name: 'MetaMask',
    tokens: ['metamask'],
    official: ['metamask.io', 'metamask.app', 'consensys.io'],
  },
  {
    name: 'Coinbase',
    tokens: ['coinbase'],
    official: ['coinbase.com', 'cbpay.io', 'wallet.coinbase.com'],
  },
  {
    name: 'Tether / USDT',
    tokens: ['tether', 'usdt'],
    official: ['tether.to', 'tether.io'],
  },
  {
    name: 'Google',
    tokens: ['google'],
    official: [
      'google.com', 'googleapis.com', 'googleusercontent.com', 'gstatic.com',
      'withgoogle.com', 'goo.gl', 'youtube.com',
    ],
  },
  {
    name: 'Microsoft',
    tokens: ['microsoft'],
    official: [
      'microsoft.com', 'microsoftonline.com', 'office.com', 'live.com',
      'azure.com', 'msn.com', 'sharepoint.com', 'outlook.com',
    ],
  },
  {
    name: 'PayPal',
    tokens: ['paypal'],
    official: ['paypal.com', 'paypal.me', 'paypalobjects.com'],
  },
];

/** Legacy shape kept for the components that render the trusted-brand list. */
export const KNOWN_TRUSTED_BRANDS = BRANDS.map(({ name, official }) => ({
  name,
  domains: official,
}));

/**
 * Suffixes with negligible registration cost and no abuse response, drawn from
 * the tails of the Spamhaus and Interisle "most abused TLD" tables.
 */
export const HIGH_RISK_SUFFIXES = [
  'top', 'xyz', 'icu', 'cam', 'cfd', 'sbs', 'buzz', 'monster', 'rest', 'bond',
  'tk', 'ml', 'ga', 'cf', 'gq', 'work', 'click', 'quest', 'fit', 'beauty',
  'lol', 'autos', 'makeup', 'skin', 'hair', 'mom', 'cyou', 'wang', 'kim',
];

/**
 * Suffixes where anyone can obtain a hostname under someone else's brand.
 * A brand name in a label here is a claim, never a credential.
 */
export const FREE_HOSTING_SUFFIXES = [
  'firebaseapp.com', 'firebasestorage.app', 'web.app', 'pages.dev',
  'workers.dev', 'r2.dev', 'github.io', 'netlify.app', 'vercel.app',
  'glitch.me', 'repl.co', 'replit.app', 'blogspot.com', 'weebly.com',
  'wixsite.com', '000webhostapp.com', 'duckdns.org', 'ngrok-free.app',
  'ngrok.io', 'xsph.ru', 'serveo.net', 'trycloudflare.com', 'onrender.com',
];

/** True when `hostname` is the brand's own domain or a subdomain of it. */
export function isOfficialHost(hostname, brand) {
  return brand.official.some((d) => hostname === d || hostname.endsWith(`.${d}`));
}

/** The brand that owns this hostname, or null. */
export function findBrandOwner(hostname) {
  return BRANDS.find((b) => isOfficialHost(hostname, b)) || null;
}

/** Suffix membership, matched on whole labels so "ru" never matches "guru". */
function suffixMatches(target, list) {
  const host = target.hostname;
  return list.find((s) => host === s || host.endsWith(`.${s}`)) || null;
}

export function highRiskSuffix(target) {
  return suffixMatches(target, HIGH_RISK_SUFFIXES);
}

export function freeHostingSuffix(target) {
  return suffixMatches(target, FREE_HOSTING_SUFFIXES);
}

/** Brand tokens shorter than this are too generic for fuzzy comparison. */
const MIN_FUZZY_LEN = 6;

function tokenize(label) {
  const parts = String(label || '').split(/[-_+]/).filter(Boolean);
  return { parts, collapsed: parts.join('') };
}

function tokenIn(bag, token) {
  return bag.parts.includes(token)
    || (token.length >= MIN_FUZZY_LEN && bag.collapsed.includes(token));
}

/**
 * Classify how a hostname relates to the brand registry.
 *
 * status is one of:
 *   official        the brand's own domain — no penalty
 *   brand-elsewhere the bare brand name on another suffix (google.co.uk)
 *   impersonation   the brand name where the brand has no control
 *   squat           a confusable or one-edit variant of the brand name
 *   path-mention    the brand named only in the path of an unrelated host
 *   none            no relationship found
 */
export function detectBrandAbuse(target) {
  const owner = findBrandOwner(target.hostname);
  if (owner) return { status: 'official', brand: owner.name };

  const label = tokenize(target.registrableLabel);
  const labelSkeleton = skeleton(label.collapsed);
  const untrustedSuffix = freeHostingSuffix(target) || highRiskSuffix(target);

  // 1. Brand name in a subdomain of a registrable domain the brand does not own.
  for (const brand of BRANDS) {
    for (const raw of target.subdomainLabels) {
      const hit = brand.tokens.find((t) => tokenIn(tokenize(raw), t));
      if (hit) {
        return {
          status: 'impersonation',
          brand: brand.name,
          kind: 'subdomain',
          evidence: `"${hit}" sits in the subdomain of ${target.registrableDomain}, `
            + `a domain ${brand.name} does not control — the part of the hostname `
            + 'that decides where you actually connect is the registrable domain',
        };
      }
    }
  }

  // 2. Brand name in the userinfo, which browsers discard entirely.
  if (target.credentials) {
    const creds = tokenize(target.credentials.replace(/[.:]+/g, '-'));
    for (const brand of BRANDS) {
      const hit = brand.tokens.find((t) => tokenIn(creds, t));
      if (hit) {
        return {
          status: 'impersonation',
          brand: brand.name,
          kind: 'userinfo',
          evidence: `"${hit}" appears before the "@", which browsers discard — the request `
            + `goes to ${target.hostname}`,
        };
      }
    }
  }

  // 3. The registrable label itself.
  for (const brand of BRANDS) {
    for (const t of brand.tokens) {
      if (label.collapsed === t) {
        if (untrustedSuffix) {
          return {
            status: 'impersonation',
            brand: brand.name,
            kind: 'lookalike-registration',
            evidence: `"${target.registrableDomain}" registers the ${brand.name} name `
              + `under .${untrustedSuffix}, which is not on its verified domain list`,
          };
        }
        return {
          status: 'brand-elsewhere',
          brand: brand.name,
          evidence: `${target.registrableDomain} carries the ${brand.name} name on a `
            + 'suffix outside the verified list — likely a regional site, worth confirming',
        };
      }
      if (tokenIn(label, t)) {
        return {
          status: 'impersonation',
          brand: brand.name,
          kind: 'label',
          evidence: `"${target.registrableDomain}" pads "${t}" with extra words; `
            + `${brand.name} serves its own name without additions`,
        };
      }
    }
  }

  // 4. Confusable and single-edit variants of the brand name.
  for (const brand of BRANDS) {
    for (const t of brand.tokens) {
      if (t.length < MIN_FUZZY_LEN) continue;
      const brandSkeleton = skeleton(t);
      if (Math.abs(labelSkeleton.length - brandSkeleton.length) > 2) continue;

      if (labelSkeleton === brandSkeleton) {
        return {
          status: 'squat',
          brand: brand.name,
          kind: 'confusable',
          evidence: `"${target.registrableLabel}" is not "${t}", but folds onto it once `
            + 'homoglyphs and lookalike glyph pairs are normalised',
        };
      }
      const distance = levenshtein(labelSkeleton, brandSkeleton);
      if (distance > 0 && distance <= (brandSkeleton.length <= 8 ? 1 : 2)) {
        return {
          status: 'squat',
          brand: brand.name,
          kind: 'typo',
          distance,
          evidence: `"${target.registrableLabel}" is ${distance} character edit`
            + `${distance === 1 ? '' : 's'} away from "${t}"`,
        };
      }
    }
  }

  // 5. Brand named only in the path — weak on its own, telling in combination.
  const pathParts = tokenize(target.path.replace(/[/.]+/g, '-'));
  for (const brand of BRANDS) {
    const hit = brand.tokens.find((t) => pathParts.parts.includes(t));
    if (hit) {
      return {
        status: 'path-mention',
        brand: brand.name,
        evidence: `the path claims "${hit}" while the host is ${target.hostname}`,
      };
    }
  }

  return { status: 'none', brand: null };
}
