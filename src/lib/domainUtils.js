/**
 * Domain parsing and confusable-folding helpers.
 *
 * Everything here resolves the registrable domain (eTLD+1) through the Public
 * Suffix List. Splitting a hostname on dots misreads every multi-label suffix:
 * "bbc.co.uk" is not "bbc" with a "co.uk" subdomain, and treating it that way
 * is what made the old scanner flag ordinary ccTLD sites.
 */
import { parse as parseHostname } from 'tldts';
// Explicit file path, not the bare specifier: bare "punycode" resolves to the
// deprecated Node builtin, and "punycode/" is a directory import Node rejects.
import punycode from 'punycode/punycode.js';

/** Characters that render like ASCII Latin in most typefaces. */
const CONFUSABLES = {
  // Cyrillic
  а: 'a', в: 'b', с: 'c', е: 'e', һ: 'h', і: 'i', ј: 'j', к: 'k',
  м: 'm', н: 'h', о: 'o', р: 'p', ѕ: 's', т: 't', у: 'y', х: 'x',
  ԁ: 'd', ԛ: 'q', ԝ: 'w',
  // Greek
  α: 'a', β: 'b', ε: 'e', ι: 'i', κ: 'k', ν: 'v', ο: 'o', ρ: 'p',
  τ: 't', υ: 'u', χ: 'x', ϲ: 'c',
  // Digits and symbols stood in for letters
  0: 'o', 1: 'l', 3: 'e', 4: 'a', 5: 's', 7: 't', $: 's',
  // Latin extended that survives NFD decomposition
  ı: 'i', ł: 'l', ø: 'o', đ: 'd', ħ: 'h',
  // Fold the i/l/1 group onto one glyph
  i: 'l',
};

/** Multi-glyph substitutions, applied after single-character folding. */
const DIGRAPHS = [['rn', 'm'], ['vv', 'w']];

const LATIN = /\p{Script=Latin}/u;
const NON_LATIN_LETTER = /[\p{L}--\p{Script=Latin}]/v;

/** Decode an IDNA/punycode hostname back to Unicode. Returns input on failure. */
export function toUnicodeHost(hostname) {
  if (!hostname || !hostname.includes('xn--')) return hostname;
  try {
    return punycode.toUnicode(hostname);
  } catch {
    return hostname;
  }
}

/** Drop combining marks so "é" collapses to "e". */
export function stripDiacritics(str) {
  return str.normalize('NFD').replace(/\p{M}/gu, '');
}

/**
 * Fold a label to a comparison form in which visually equivalent strings match.
 * "binancé" and "b1nance" both reduce to the same skeleton as "binance".
 */
export function skeleton(label) {
  let out = stripDiacritics(String(label).toLowerCase());
  out = [...out].map((ch) => CONFUSABLES[ch] ?? ch).join('');
  for (const [from, to] of DIGRAPHS) out = out.split(from).join(to);
  return out;
}

/** True when a label mixes Latin with another script — a homograph hallmark. */
export function hasMixedScripts(label) {
  return LATIN.test(label) && NON_LATIN_LETTER.test(label);
}

/** Shannon entropy in bits. Used to spot algorithmically generated labels. */
export function shannonEntropy(str) {
  if (!str) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let bits = 0;
  for (const n of Object.values(freq)) {
    const p = n / str.length;
    bits -= p * Math.log2(p);
  }
  return Number(bits.toFixed(3));
}

/**
 * Normalise a URL into the parts every heuristic needs.
 *
 * Structure (suffix / registrable domain / subdomain) is resolved from the
 * ASCII host so the PSL lookup is exact; labels are additionally exposed in
 * decoded Unicode form so confusable folding sees "binancé", not
 * "xn--binanc-gva".
 */
export function parseTarget(rawUrl) {
  let text = String(rawUrl ?? '').trim();
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) text = `https://${text}`;

  let url;
  try {
    url = new URL(text);
  } catch {
    return { ok: false, input: String(rawUrl ?? '').trim() };
  }
  if (!url.hostname) return { ok: false, input: text };

  const hostname = url.hostname.toLowerCase();
  const info = parseHostname(hostname, { allowPrivateDomains: true });
  const subdomain = info.subdomain || '';
  const subdomainLabels = subdomain ? subdomain.split('.').filter(Boolean) : [];

  return {
    ok: true,
    url,
    href: url.toString(),
    scheme: url.protocol.replace(':', ''),
    hostname,
    unicodeHost: toUnicodeHost(hostname),
    isPunycode: hostname.includes('xn--'),
    isIp: Boolean(info.isIp),
    publicSuffix: info.publicSuffix || '',
    isIcannSuffix: info.isIcann === true,
    registrableDomain: info.domain || hostname,
    registrableLabel: toUnicodeHost(info.domainWithoutSuffix || ''),
    subdomain,
    subdomainLabels: subdomainLabels.map(toUnicodeHost),
    path: url.pathname || '/',
    query: url.search || '',
    credentials: url.username || '',
  };
}

/** Iterative Levenshtein distance. */
export function levenshtein(a, b) {
  if (a === b) return 0;
  if (a.length < b.length) return levenshtein(b, a);
  if (b.length === 0) return a.length;

  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 0; i < a.length; i++) {
    const row = [i + 1];
    for (let j = 0; j < b.length; j++) {
      row.push(Math.min(
        prev[j + 1] + 1,
        row[j] + 1,
        prev[j] + (a[i] === b[j] ? 0 : 1),
      ));
    }
    prev = row;
  }
  return prev[b.length];
}
