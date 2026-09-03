#!/usr/bin/env node
/**
 * URL scanner regression corpus.
 *
 * The benign half is the important half: a scanner that flags real sites gets
 * ignored, and once it is ignored its recall is irrelevant. Every entry here is
 * a real address that a ChainShield user could plausibly paste.
 *
 * Run with: npm test
 */
import { analyzeUrl } from '../src/lib/phishingDetector.js';
import { skeleton, parseTarget } from '../src/lib/domainUtils.js';

/** Legitimate URLs. Any non-SAFE verdict here is a false positive. */
const BENIGN = [
  'https://www.google.co.uk',
  'https://www.google.de',
  'https://googleapis.com',
  'https://paypal.me/jdoe',
  'https://www.microsoft.co.uk',
  'https://coinbase.com/price/bitcoin',
  'https://www.binance.com/en/trade/BTC_USDT',
  'https://accounts.google.com/signin',
  'https://support.metamask.io/hc/en-us/articles/360015489591',
  'https://en.wikipedia.org/wiki/Phishing',
  'https://github.com/Podugboch/chainshield',
  'https://stackoverflow.com/questions/12345678/how-to-parse-a-url-in-javascript',
  'https://www.amazon.co.uk/dp/B08N5WRWNW?ref=nav_signin&pd_rd_i=B08N5WRWNW',
  'https://docs.google.com/document/d/1a2b3c4d5e6f7g8h9i0j/edit',
  'https://www.gov.uk/government/organisations/hm-revenue-customs',
  'https://open.spotify.com/track/4cOdK2wGLETKBW3PvgPWqT',
  'https://api.github.com/repos/nodejs/node/issues?state=open&per_page=100',
  'https://www.bbc.co.uk/news/technology-12345678',
  'http://neverssl.com',
  'https://firebasestorage.googleapis.com/v0/b/my-app.appspot.com/o/f.pdf?alt=media&token=abc-123',
  'https://zoom.us/j/91234567890?pwd=abcdEFGH1234',
  'https://www.paypal.com/uk/webapps/mpp/home',
  'https://tether.to/en/transparency',
  'https://mail.proton.me/u/0/inbox',
  'https://etherscan.io/address/0xdac17f958d2ee523a2206206994597c13d831ec7',
  'https://app.example.com/reset?email=jane.doe@example.com&token=9f2c1a',
  'https://www.nhs.uk/nhs-services/gps/how-to-register-with-a-gp-surgery/',
  'https://learn.microsoft.com/en-us/azure/architecture/guide/',
  'https://atlascapture.com/dashboard',
  'https://www.gov.uk/log-in-register-hmrc-online-services',
];

/**
 * Phishing URLs, patterns taken from live feed samples. `expect` is the weakest
 * verdict that still counts as a catch, so a rule change that downgrades a
 * MALICIOUS verdict to SUSPICIOUS fails the test rather than passing quietly.
 */
const PHISHING = [
  { url: 'http://binance-verify-account.tk/login', expect: 'MALICIOUS' },
  { url: 'https://metamask-wallet-connect.xyz/restore', expect: 'MALICIOUS' },
  { url: 'http://192.168.1.55/coinbase/signin.php', expect: 'MALICIOUS' },
  { url: 'https://atlascapture-payout-verify.top/kyc-update', expect: 'MALICIOUS' },
  { url: 'https://binancé.com/login', expect: 'MALICIOUS' },
  { url: 'https://secure-paypal.com.verify-account.cfd/billing-confirm', expect: 'MALICIOUS' },
  { url: 'http://coinbase.com-login-security.icu/authenticate', expect: 'MALICIOUS' },
  { url: 'https://www.gooogle.com/accounts', expect: 'MALICIOUS' },
  { url: 'https://metarnask.io/wallet-connect', expect: 'MALICIOUS' },
  { url: 'https://claim-usdt-bonus-claim.sbs/wallet-connect', expect: 'MALICIOUS' },
  { url: 'https://coinbase-secure-login.pages.dev/verify', expect: 'MALICIOUS' },
  { url: 'https://atlas-capture.support-payout.click/action-required', expect: 'MALICIOUS' },
  { url: 'https://atlas-capture-support.top/payout-verify', expect: 'MALICIOUS' },
  { url: 'https://binance-security-auth.xyz/login', expect: 'MALICIOUS' },
  { url: 'https://аррle-metamask.com/connect', expect: 'MALICIOUS' },
  { url: 'https://secure-login.auth-93821a.xyz/verify?user=84920', expect: 'SUSPICIOUS' },
  { url: 'http://www.f0519141.xsph.ru', expect: 'SUSPICIOUS' },
  { url: 'https://service-mitld.firebaseapp.com/', expect: 'SUSPICIOUS' },
  { url: 'https://paypal.com@login-verify.icu/secure', expect: 'MALICIOUS' },
];

/** Direct assertions on the folding and parsing primitives. */
const UNIT = [
  ['skeleton folds Cyrillic to Latin', () => skeleton('раypal') === skeleton('paypal')],
  ['skeleton folds rn to m', () => skeleton('metarnask') === skeleton('metamask')],
  ['skeleton folds digit substitutes', () => skeleton('b1nance') === skeleton('binance')],
  ['skeleton keeps distinct names distinct', () => skeleton('coinbase') !== skeleton('binance')],
  ['multi-label suffix resolves to eTLD+1',
    () => parseTarget('https://www.bbc.co.uk/news').registrableDomain === 'bbc.co.uk'],
  ['multi-label suffix leaves a one-label subdomain',
    () => parseTarget('https://www.bbc.co.uk/news').subdomainLabels.length === 1],
  ['brand name in a foreign subdomain is not the registrable domain',
    () => parseTarget('http://coinbase.com-login-security.icu/x').registrableDomain
      === 'com-login-security.icu'],
  ['punycode host decodes for comparison',
    () => parseTarget('https://binancé.com').registrableLabel === 'binancé'],
  ['credentials before @ are not the host',
    () => parseTarget('https://paypal.com@login-verify.icu/x').hostname === 'login-verify.icu'],
];

const RANK = { SAFE: 0, SUSPICIOUS: 1, MALICIOUS: 2 };
const line = (mark, text) => console.log(`  ${mark.padEnd(4)} ${text}`);

let failures = 0;

console.log(`\nURL scanner regression\n${'='.repeat(66)}`);

console.log('\nPrimitives');
for (const [name, check] of UNIT) {
  let ok = false;
  let note = '';
  try {
    ok = check() === true;
  } catch (err) {
    note = ` (threw: ${err.message})`;
  }
  if (!ok) failures += 1;
  line(ok ? 'ok' : 'FAIL', `${name}${note}`);
}

console.log('\nLegitimate URLs — every non-SAFE verdict is a false positive');
let falsePositives = 0;
for (const url of BENIGN) {
  const result = analyzeUrl(url);
  const ok = result.riskLevel === 'SAFE';
  if (!ok) {
    falsePositives += 1;
    failures += 1;
  }
  line(ok ? 'ok' : 'FAIL',
    `${String(result.riskScore).padStart(3)}  ${result.riskLevel.padEnd(10)} ${url}`);
  if (!ok) line('', `     triggered: ${result.reasons.map((r) => r.id || r.category).join(', ')}`);
}

console.log('\nPhishing URLs — every SAFE verdict is a miss');
let misses = 0;
for (const { url, expect } of PHISHING) {
  const result = analyzeUrl(url);
  const ok = RANK[result.riskLevel] >= RANK[expect];
  if (!ok) {
    misses += 1;
    failures += 1;
  }
  line(ok ? 'ok' : 'FAIL',
    `${String(result.riskScore).padStart(3)}  ${result.riskLevel.padEnd(10)} ${url}`
    + `${ok ? '' : `  (needed ${expect})`}`);
}

const caught = PHISHING.length - misses;
console.log(`\n${'='.repeat(66)}`);
console.log(`false positives : ${falsePositives}/${BENIGN.length} `
  + `(${(falsePositives / BENIGN.length * 100).toFixed(1)}% of legitimate URLs flagged)`);
console.log(`recall          : ${caught}/${PHISHING.length} `
  + `(${(caught / PHISHING.length * 100).toFixed(1)}%)`);
console.log(failures === 0 ? '\nall checks passed\n' : `\n${failures} check(s) failed\n`);

process.exit(failures === 0 ? 0 : 1);
