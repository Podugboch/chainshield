#!/usr/bin/env node
/**
 * Forensics regression corpus.
 *
 * Everything here guards a number or an address that ends up in a document
 * someone files with a bank, an exchange or the police. The bar is therefore
 * not "the function runs" but "the digits are exactly right, and where they
 * cannot be established the code says so instead of guessing".
 *
 * No network access: token metadata resolves from the per-network registry, and
 * the GoPlus section stubs `fetch` with canned payloads.
 *
 * Run with: npm test
 */
import { keccak_256 } from '@noble/hashes/sha3.js';
import {
  ERC20, addressFromTopic, decodeStringResult, decodeUint, encodeBalanceOf,
  formatAmountForDisplay, formatUnits, hexToBigInt, isHexAddress, isTxHash,
  toChecksumAddress, validateAddress, validateTxHash,
} from '../src/lib/evm.js';
import {
  DEFAULT_INCIDENT, KNOWN_ENTITIES, SUPPORTED_NETWORKS, TOKEN_ISSUERS,
  decodeTransfers, identifyEntity, issuerForToken, selectPrimaryTransfer,
} from '../src/lib/blockchainForensics.js';
import { scanGoPlusAsset } from '../src/lib/goplusSecurity.js';

// ---------------------------------------------------------------- test harness

let failures = 0;
const line = (mark, text) => console.log(`  ${mark.padEnd(4)} ${text}`);
const section = (title) => console.log(`\n${title}`);

const show = (v) => {
  if (typeof v === 'bigint') return `${v}n`;
  if (typeof v === 'string') return JSON.stringify(v);
  return JSON.stringify(v, (_k, x) => (typeof x === 'bigint' ? `${x}n` : x));
};

const same = (a, b) => (typeof a === 'object' && a !== null ? show(a) === show(b) : a === b);

/** Assert a thunk's value. The thunk may be async; anything thrown is a fail. */
async function eq(name, thunk, expected) {
  let actual;
  let threw = null;
  try {
    actual = await thunk();
  } catch (err) {
    threw = err;
  }
  const passed = !threw && same(actual, expected);
  if (!passed) failures += 1;
  line(passed ? 'ok' : 'FAIL', name);
  if (!passed) {
    line('', `     expected ${show(expected)}, got `
      + `${threw ? `throw: ${threw.message}` : show(actual)}`);
  }
}

/** Assert a thunk is truthy. Use when there is nothing useful to print. */
async function ok(name, thunk) {
  await eq(name, async () => Boolean(await thunk()), true);
}

// ------------------------------------------------------------------- fixtures

const utf8 = (s) => new TextEncoder().encode(s);
const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
const selectorOf = (sig) => `0x${hex(keccak_256(utf8(sig))).slice(0, 8)}`;
const topicOf = (sig) => `0x${hex(keccak_256(utf8(sig)))}`;
const word = (value) => value.toString(16).padStart(64, '0');
const addressTopic = (addr) => `0x${addr.replace(/^0x/, '').toLowerCase().padStart(64, '0')}`;

const USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48'; // 6 decimals, in registry
const USDT = '0xdac17f958d2ee523a2206206994597c13d831ec7'; // 6 decimals, in registry
const DISPERSER = '0xd152f549545093347a162dce210e7293f1452150';
const COLLECTOR = '0xd23ac29c1e1949d0c5864b4a23a01cc3e4dd236b';
const FEE_SINK = '0x70faa28a6b8d6d0fc678a165fc367756f71d5b35';

const transferLog = (token, from, to, raw, logIndex) => ({
  address: token,
  logIndex: `0x${logIndex.toString(16)}`,
  topics: [ERC20.TRANSFER_TOPIC, addressTopic(from), addressTopic(to)],
  data: `0x${word(raw)}`,
});

/**
 * The shape of the incident receipt: the victim's 146.07 USDC is the SECOND
 * log, behind a 1 USDC fee leg. Reading logs[0] and calling it "the" transfer is
 * the bug this fixture exists to keep fixed.
 */
const INCIDENT_RECEIPT = {
  status: '0x1',
  gasUsed: '0x1d4c0',
  logs: [
    transferLog(USDC, DISPERSER, FEE_SINK, 1000000n, 0),
    transferLog(USDC, DISPERSER, COLLECTOR, 146070000n, 1),
    transferLog(USDT, DISPERSER, FEE_SINK, 500000n, 2),
    // Two topics only: a non-standard event that happens to share the Transfer
    // signature. Its `data` is not a uint256 amount and must not be decoded.
    { address: USDC, logIndex: '0x3', topics: [ERC20.TRANSFER_TOPIC, addressTopic(DISPERSER)], data: '0x' },
  ],
};

const transfer = (tokenContract, rawAmount, decimals, logIndex) => ({
  logIndex, tokenContract, rawAmount: String(rawAmount), decimals, amountResolved: true,
});

// ------------------------------------------------------- EIP-55 reference set

/** Straight from EIP-55. If these drift, every address the app prints is wrong. */
const EIP55_VECTORS = [
  '0x52908400098527886E0F7030069857D2E4169EE7',
  '0x8617E340B3D01FA5F11F306F4090FD50E238070D',
  '0xde709f2102306220921060314715629080e2fb77',
  '0x27b1fdb04752bbc536007a920d24acb045561c26',
  '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
  '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359',
  '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB',
  '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb',
];

// ----------------------------------------------------------------- the checks

console.log(`\nForensics regression\n${'='.repeat(66)}`);

section('EIP-55 checksums');
for (const vector of EIP55_VECTORS) {
  await eq(`round-trips ${vector.slice(0, 10)}…`,
    () => toChecksumAddress(vector.toLowerCase()), vector);
}
await eq('uppercase input is re-cased, not trusted',
  () => toChecksumAddress('0X5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED'),
  '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed');

section('Address validation');
await eq('accepts a correctly checksummed address',
  () => validateAddress('0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed').ok, true);
await eq('reports a checksummed address as verified',
  () => validateAddress('0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed').checksumVerified, true);
await eq('accepts all-lowercase but reports it as unverified',
  () => validateAddress(COLLECTOR).checksumVerified, false);
await eq('normalises a lowercase address to its checksum form',
  () => validateAddress(COLLECTOR).address, '0xd23Ac29C1e1949D0c5864B4a23a01cc3e4dd236b');
await eq('rejects a mixed-case address with one wrong character',
  () => validateAddress('0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAee').ok, false);
await eq('suggests the correct casing when the checksum fails',
  () => validateAddress('0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed').checksum,
  '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed');
await eq('rejects a transposition inside a checksummed address',
  () => validateAddress('0x71c8F79D3a5d8d3d8dB4D849A6262b54fC6e0132').ok, false);
await eq('rejects a truncated address', () => validateAddress('0xd23Ac29C1e1949D0c5864').ok, false);
await eq('names the length in the rejection reason',
  () => /received 23/.test(validateAddress('0xd23Ac29C1e1949D0c5864').reason), true);
await eq('rejects a missing 0x prefix',
  () => validateAddress('d23ac29c1e1949d0c5864b4a23a01cc3e4dd236b').ok, false);
await eq('rejects non-hex characters',
  () => validateAddress('0xd23ac29c1e1949d0c5864b4a23a01cc3e4dd236g').ok, false);
await eq('rejects an empty address', () => validateAddress('').ok, false);
await eq('rejects null without throwing', () => validateAddress(null).ok, false);
await eq('trims surrounding whitespace',
  () => validateAddress(`  ${COLLECTOR}\n`).ok, true);
await eq('isHexAddress rejects a 41-character string',
  () => isHexAddress('0xd23ac29c1e1949d0c5864b4a23a01cc3e4dd236'), false);

section('Transaction hash validation');
await eq('accepts the incident hash', () => validateTxHash(DEFAULT_INCIDENT.txHash).ok, true);
await eq('lowercases the accepted hash',
  () => validateTxHash(DEFAULT_INCIDENT.txHash.toUpperCase().replace('0X', '0x')).hash,
  DEFAULT_INCIDENT.txHash);
await eq('rejects a 64-character hash missing its prefix',
  () => validateTxHash(DEFAULT_INCIDENT.txHash.slice(2)).ok, false);
await eq('rejects an address passed as a hash', () => validateTxHash(COLLECTOR).ok, false);
await eq('rejects non-hex characters in a hash',
  () => validateTxHash(`0x${'z'.repeat(64)}`).ok, false);
await eq('isTxHash rejects null', () => isTxHash(null), false);

section('Exact amount formatting — the float path is the bug being excluded');
await eq('146.07 USDC at 6 decimals', () => formatUnits(146070000n, 6), '146.07');
await eq('one wei of an 18-decimal token', () => formatUnits(1n, 18), '0.000000000000000001');
await eq('an 18-decimal amount well past 2^53 keeps every digit',
  () => formatUnits(12345678901234567890123n, 18), '12345.678901234567890123');
await eq('a value above 2^53 is not rounded by a float divide',
  () => formatUnits(9007199254740993n, 0), '9007199254740993');
await eq('zero decimals returns the integer', () => formatUnits(42n, 0), '42');
await eq('trailing fractional zeros are trimmed', () => formatUnits(1500000n, 6), '1.5');
await eq('a whole amount has no decimal point', () => formatUnits(2000000n, 6), '2');
await eq('an amount below one keeps its leading zero', () => formatUnits(70000n, 6), '0.07');
await eq('zero formats as 0', () => formatUnits(0n, 18), '0');
await eq('negative amounts keep their sign', () => formatUnits(-146070000n, 6), '-146.07');
await eq('a hex string is accepted as raw input', () => formatUnits('0x8b4d9f0', 6), '146.07');
await eq('display form groups thousands',
  () => formatAmountForDisplay(1234567890000n, 6).text, '1,234,567.89');
await eq('display form marks a rounded fraction',
  () => formatAmountForDisplay(1000000000000000001n, 18, 6).rounded, true);
await eq('display form keeps the exact value alongside the rounded one',
  () => formatAmountForDisplay(1000000000000000001n, 18, 6).exact, '1.000000000000000001');
await eq('display form does not mark an exact fraction as rounded',
  () => formatAmountForDisplay(146070000n, 6).rounded, false);
await eq('hexToBigInt treats 0x as zero', () => hexToBigInt('0x'), 0n);
await eq('hexToBigInt treats null as zero', () => hexToBigInt(null), 0n);
await eq('hexToBigInt accepts an unprefixed quantity', () => hexToBigInt('ff'), 255n);

section('ABI decoding');
await eq('Transfer topic matches keccak256 of the event signature',
  () => topicOf('Transfer(address,address,uint256)'), ERC20.TRANSFER_TOPIC);
await eq('decimals() selector', () => selectorOf('decimals()'), ERC20.DECIMALS);
await eq('symbol() selector', () => selectorOf('symbol()'), ERC20.SYMBOL);
await eq('balanceOf(address) selector', () => selectorOf('balanceOf(address)'), ERC20.BALANCE_OF);
await eq('balanceOf calldata is the selector plus a padded word',
  () => encodeBalanceOf('0xd23Ac29C1e1949D0c5864B4a23a01cc3e4dd236b'),
  `${ERC20.BALANCE_OF}000000000000000000000000${COLLECTOR.slice(2)}`);
await eq('an indexed address topic decodes to a checksummed address',
  () => addressFromTopic(addressTopic(COLLECTOR)), '0xd23Ac29C1e1949D0c5864B4a23a01cc3e4dd236b');
await eq('a short topic decodes to null rather than a wrong address',
  () => addressFromTopic('0x00'), null);
await eq('decodeUint returns null for an empty response', () => decodeUint('0x'), null);
await eq('decodeUint reads a uint8 decimals word',
  () => decodeUint(`0x${word(6n)}`), 6n);
await eq('decodeUint reads a uint256 above 2^53',
  () => decodeUint(`0x${word(12345678901234567890123n)}`), 12345678901234567890123n);
await eq('a dynamic string return value decodes',
  () => decodeStringResult(`0x${word(32n)}${word(4n)}${hex(utf8('USDC')).padEnd(64, '0')}`), 'USDC');
await eq('a bytes32 symbol decodes (MKR and SAI predate the final ABI)',
  () => decodeStringResult(`0x${hex(utf8('MKR')).padEnd(64, '0')}`), 'MKR');
await eq('an empty response decodes to null, not an empty symbol',
  () => decodeStringResult('0x'), null);
await eq('a word of control bytes is not read as text',
  () => decodeStringResult(`0x${'01'.repeat(32)}`), null);

section('Receipt transfer decoding');
const decoded = await decodeTransfers(SUPPORTED_NETWORKS.ethereum, INCIDENT_RECEIPT);
await eq('the two-topic non-standard log is skipped', () => decoded.length, 3);
await eq('registry decimals resolve without a network call',
  () => decoded.every((t) => t.decimalsSource === 'registry'), true);
await eq('every amount is resolved', () => decoded.every((t) => t.amountResolved), true);
await eq('the victim leg decodes to 146.07', () => decoded[1].amount, '146.07');
await eq('its raw integer is preserved as a string', () => decoded[1].rawAmount, '146070000');
await eq('the sender is recovered from topic 1 and checksummed',
  () => decoded[1].sender, '0xD152f549545093347A162Dce210e7293f1452150');
await eq('the recipient is recovered from topic 2 and checksummed',
  () => decoded[1].recipient, '0xd23Ac29C1e1949D0c5864B4a23a01cc3e4dd236b');
await eq('the token contract is checksummed',
  () => decoded[1].tokenContract, '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48');
await eq('the registry symbol is used', () => decoded[1].tokenSymbol, 'USDC');
await eq('log indices come from the log, not the array position',
  () => decoded.map((t) => t.logIndex), [0, 1, 2]);

section('Primary transfer selection');
await eq('the payment is picked over an earlier fee leg',
  () => selectPrimaryTransfer(decoded).rawAmount, '146070000');
await eq('not simply logs[0]',
  () => selectPrimaryTransfer(decoded).logIndex !== decoded[0].logIndex, true);
await eq('an empty receipt yields null, not a fabricated transfer',
  () => selectPrimaryTransfer([]), null);
await eq('several legs of one token outrank a single leg of another', () => {
  const legs = [
    transfer(USDT, 200000000n, 6, 0), // 200 USDT, one leg
    transfer(USDC, 146070000n, 6, 1), // 146.07 + 90 USDC across two
    transfer(USDC, 90000000n, 6, 2),
  ];
  return selectPrimaryTransfer(legs).rawAmount;
}, '146070000');
await eq('a dust leg of an 18-decimal token cannot outrank a 6-decimal payment', () => {
  // 1000000000 units at 18 decimals is 0.000000001 tokens. Compared as raw
  // integers it beats 146.07 USDC, which is how a dossier ends up quoting dust.
  const legs = [
    transfer('0xWETH', 1000000000n, 18, 0),
    transfer(USDC, 146070000n, 6, 1),
  ];
  return selectPrimaryTransfer(legs).rawAmount;
}, '146070000');
await eq('a genuinely larger 18-decimal transfer still wins', () => {
  const legs = [
    transfer('0xWETH', 2000000000000000000n, 18, 0), // 2 tokens
    transfer(USDC, 1000000n, 6, 1), // 1 USDC
  ];
  return selectPrimaryTransfer(legs).rawAmount;
}, '2000000000000000000');
await eq('ties break toward the earlier log', () => {
  const legs = [transfer(USDC, 5000000n, 6, 7), transfer(USDC, 5000000n, 6, 9)];
  return selectPrimaryTransfer(legs).logIndex;
}, 7);
await eq('an unresolved-only receipt falls back to the first log rather than null',
  () => selectPrimaryTransfer([{ logIndex: 0, rawAmount: '1', amountResolved: false }]).logIndex, 0);

section('Freeze authority — a letter to the wrong issuer is not a letter');
await eq('USDT routes to Tether', () => issuerForToken(USDT).issuer, 'Tether');
await eq('USDT freeze call is addBlackList', () => issuerForToken(USDT).freezeFunction, 'addBlackList');
await eq('USDC routes to Circle', () => issuerForToken(USDC).issuer, 'Circle');
await eq('USDC freeze call is blacklist', () => issuerForToken(USDC).freezeFunction, 'blacklist');
await eq('a checksummed contract address still resolves',
  () => issuerForToken('0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48').token, 'USDC');
await eq('a pegged token reports that nobody can freeze it',
  () => issuerForToken('0x55d398326f99059ff775485246999027b3197955').canFreeze, false);
await eq('an unknown token returns null instead of a default issuer',
  () => issuerForToken('0x1111111111111111111111111111111111111111'), null);
await eq('a blank contract returns null', () => issuerForToken(''), null);

section('Incident record consistency');
await eq('the incident token contract has a known issuer',
  () => Boolean(issuerForToken(DEFAULT_INCIDENT.tokenContract)), true);
// This is the record that was wrong: the loss was filed as USDT while the
// Transfer log sits on Circle's USDC contract, so the generated freeze request
// was addressed to a company with no authority over the funds.
await eq('the stated token matches the contract the transfer is on',
  () => DEFAULT_INCIDENT.token.includes(issuerForToken(DEFAULT_INCIDENT.tokenContract).token), true);
await eq('the stated amount names the same token',
  () => DEFAULT_INCIDENT.stolenAmount.includes(issuerForToken(DEFAULT_INCIDENT.tokenContract).token),
  true);
await eq('the incident tx hash is well-formed',
  () => validateTxHash(DEFAULT_INCIDENT.txHash).ok, true);
for (const field of ['tokenContract', 'scammerAddress', 'destinationAddress', 'payoutDisperser']) {
  await eq(`incident ${field} passes EIP-55 validation`,
    () => validateAddress(DEFAULT_INCIDENT[field]).ok, true);
}

section('Lookup table integrity — an uppercase key is a dead key');
await eq('every KNOWN_ENTITIES key is a lowercase address',
  () => Object.keys(KNOWN_ENTITIES).filter((k) => k !== k.toLowerCase() || !isHexAddress(k)), []);
await eq('every TOKEN_ISSUERS key is a lowercase address',
  () => Object.keys(TOKEN_ISSUERS).filter((k) => k !== k.toLowerCase() || !isHexAddress(k)), []);
await eq('every registry token address is valid',
  () => Object.values(SUPPORTED_NETWORKS)
    .flatMap((n) => n.tokens)
    .filter((t) => !isHexAddress(t.address))
    .map((t) => t.address), []);
await eq('every registry token has plausible decimals',
  () => Object.values(SUPPORTED_NETWORKS)
    .flatMap((n) => n.tokens)
    .filter((t) => !Number.isInteger(t.decimals) || t.decimals < 0 || t.decimals > 36)
    .map((t) => t.symbol), []);
await eq('every RPC endpoint is https',
  () => Object.values(SUPPORTED_NETWORKS)
    .flatMap((n) => n.rpcUrls)
    .filter((u) => !u.startsWith('https://')), []);
await eq('the flagged collector is tagged as a scammer',
  () => identifyEntity(DEFAULT_INCIDENT.scammerAddress).type, 'FLAGGED_SCAMMER');
await eq('entity lookup is case-insensitive',
  () => identifyEntity(COLLECTOR.toUpperCase().replace('0X', '0x')).type, 'FLAGGED_SCAMMER');
await eq('an untagged address is UNTAGGED, not clean',
  () => identifyEntity('0x1111111111111111111111111111111111111111').riskLevel, 'UNTAGGED');
await eq('a missing address is UNKNOWN', () => identifyEntity(null).riskLevel, 'UNKNOWN');

// ------------------------------------------------------------- GoPlus scoring

/**
 * Serve canned GoPlus payloads. `fail` simulates the outage case, which is the
 * one that used to score every address as clean.
 */
function stubGoPlus({ token = null, address = null, fail = false } = {}) {
  const original = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (fail) throw new Error('network down');
    const isToken = String(url).includes('/token_security/');
    return {
      ok: true,
      json: async () => (isToken
        ? { code: 1, result: token ? { [COLLECTOR]: token } : {} }
        : { code: 1, result: address || {} }),
    };
  };
  return () => { globalThis.fetch = original; };
}

async function withGoPlus(opts, assertions) {
  const restore = stubGoPlus(opts);
  try {
    await assertions(await scanGoPlusAsset(COLLECTOR, 'ethereum'));
  } finally {
    restore();
  }
}

section('GoPlus scoring — "nothing matched" vs "never checked"');
await withGoPlus({ address: {} }, async (r) => {
  await eq('a clean answer is NO THREATS FOUND, not SAFE', () => r.riskLevel, 'NO THREATS FOUND');
  await eq('a clean answer is not marked degraded', () => r.degraded, false);
  await eq('a clean answer states it is not a guarantee',
    () => r.caveat.includes('not a guarantee'), true);
  await eq('the address feed is recorded as having answered', () => r.metrics.hasAddressData, true);
  await eq('a non-token address reports no token data', () => r.metrics.hasTokenData, false);
});

await withGoPlus({ fail: true }, async (r) => {
  await eq('an outage is UNKNOWN, not NO THREATS FOUND', () => r.riskLevel, 'UNKNOWN');
  await eq('an outage is flagged degraded', () => r.degraded, true);
  await eq('both failed feeds are named in dataGaps', () => r.dataGaps.length, 2);
  await eq('an outage does not claim the token feed answered', () => r.metrics.hasTokenData, false);
  await eq('an outage does not claim the address feed answered',
    () => r.metrics.hasAddressData, false);
  await eq('an outage scores zero without calling it clean', () => r.riskScore, 0);
});

// GoPlus reports tax as a fraction: "0.15" is 15%. The threshold was once
// `> 10`, which only fired at a 1000% tax, so every ordinary scam tax passed.
await withGoPlus({
  token: {
    token_symbol: 'SCAM', token_name: 'Scam', is_open_source: '1',
    buy_tax: '0.15', sell_tax: '0.15',
  },
}, async (r) => {
  await eq('a 15% tax is flagged',
    () => r.flags.some((f) => f.type === 'EXCESSIVE_TAX'), true);
  await eq('the tax is displayed as a percentage', () => r.metrics.buyTaxPct, 15);
  await eq('the fraction is kept for comparison', () => r.metrics.buyTax, 0.15);
  await eq('a taxed token is not left at NO THREATS FOUND', () => r.riskLevel, 'SUSPICIOUS');
});

await withGoPlus({
  token: {
    token_symbol: 'OK', token_name: 'Ordinary', is_open_source: '1',
    buy_tax: '0.03', sell_tax: '0.03',
  },
}, async (r) => {
  await eq('a 3% tax is not flagged as excessive',
    () => r.flags.some((f) => f.type === 'EXCESSIVE_TAX'), false);
  await eq('an ordinary token stays at NO THREATS FOUND', () => r.riskLevel, 'NO THREATS FOUND');
});

await withGoPlus({ token: { token_symbol: 'HID', token_name: 'Hidden', is_open_source: '0' } },
  async (r) => {
    await eq('unverified source code is flagged',
      () => r.flags.some((f) => f.type === 'UNVERIFIED_SOURCE'), true);
    await eq('unverified source alone is SUSPICIOUS, not critical', () => r.riskLevel, 'SUSPICIOUS');
  });

await withGoPlus({
  token: { token_symbol: 'TRAP', token_name: 'Trap', is_honeypot: '1', is_open_source: '1' },
}, async (r) => {
  await eq('a honeypot is CRITICAL MALICIOUS', () => r.riskLevel, 'CRITICAL MALICIOUS');
  await eq('the honeypot metric is set', () => r.metrics.isHoneypot, true);
  await eq('the token feed is recorded as having answered', () => r.metrics.hasTokenData, true);
});

await withGoPlus({ address: { phishing_activities: '1' } }, async (r) => {
  await eq('a reported phishing address is CRITICAL MALICIOUS', () => r.riskLevel, 'CRITICAL MALICIOUS');
  await eq('the phishing flag is present',
    () => r.flags.some((f) => f.type === 'PHISHING_ACTIVITY'), true);
});

await withGoPlus({ address: { mixer: '1' } }, async (r) => {
  await eq('a mixer link scores below critical', () => r.riskLevel, 'SUSPICIOUS');
  await eq('the mixer flag is present',
    () => r.flags.some((f) => f.type === 'MIXER_ASSOCIATED'), true);
});

await eq('a malformed target returns null rather than a score', async () => {
  const restore = stubGoPlus({ address: {} });
  try {
    return await scanGoPlusAsset('0xnope', 'ethereum');
  } finally {
    restore();
  }
}, null);

console.log(`\n${'='.repeat(66)}`);
console.log(failures === 0 ? '\nall checks passed\n' : `\n${failures} check(s) failed\n`);
process.exit(failures === 0 ? 0 : 1);
