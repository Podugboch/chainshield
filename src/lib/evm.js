/**
 * EVM primitives: address validation, exact fixed-point formatting, and the
 * minimal ABI encoding/decoding this app needs.
 *
 * The formatting here is deliberately BigInt-only. Every amount in this
 * codebase used to be computed as `Number(BigInt(raw)) / 10 ** decimals`, which
 * converts to a float *before* scaling: raw values above 2^53 lose their low
 * digits, and an 18-decimal balance passes that in ordinary use. For a tool
 * whose output goes into a police report, an amount that is quietly wrong in
 * the last places is worse than no amount at all.
 */
import { keccak_256 } from '@noble/hashes/sha3.js';

const HEX_ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const HEX_TX_HASH = /^0x[0-9a-fA-F]{64}$/;

export function isHexAddress(value) {
  return typeof value === 'string' && HEX_ADDRESS.test(value.trim());
}

export function isTxHash(value) {
  return typeof value === 'string' && HEX_TX_HASH.test(value.trim());
}

/** EIP-55: capitalise hex digits according to keccak256 of the lowercase form. */
export function toChecksumAddress(address) {
  const clean = address.trim().toLowerCase().replace(/^0x/, '');
  const hash = keccak_256(new TextEncoder().encode(clean));
  let out = '0x';
  for (let i = 0; i < clean.length; i += 1) {
    const ch = clean[i];
    if (ch >= 'a' && ch <= 'f') {
      // Nibble i of the hash: high nibble for even i, low nibble for odd.
      const nibble = i % 2 === 0 ? hash[i >> 1] >> 4 : hash[i >> 1] & 0x0f;
      out += nibble >= 8 ? ch.toUpperCase() : ch;
    } else {
      out += ch;
    }
  }
  return out;
}

/**
 * Validate an address for use as a scan target or a payout destination.
 *
 * A mixed-case address carries a checksum, so a single mistyped character is
 * detectable and must be rejected rather than silently queried. An all-lower or
 * all-upper address carries no checksum -- it can only be accepted as-is, and
 * the caller is told so via `checksumVerified`.
 */
export function validateAddress(raw) {
  const value = String(raw ?? '').trim();
  if (!value) return { ok: false, reason: 'No address provided.' };
  if (!value.startsWith('0x')) return { ok: false, reason: 'Address must start with 0x.' };
  if (value.length !== 42) {
    return {
      ok: false,
      reason: `Address must be 42 characters including 0x (received ${value.length}).`,
    };
  }
  if (!HEX_ADDRESS.test(value)) {
    return { ok: false, reason: 'Address contains characters outside 0-9 and a-f.' };
  }

  const body = value.slice(2);
  const hasUpper = /[A-F]/.test(body);
  const hasLower = /[a-f]/.test(body);
  const checksum = toChecksumAddress(value);

  if (hasUpper && hasLower && value !== checksum) {
    return {
      ok: false,
      reason: 'EIP-55 checksum does not match - at least one character is wrong. '
        + 'Re-copy the address rather than correcting it by hand.',
      checksum,
    };
  }

  return {
    ok: true,
    address: checksum,
    lower: value.toLowerCase(),
    checksumVerified: hasUpper && hasLower,
  };
}

export function validateTxHash(raw) {
  const value = String(raw ?? '').trim();
  if (!value) return { ok: false, reason: 'No transaction hash provided.' };
  if (!value.startsWith('0x')) return { ok: false, reason: 'Transaction hash must start with 0x.' };
  if (value.length !== 66) {
    return {
      ok: false,
      reason: `Transaction hash must be 66 characters including 0x (received ${value.length}).`,
    };
  }
  if (!HEX_TX_HASH.test(value)) {
    return { ok: false, reason: 'Transaction hash contains non-hex characters.' };
  }
  return { ok: true, hash: value.toLowerCase() };
}

/** Parse a hex quantity. Tolerates '0x', '', null and unprefixed digits. */
export function hexToBigInt(hex) {
  if (hex === null || hex === undefined) return 0n;
  const s = String(hex).trim();
  if (!s || s === '0x' || s === '0X') return 0n;
  return BigInt(s.startsWith('0x') || s.startsWith('0X') ? s : `0x${s}`);
}

/**
 * Exact fixed-point rendering of a raw integer amount. Pure string arithmetic,
 * so an 18-decimal value with 30 significant digits survives intact.
 * Returns e.g. formatUnits(146070000n, 6) === '146.07'.
 */
export function formatUnits(value, decimals) {
  const d = Number.isInteger(decimals) && decimals >= 0 ? decimals : 0;
  const raw = typeof value === 'bigint' ? value : hexToBigInt(value);
  const negative = raw < 0n;
  const digits = (negative ? -raw : raw).toString().padStart(d + 1, '0');
  const whole = digits.slice(0, digits.length - d) || '0';
  const frac = d > 0 ? digits.slice(digits.length - d).replace(/0+$/, '') : '';
  return `${negative ? '-' : ''}${whole}${frac ? `.${frac}` : ''}`;
}

/**
 * Display form: thousands separators, at most `maxFrac` decimal places, and an
 * explicit marker when rounding actually dropped something. A truncated amount
 * that looks exact is how a report ends up misstating a loss.
 */
export function formatAmountForDisplay(value, decimals, maxFrac = 6) {
  const exact = formatUnits(value, decimals);
  const [whole, frac = ''] = exact.split('.');
  const grouped = whole.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  if (!frac) return { text: grouped, exact, rounded: false };
  if (frac.length <= maxFrac) return { text: `${grouped}.${frac}`, exact, rounded: false };
  return { text: `${grouped}.${frac.slice(0, maxFrac)}...`, exact, rounded: true };
}

/** Left-pad a value to a 32-byte ABI word. */
function word(hexNoPrefix) {
  return hexNoPrefix.toLowerCase().padStart(64, '0');
}

export const ERC20 = {
  // keccak256 selectors for the three calls used here.
  DECIMALS: '0x313ce567',
  SYMBOL: '0x95d89b41',
  BALANCE_OF: '0x70a08231',
  // Transfer(address indexed from, address indexed to, uint256 value)
  TRANSFER_TOPIC: '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
};

export function encodeBalanceOf(address) {
  return ERC20.BALANCE_OF + word(address.replace(/^0x/, ''));
}

/** Recover an address from an indexed log topic (right-most 20 bytes). */
export function addressFromTopic(topic) {
  if (typeof topic !== 'string' || topic.length < 42) return null;
  const body = topic.replace(/^0x/, '').padStart(64, '0');
  return toChecksumAddress(`0x${body.slice(24)}`);
}

/** Decode a uint8/uint256 return word. Returns null for an empty response. */
export function decodeUint(hex) {
  if (!hex || hex === '0x') return null;
  return hexToBigInt(hex);
}

/**
 * Decode a `string` return value, falling back to bytes32.
 *
 * Tokens predating the finalised ERC-20 text -- MKR and SAI among them --
 * declare `symbol()` as bytes32 and return a fixed 32-byte word with no offset
 * header. Decoding those as a dynamic string yields mojibake, so the length of
 * the response decides which shape it is.
 */
export function decodeStringResult(hex) {
  if (!hex || hex === '0x') return null;
  const body = hex.replace(/^0x/, '');

  // Dynamic string: offset word, length word, then padded data.
  if (body.length >= 128) {
    try {
      const offset = Number(BigInt(`0x${body.slice(0, 64)}`)) * 2;
      const length = Number(BigInt(`0x${body.slice(offset, offset + 64)}`)) * 2;
      if (length > 0 && offset + 64 + length <= body.length) {
        const bytes = body.slice(offset + 64, offset + 64 + length);
        const decoded = bytesToUtf8(bytes);
        if (decoded) return decoded;
      }
    } catch {
      // Fall through to the bytes32 reading below.
    }
  }

  // bytes32: a single word, right-padded with zeros.
  const trimmed = body.slice(0, 64).replace(/(00)+$/, '');
  return bytesToUtf8(trimmed);
}

function bytesToUtf8(hexBody) {
  if (!hexBody) return null;
  const pairs = hexBody.match(/.{1,2}/g) || [];
  const bytes = new Uint8Array(pairs.map((p) => parseInt(p, 16)));
  const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes)
    .replace(/\u0000+/g, '')
    .trim();
  // Any remaining control byte means this word was never text.
  return text && !/[\u0000-\u001f]/.test(text) ? text : null;
}

