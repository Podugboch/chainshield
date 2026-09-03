import { scanGoPlusAsset } from './goplusSecurity.js';
import {
  ERC20, addressFromTopic, decodeStringResult, decodeUint, encodeBalanceOf,
  formatAmountForDisplay, formatUnits, hexToBigInt, toChecksumAddress,
  validateAddress, validateTxHash,
} from './evm.js';

/**
 * Blockchain Forensics Engine
 *
 * Multi-chain JSON-RPC scanner, transfer decoder and transaction-history
 * indexer. Amounts are handled as BigInt throughout and only turned into text
 * at the edge -- see the note in evm.js for why.
 */

export const SUPPORTED_NETWORKS = {
  ethereum: {
    id: 'ethereum',
    name: 'Ethereum Mainnet',
    currency: 'ETH',
    chainId: '1',
    rpcUrls: [
      'https://ethereum-rpc.publicnode.com',
      'https://eth.llamarpc.com',
      'https://rpc.ankr.com/eth',
      'https://1rpc.io/eth'
    ],
    apiBase: 'https://eth.blockscout.com/api',
    explorer: 'https://etherscan.io',
    tokens: [
      { symbol: 'USDT', address: '0xdac17f958d2ee523a2206206994597c13d831ec7', decimals: 6 },
      { symbol: 'USDC', address: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48', decimals: 6 }
    ]
  },
  bsc: {
    id: 'bsc',
    name: 'BNB Smart Chain (BSC)',
    currency: 'BNB',
    chainId: '56',
    rpcUrls: [
      'https://bsc-rpc.publicnode.com',
      'https://bsc-dataseed1.binance.org',
      'https://binance.llamarpc.com'
    ],
    apiBase: 'https://bsc.blockscout.com/api',
    explorer: 'https://bscscan.com',
    tokens: [
      { symbol: 'USDT (BEP-20)', address: '0x55d398326f99059ff775485246999027b3197955', decimals: 18 },
      { symbol: 'USDC', address: '0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d', decimals: 18 }
    ]
  },
  polygon: {
    id: 'polygon',
    name: 'Polygon (PoS)',
    currency: 'POL',
    chainId: '137',
    rpcUrls: [
      'https://polygon-bor-rpc.publicnode.com',
      'https://polygon.llamarpc.com',
      'https://polygon-rpc.com'
    ],
    apiBase: 'https://polygon.blockscout.com/api',
    explorer: 'https://polygonscan.com',
    tokens: [
      { symbol: 'USDT', address: '0xc2132D05D31c914a87C6611C10748AEb04B58e8F', decimals: 6 },
      { symbol: 'USDC', address: '0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359', decimals: 6 }
    ]
  },
  arbitrum: {
    id: 'arbitrum',
    name: 'Arbitrum One',
    currency: 'ETH',
    chainId: '42161',
    rpcUrls: [
      'https://arbitrum-one-rpc.publicnode.com',
      'https://arb1.arbitrum.io/rpc',
      'https://arbitrum.llamarpc.com'
    ],
    apiBase: 'https://arbitrum.blockscout.com/api',
    explorer: 'https://arbiscan.io',
    tokens: [
      { symbol: 'USDT', address: '0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9', decimals: 6 },
      { symbol: 'USDC', address: '0xaf88d065e77c8cC2239327C5EDb3A432268e5831', decimals: 6 }
    ]
  },
  base: {
    id: 'base',
    name: 'Base',
    currency: 'ETH',
    chainId: '8453',
    rpcUrls: [
      'https://base-rpc.publicnode.com',
      'https://mainnet.base.org',
      'https://base.llamarpc.com'
    ],
    apiBase: 'https://base.blockscout.com/api',
    explorer: 'https://basescan.org',
    tokens: [
      { symbol: 'USDC', address: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', decimals: 6 }
    ]
  },
  optimism: {
    id: 'optimism',
    name: 'Optimism',
    currency: 'ETH',
    chainId: '10',
    rpcUrls: [
      'https://optimism-rpc.publicnode.com',
      'https://mainnet.optimism.io'
    ],
    apiBase: 'https://optimism.blockscout.com/api',
    explorer: 'https://optimistic.etherscan.io',
    tokens: [
      { symbol: 'USDT', address: '0x94b008aA00579c1307B0EF2c499aD98a8ce58e58', decimals: 6 },
      { symbol: 'USDC', address: '0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85', decimals: 6 }
    ]
  }
};

export const KNOWN_ENTITIES = {
  '0x28c6c06298d514db089934071355e5743bf21d60': { name: 'Binance: Hot Wallet 6', type: 'CEX_EXCHANGE', riskLevel: 'MONITORED_KYC', color: '#f59e0b' },
  '0x21a31ee1afc51d94c2efccaa2092ad1028285549': { name: 'Binance: Hot Wallet 14', type: 'CEX_EXCHANGE', riskLevel: 'MONITORED_KYC', color: '#f59e0b' },
  '0xdfd5293d8e347dfe59e90efd55b2956a1343963d': { name: 'Binance: Deposit Gateway', type: 'CEX_DEPOSIT', riskLevel: 'MONITORED_KYC', color: '#f59e0b' },
  '0xd23ac29c1e1949d0c5864b4a23a01cc3e4dd236b': { name: 'Atlas Capture Phishing Collector', type: 'FLAGGED_SCAMMER', riskLevel: 'CRITICAL', color: '#ef4444' },
  '0xdb254315a6abdcbebf65a7d538bb275790c07857': { name: 'Scammer Cashout Destination', type: 'FLAGGED_SCAMMER', riskLevel: 'CRITICAL', color: '#ef4444' },
  '0x70faa28a6b8d6d0fc678a165fc367756f71d5b35': { name: 'OKX Deposit Gateway', type: 'CEX_DEPOSIT', riskLevel: 'MONITORED_KYC', color: '#3b82f6' },
  '0xd152f549545093347a162dce210e7293f1452150': { name: 'Disperse.app / Atlas Capture Payout Deployer', type: 'PAYOUT_DISPERSER', riskLevel: 'VERIFIED', color: '#38bdf8' },
  '0xdac17f958d2ee523a2206206994597c13d831ec7': { name: 'Tether USD (ERC-20 USDT)', type: 'TOKEN_CONTRACT', riskLevel: 'VERIFIED', color: '#10b981' },
  '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48': { name: 'USD Coin (ERC-20 USDC)', type: 'TOKEN_CONTRACT', riskLevel: 'VERIFIED', color: '#10b981' },
  '0x55d398326f99059ff775485246999027b3197955': { name: 'Binance-Peg BSC-USD', type: 'TOKEN_CONTRACT', riskLevel: 'VERIFIED', color: '#10b981' }
};

export const DEFAULT_INCIDENT = {
  incidentId: 'INC-2026-ATLAS-01',
  victimPlatform: 'Atlas Capture Contractor Payout',
  stolenAmount: '146.07 USDC',
  // The token was recorded as "USDC / USDT (ERC-20)" and elsewhere as plain
  // USDT. Reading the receipt settles it: the Transfer log for 146.07 is on
  // 0xA0b8...eB48, which is Circle's USDC. This matters beyond tidiness --
  // USDT and USDC are frozen by different issuers, so a freeze request naming
  // the wrong one is addressed to a company with no authority over the funds.
  token: 'USDC (ERC-20)',
  tokenContract: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
  scammerAddress: '0xd23Ac29C1e1949D0c5864B4a23a01cc3e4dd236b',
  txHash: '0x44e5dbb257694dd3297e3a24808a6098f2bce9816bc9b202879104dccec911e7',
  destinationExchange: 'Binance / Receiving Wallet',
  destinationAddress: '0xdb254315a6abdcbebf65a7d538bb275790c07857',
  // The payout arrived via a disperser contract in a 300-transfer batch; the
  // victim's leg is the 146.07 USDC transfer out of 0xD152...2150.
  payoutDisperser: '0xD152f549545093347A162Dce210e7293f1452150',
  summary: 'Phishing attack compromised user credentials on Atlas Capture. Scammer altered payout wallet to 0xd23Ac2...236b, received funds, and swept them to 0xdb2543...7857.',
};

export const SAMPLE_INCIDENT = DEFAULT_INCIDENT;

/**
 * Which company can actually freeze a given token, and where to ask.
 *
 * A centrally-issued stablecoin can be frozen by its issuer and nobody else.
 * The enforcement letter used to be hardcoded to Tether regardless of the token
 * involved, which is a request sent to a party with no control over the asset.
 *
 * `contact` values are the issuers' public channels. Confirm the current address
 * on the issuer's own site before sending: compliance contacts change, and a
 * letter to a dead mailbox reads as no letter at all.
 */
export const TOKEN_ISSUERS = {
  '0xdac17f958d2ee523a2206206994597c13d831ec7': {
    token: 'USDT',
    issuer: 'Tether',
    canFreeze: true,
    freezeFunction: 'addBlackList',
    contact: 'compliance@tether.to',
    portal: 'https://tether.to/en/transparency',
  },
  '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48': {
    token: 'USDC',
    issuer: 'Circle',
    canFreeze: true,
    freezeFunction: 'blacklist',
    contact: null,
    portal: 'https://support.usdc.circle.com',
  },
  '0x55d398326f99059ff775485246999027b3197955': {
    token: 'BSC-USD',
    issuer: 'Binance (pegged token)',
    canFreeze: false,
    freezeFunction: null,
    contact: null,
    portal: 'https://www.binance.com/en/support',
  },
};

/** Look up the issuer for a token contract. Returns null when unknown. */
export function issuerForToken(contractAddress) {
  if (!contractAddress) return null;
  return TOKEN_ISSUERS[contractAddress.trim().toLowerCase()] || null;
}

const RPC_TIMEOUT_MS = 8000;
let rpcRequestId = 0;

/**
 * Call each RPC endpoint in turn until one answers.
 *
 * The timeout is the point: a public endpoint that accepts the connection and
 * then stalls would otherwise hang the whole scan, because there is no deadline
 * on fetch by default and the fallback list is never reached.
 */
async function robustRpcCall(rpcUrls, method, params) {
  const failures = [];

  for (const url of rpcUrls) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), RPC_TIMEOUT_MS);
    try {
      rpcRequestId += 1;
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', method, params, id: rpcRequestId }),
        signal: controller.signal,
      });

      if (!response.ok) throw new Error(`HTTP ${response.status}`);

      const json = await response.json();
      if (json.error) throw new Error(json.error.message || 'RPC error');

      return json.result;
    } catch (err) {
      failures.push(`${new URL(url).host}: ${err.name === 'AbortError' ? 'timed out' : err.message}`);
    } finally {
      clearTimeout(timer);
    }
  }

  throw new Error(`All ${rpcUrls.length} RPC endpoints failed for ${method} (${failures.join('; ')})`);
}

/**
 * Token metadata, read from the contract rather than guessed.
 *
 * The previous code defaulted an unknown token to 6 decimals. Anything with 18
 * -- which is most ERC-20s, including BSC's USDT -- then displayed as 10^12
 * times its real value, and the number went straight into a law-enforcement
 * dossier. Unknown now means "ask the chain", and if the chain will not answer,
 * the amount is reported as unresolved instead of being invented.
 */
const tokenMetaCache = new Map();

async function resolveTokenMeta(net, contractAddress) {
  const key = `${net.id}:${contractAddress.toLowerCase()}`;
  if (tokenMetaCache.has(key)) return tokenMetaCache.get(key);

  const known = net.tokens.find((t) => t.address.toLowerCase() === contractAddress.toLowerCase());
  if (known) {
    const meta = { symbol: known.symbol, decimals: known.decimals, source: 'registry' };
    tokenMetaCache.set(key, meta);
    return meta;
  }

  const meta = { symbol: null, decimals: null, source: 'unresolved' };
  try {
    const [decHex, symHex] = await Promise.all([
      robustRpcCall(net.rpcUrls, 'eth_call', [{ to: contractAddress, data: ERC20.DECIMALS }, 'latest'])
        .catch(() => null),
      robustRpcCall(net.rpcUrls, 'eth_call', [{ to: contractAddress, data: ERC20.SYMBOL }, 'latest'])
        .catch(() => null),
    ]);

    const decoded = decodeUint(decHex);
    // A token cannot have more decimals than uint8 allows; anything outside
    // that range is a non-conforming contract, not a value to divide by.
    if (decoded !== null && decoded >= 0n && decoded <= 36n) {
      meta.decimals = Number(decoded);
      meta.source = 'on-chain';
    }
    const symbol = decodeStringResult(symHex);
    if (symbol) meta.symbol = symbol.slice(0, 16);
  } catch (e) {
    console.warn(`Token metadata unresolved for ${contractAddress}:`, e.message);
  }

  tokenMetaCache.set(key, meta);
  return meta;
}

export function identifyEntity(address) {
  if (!address) return { name: 'Unknown', type: 'EOA', riskLevel: 'UNKNOWN', color: '#94a3b8' };
  const lower = address.toLowerCase();
  if (KNOWN_ENTITIES[lower]) {
    return KNOWN_ENTITIES[lower];
  }
  return {
    name: `Address (${address.slice(0, 6)}...${address.slice(-4)})`,
    type: 'EOA',
    riskLevel: 'UNTAGGED',
    color: '#94a3b8'
  };
}

/**
 * Decode every ERC-20 Transfer in a receipt, not just the first.
 *
 * A swap, a router hop or a fee-on-transfer token emits several. Reading
 * `logs[0]` and calling it "the" transfer picked an arbitrary leg -- often a
 * fee or an intermediate pool -- and reported it as the amount stolen.
 *
 * Logs with fewer than three topics are skipped: those are non-standard events
 * sharing the Transfer signature (some NFT and wrapper contracts emit them),
 * and their `data` is not a uint256 amount.
 *
 * Exported for scripts/test_forensics.mjs: a receipt whose tokens are all in
 * the network registry decodes with no network access, so the amount that ends
 * up in a dossier is testable against a fixture.
 */
export async function decodeTransfers(net, receipt) {
  const logs = (receipt.logs || []).filter(
    (l) => l.topics?.[0]?.toLowerCase() === ERC20.TRANSFER_TOPIC && l.topics.length >= 3,
  );

  const contracts = [...new Set(logs.map((l) => l.address.toLowerCase()))];
  const metas = new Map();
  await Promise.all(contracts.map(async (addr) => {
    metas.set(addr, await resolveTokenMeta(net, addr));
  }));

  return logs.map((log, index) => {
    const meta = metas.get(log.address.toLowerCase()) || { symbol: null, decimals: null, source: 'unresolved' };
    const rawAmount = hexToBigInt(log.data);
    const resolved = meta.decimals !== null;

    return {
      logIndex: log.logIndex ? Number(hexToBigInt(log.logIndex)) : index,
      tokenContract: toChecksumAddress(log.address),
      tokenSymbol: meta.symbol || 'Unknown token',
      decimals: meta.decimals,
      decimalsSource: meta.source,
      amountResolved: resolved,
      rawAmount: rawAmount.toString(),
      // Null rather than a guessed number when decimals are unknown. The UI
      // shows the raw integer and says so.
      amount: resolved ? formatUnits(rawAmount, meta.decimals) : null,
      amountDisplay: resolved
        ? formatAmountForDisplay(rawAmount, meta.decimals).text
        : `${rawAmount.toString()} (raw, decimals unknown)`,
      sender: addressFromTopic(log.topics[1]),
      recipient: addressFromTopic(log.topics[2]),
    };
  });
}

/**
 * Pick the transfer a human would call "the" payment: the largest by value
 * among the dominant token. Ties break toward the earliest log. Returns null
 * when nothing can be compared, rather than defaulting to the first entry.
 *
 * Raw integers are not comparable across tokens, so everything is scaled to the
 * largest decimals present before anything is ranked. Without that, a dust leg
 * of an 18-decimal token -- 1000000000 units is a billionth of one token --
 * outranks a 146.07 USDC payment (146070000 units at 6 decimals) on the
 * strength of the bigger integer, and the dossier quotes the dust.
 */
export function selectPrimaryTransfer(transfers) {
  const usable = transfers.filter((t) => t.amountResolved);
  if (usable.length === 0) return transfers[0] || null;

  const scale = Math.max(...usable.map((t) => t.decimals));
  const valueOf = (t) => BigInt(t.rawAmount) * 10n ** BigInt(scale - t.decimals);

  // Group by token so the several legs of one payment count together against a
  // single larger leg of an unrelated token.
  const byToken = new Map();
  for (const t of usable) {
    const list = byToken.get(t.tokenContract) || [];
    list.push(t);
    byToken.set(t.tokenContract, list);
  }

  let best = null;
  for (const list of byToken.values()) {
    const total = list.reduce((acc, t) => acc + valueOf(t), 0n);
    const largest = list.reduce((a, b) => (valueOf(b) > valueOf(a) ? b : a));
    if (!best || total > best.total) best = { total, largest };
  }
  return best?.largest || null;
}

export async function fetchWalletTransactionHistory(rawAddress, networkKey = 'ethereum') {
  const validated = validateAddress(rawAddress);
  if (!validated.ok) return [];
  const address = validated.lower;
  const net = SUPPORTED_NETWORKS[networkKey] || SUPPORTED_NETWORKS.ethereum;
  const history = [];

  if (!net.apiBase) return [];

  const fetchJson = async (params) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), RPC_TIMEOUT_MS);
    try {
      const resp = await fetch(`${net.apiBase}?${params}`, { signal: controller.signal });
      if (!resp.ok) return null;
      return await resp.json();
    } catch (e) {
      console.warn('History request failed:', e.name === 'AbortError' ? 'timed out' : e.message);
      return null;
    } finally {
      clearTimeout(timer);
    }
  };

  const tokenData = await fetchJson(new URLSearchParams({
    module: 'account', action: 'tokentx', address, sort: 'desc', page: '1', offset: '25',
  }));

  if (Array.isArray(tokenData?.result)) {
    for (const tx of tokenData.result) {
      const decimals = normaliseDecimals(tx.tokenDecimal);
      const rawValue = safeBigInt(tx.value);
      const isIncoming = tx.to?.toLowerCase() === address;
      const counterparty = isIncoming ? tx.from : tx.to;
      const sign = isIncoming ? '+' : '-';
      const display = decimals === null
        ? `${rawValue.toString()} (raw)`
        : formatAmountForDisplay(rawValue, decimals).text;

      history.push({
        hash: tx.hash,
        blockNumber: Number(tx.blockNumber) || 0,
        timeStamp: Number(tx.timeStamp) * 1000 || 0,
        from: tx.from,
        to: tx.to,
        counterparty,
        counterpartyEntity: identifyEntity(counterparty),
        direction: isIncoming ? 'IN' : 'OUT',
        // Exact decimal string; `value` stays numeric for sorting only.
        amountExact: decimals === null ? null : formatUnits(rawValue, decimals),
        value: decimals === null ? 0 : Number(formatUnits(rawValue, decimals)),
        formattedAmount: `${sign}${display} ${tx.tokenSymbol || 'token'}`.trim(),
        decimalsKnown: decimals !== null,
        tokenSymbol: tx.tokenSymbol || 'Unknown token',
        tokenName: tx.tokenName,
        isToken: true,
        // The explorer's tokentx list only contains transfers that actually
        // happened, so these are successful by construction.
        status: 'SUCCESS',
        explorerUrl: `${net.explorer}/tx/${tx.hash}`,
      });
    }
  }

  const normalData = await fetchJson(new URLSearchParams({
    module: 'account', action: 'txlist', address, sort: 'desc', page: '1', offset: '15',
  }));

  if (Array.isArray(normalData?.result)) {
    for (const tx of normalData.result) {
      const rawValue = safeBigInt(tx.value);
      // Zero-value calls are contract interactions already represented by the
      // token list; skip only when that hash is genuinely already present.
      if (rawValue === 0n && history.some((h) => h.hash === tx.hash)) continue;

      const isIncoming = tx.to?.toLowerCase() === address;
      const counterparty = isIncoming ? tx.from : tx.to;
      const exact = formatUnits(rawValue, 18);

      history.push({
        hash: tx.hash,
        blockNumber: Number(tx.blockNumber) || 0,
        timeStamp: Number(tx.timeStamp) * 1000 || 0,
        from: tx.from,
        to: tx.to,
        counterparty,
        counterpartyEntity: identifyEntity(counterparty),
        direction: isIncoming ? 'IN' : 'OUT',
        amountExact: exact,
        value: Number(exact),
        formattedAmount: `${isIncoming ? '+' : '-'}${formatAmountForDisplay(rawValue, 18, 6).text} ${net.currency}`,
        decimalsKnown: true,
        tokenSymbol: net.currency,
        tokenName: net.currency,
        isToken: false,
        status: tx.isError === '0' ? 'SUCCESS' : 'FAILED',
        explorerUrl: `${net.explorer}/tx/${tx.hash}`,
      });
    }
  }

  history.sort((a, b) => b.timeStamp - a.timeStamp);
  return history;
}

export async function scanWalletLive(rawAddress, networkKey = 'ethereum') {
  const validated = validateAddress(rawAddress);
  if (!validated.ok) {
    return { valid: false, message: validated.reason, checksumSuggestion: validated.checksum || null };
  }

  const address = validated.address;
  const net = SUPPORTED_NETWORKS[networkKey] || SUPPORTED_NETWORKS.ethereum;

  const results = {
    address,
    valid: true,
    checksumVerified: validated.checksumVerified,
    network: net.name,
    currency: net.currency,
    explorerUrl: `${net.explorer}/address/${address}`,
    isContract: false,
    nonce: 0,
    nativeBalance: '0',
    nativeBalanceRaw: '0',
    tokenBalances: [],
    transactions: [],
    goplusAudit: null,
    riskScore: 0,
    riskLevel: 'LOW',
    riskFlags: [],
    dataGaps: [],
    entity: identifyEntity(address),
    timestamp: new Date().toISOString(),
  };

  // These three are independent; running them in sequence tripled the latency
  // of every scan for no reason.
  const [balHex, countHex, codeHex] = await Promise.all([
    robustRpcCall(net.rpcUrls, 'eth_getBalance', [address, 'latest']).catch((e) => {
      results.dataGaps.push(`Native balance unavailable (${e.message}).`);
      return null;
    }),
    robustRpcCall(net.rpcUrls, 'eth_getTransactionCount', [address, 'latest']).catch((e) => {
      results.dataGaps.push(`Transaction count unavailable (${e.message}).`);
      return null;
    }),
    robustRpcCall(net.rpcUrls, 'eth_getCode', [address, 'latest']).catch((e) => {
      results.dataGaps.push(`Contract bytecode check unavailable (${e.message}).`);
      return null;
    }),
  ]);

  const nativeRaw = hexToBigInt(balHex);
  results.nativeBalanceRaw = nativeRaw.toString();
  results.nativeBalance = formatUnits(nativeRaw, 18);
  results.nativeBalanceDisplay = formatAmountForDisplay(nativeRaw, 18, 6).text;
  results.nonce = Number(hexToBigInt(countHex));
  results.isContract = Boolean(codeHex && codeHex !== '0x' && codeHex !== '0x0');

  // Token balances, also in parallel. A failed call is recorded as unknown
  // rather than as a zero balance -- "no funds" and "could not check" lead to
  // opposite conclusions when judging a swept wallet.
  const balanceCalldata = encodeBalanceOf(address);
  results.tokenBalances = await Promise.all(net.tokens.map(async (tok) => {
    try {
      const hex = await robustRpcCall(net.rpcUrls, 'eth_call', [
        { to: tok.address, data: balanceCalldata }, 'latest',
      ]);
      const raw = hexToBigInt(hex);
      return {
        symbol: tok.symbol,
        tokenAddress: tok.address,
        balance: formatUnits(raw, tok.decimals),
        balanceDisplay: formatAmountForDisplay(raw, tok.decimals, 4).text,
        rawBalance: raw.toString(),
        known: true,
      };
    } catch (e) {
      return {
        symbol: tok.symbol,
        tokenAddress: tok.address,
        balance: null,
        balanceDisplay: 'unavailable',
        rawBalance: null,
        known: false,
        error: e.message,
      };
    }
  }));

  // 5. Fetch Full Live Transaction History
  try {
    results.transactions = await fetchWalletTransactionHistory(address, networkKey);
  } catch (e) {
    console.warn('History query note:', e);
  }

  // 6. Run GoPlus Security Multi-Chain Audit
  try {
    results.goplusAudit = await scanGoPlusAsset(address, networkKey);
  } catch (e) {
    console.warn('GoPlus audit note:', e);
  }

  // 7. Evaluate Forensic Risk Heuristics
  let score = 0;

  if (results.entity.type === 'FLAGGED_SCAMMER') {
    score += 85;
    results.riskFlags.push({
      title: 'Flagged Malicious Address',
      description: 'Listed in ChainShield\'s local threat table as a scam intermediary. '
        + 'This is a curated local list, not an external feed.',
    });
  }

  // The swept-wallet inference needs every balance to have actually been read.
  // Previously an unreachable RPC recorded 0 and the wallet was flagged as
  // emptied on the strength of a failed request.
  const balancesComplete = results.tokenBalances.every((t) => t.known)
    && !results.dataGaps.some((g) => g.startsWith('Native balance'));
  const tokensAllZero = results.tokenBalances.every((t) => t.known && t.rawBalance === '0');

  if (balancesComplete && results.nonce > 0 && nativeRaw < 100000000000000n && tokensAllZero) {
    score += 35;
    results.riskFlags.push({
      title: 'Swept / Burner Wallet Signature',
      description: 'Has sent transactions but holds effectively nothing now, in the tokens checked. '
        + 'Common for a cashout hop, though also true of any wallet that was simply emptied.',
    });
  } else if (!balancesComplete) {
    results.dataGaps.push(
      'Balance data incomplete, so the swept-wallet check was skipped rather than guessed.',
    );
  }

  if (results.entity.type === 'CEX_EXCHANGE' || results.entity.type === 'CEX_DEPOSIT') {
    results.riskFlags.push({
      title: 'Centralized Exchange Endpoint',
      description: 'Deposits to this address are governed by mandatory KYC identity verification.'
    });
  }

  // Incorporate GoPlus score if present
  if (results.goplusAudit && results.goplusAudit.riskScore > 0) {
    score = Math.max(score, results.goplusAudit.riskScore);
    results.goplusAudit.flags.forEach(f => {
      results.riskFlags.push({
        title: f.title,
        description: f.description
      });
    });
  }

  results.riskScore = Math.min(100, score);
  results.riskLevel = results.riskScore >= 75 ? 'CRITICAL' : results.riskScore >= 40 ? 'SUSPICIOUS' : 'LOW';

  return results;
}

export async function scanTransactionLive(rawTxHash, networkKey = 'ethereum') {
  const check = validateTxHash(rawTxHash);
  if (!check.ok) {
    return { found: false, valid: false, message: check.reason };
  }
  const txHash = check.hash;
  const net = SUPPORTED_NETWORKS[networkKey] || SUPPORTED_NETWORKS.ethereum;

  const results = {
    txHash,
    valid: true,
    network: net.name,
    networkKey: net.id,
    explorerUrl: `${net.explorer}/tx/${txHash}`,
    status: 'UNKNOWN',
    from: null,
    to: null,
    nativeValue: '0',
    nativeSymbol: net.currency,
    blockNumber: null,
    timestamp: null,
    gasUsed: 0,
    feePaid: null,
    isTokenTransfer: false,
    transfers: [],
    transferCount: 0,
    tokenTransferData: null,
    hops: [],
    notes: [],
    scannedAt: new Date().toISOString(),
  };

  let tx;
  try {
    tx = await robustRpcCall(net.rpcUrls, 'eth_getTransactionByHash', [txHash]);
  } catch (err) {
    return { found: false, valid: true, message: `Could not reach ${net.name}: ${err.message}` };
  }

  if (!tx) {
    return {
      found: false,
      valid: true,
      message: `Transaction not found on ${net.name}. It may be on a different chain, `
        + 'still pending, or dropped from the mempool.',
    };
  }

  results.found = true;
  results.from = tx.from ? toChecksumAddress(tx.from) : null;
  // A contract-creation transaction has no `to`.
  results.to = tx.to ? toChecksumAddress(tx.to) : null;
  results.isContractCreation = !tx.to;
  results.nativeValue = formatUnits(hexToBigInt(tx.value), 18);
  results.blockNumber = tx.blockNumber ? Number(hexToBigInt(tx.blockNumber)) : null;

  if (!tx.blockNumber) {
    results.status = 'PENDING';
    results.notes.push('Still pending: not yet included in a block, so nothing is final.');
    return results;
  }

  try {
    const receipt = await robustRpcCall(net.rpcUrls, 'eth_getTransactionReceipt', [txHash]);
    if (!receipt) {
      results.notes.push('Receipt not available yet; transfer details could not be decoded.');
      return results;
    }

    results.status = receipt.status === '0x1' ? 'SUCCESS' : 'FAILED';
    results.gasUsed = Number(hexToBigInt(receipt.gasUsed));

    const effectiveGasPrice = hexToBigInt(receipt.effectiveGasPrice ?? tx.gasPrice);
    if (effectiveGasPrice > 0n) {
      results.feePaid = formatUnits(hexToBigInt(receipt.gasUsed) * effectiveGasPrice, 18);
    }

    // A reverted transaction still emits no transfers; saying so explicitly
    // matters, because "no transfers found" reads like a decode failure.
    if (results.status === 'FAILED') {
      results.notes.push('Transaction reverted: no funds moved, and any transfer logs are void.');
      return results;
    }

    const transfers = await decodeTransfers(net, receipt);
    results.transfers = transfers;
    results.transferCount = transfers.length;
    results.isTokenTransfer = transfers.length > 0;

    if (transfers.some((t) => !t.amountResolved)) {
      results.notes.push(
        'At least one token would not report its decimals, so that amount is shown as a raw '
        + 'integer. Confirm it on the block explorer before quoting it.',
      );
    }
    if (transfers.length > 1) {
      results.notes.push(
        `${transfers.length} token transfers in this transaction. The highlighted one is the `
        + 'largest of the dominant token; the full list is below.',
      );
    }

    const primary = selectPrimaryTransfer(transfers);
    if (primary) {
      results.tokenTransferData = {
        tokenContract: primary.tokenContract,
        tokenSymbol: primary.tokenSymbol,
        sender: primary.sender,
        recipient: primary.recipient,
        amount: primary.amount,
        amountDisplay: primary.amountDisplay,
        amountResolved: primary.amountResolved,
        decimals: primary.decimals,
        decimalsSource: primary.decimalsSource,
        rawAmount: primary.rawAmount,
      };
    }

    results.hops = buildHops(results, primary);
    return results;
  } catch (err) {
    results.notes.push(`Receipt decode incomplete: ${err.message}`);
    return results;
  }
}

/**
 * Build the hop list from what the receipt actually proves.
 *
 * This describes one transaction: sender to recipient. It is not a traced
 * money trail -- the previous version labelled step 2 "Deposited into Exchange"
 * from a local address table, which asserted a conclusion the transaction did
 * not contain. Following funds onward is fetchOnwardHops(), which is explicit
 * about being a separate query.
 */
function buildHops(results, primary) {
  const sender = primary?.sender || results.from;
  const recipient = primary?.recipient || results.to;
  if (!sender || !recipient) return [];

  const recipientEntity = identifyEntity(recipient);
  const movement = primary
    ? `Sent ${primary.amountDisplay} ${primary.amountResolved ? primary.tokenSymbol : ''}`.trim()
    : `Sent ${results.nativeValue} ${results.nativeSymbol}`;

  return [
    {
      step: 1,
      label: 'Sender',
      address: sender,
      entity: identifyEntity(sender),
      action: movement,
    },
    {
      step: 2,
      label: 'Recipient',
      address: recipient,
      entity: recipientEntity,
      action: recipientEntity.type === 'CEX_DEPOSIT' || recipientEntity.type === 'CEX_EXCHANGE'
        ? 'Address is tagged as an exchange deposit endpoint in ChainShield\'s local table'
        : 'Received funds',
    },
  ];
}

/**
 * Follow funds forward from a recipient address, one hop at a time.
 *
 * This is the real answer to the stubbed transaction endpoint. Constraints
 * worth knowing before reading the output:
 *
 *   - It follows the largest outgoing transfer of the same token at each hop.
 *     That is a heuristic, not the truth: a splitter that fans funds into ten
 *     equal parts will be followed down one branch only.
 *   - It only sees transfers the explorer API returns, and only those after the
 *     source transaction's block.
 *   - Reaching an exchange deposit address is where tracing stops being useful
 *     anyway: past that point the chain shows an omnibus wallet, and only the
 *     exchange can say whose account it was.
 *
 * Each hop carries `confidence` so the UI cannot present a guess as a finding.
 */
export async function fetchOnwardHops(startAddress, {
  networkKey = 'ethereum',
  tokenContract = null,
  fromBlock = 0,
  maxHops = 4,
  minFraction = 0.5,
} = {}) {
  const net = SUPPORTED_NETWORKS[networkKey] || SUPPORTED_NETWORKS.ethereum;
  const validated = validateAddress(startAddress);
  if (!validated.ok) return { ok: false, reason: validated.reason, hops: [] };
  if (!net.apiBase) return { ok: false, reason: `No explorer API configured for ${net.name}.`, hops: [] };

  const hops = [];
  const visited = new Set([validated.lower]);
  let current = validated.lower;
  let blockFloor = fromBlock;
  let terminal = null;

  for (let depth = 0; depth < maxHops; depth += 1) {
    let transfers;
    try {
      transfers = await fetchTokenTransfers(net, current, tokenContract);
    } catch (e) {
      terminal = { reason: `Explorer query failed at hop ${depth + 1}: ${e.message}` };
      break;
    }

    const outgoing = transfers
      .filter((t) => t.from?.toLowerCase() === current)
      .filter((t) => t.blockNumber >= blockFloor)
      .filter((t) => !visited.has(t.to?.toLowerCase()));

    if (outgoing.length === 0) {
      terminal = { reason: 'No onward transfer found from this address.' };
      break;
    }

    const total = outgoing.reduce((acc, t) => acc + t.rawValue, 0n);
    const largest = outgoing.reduce((a, b) => (b.rawValue > a.rawValue ? b : a));
    // Integer percentage: avoids a float divide on values that may exceed 2^53.
    const sharePct = total > 0n ? Number((largest.rawValue * 100n) / total) : 0;

    const next = largest.to.toLowerCase();
    const entity = identifyEntity(next);

    hops.push({
      step: hops.length + 1,
      from: toChecksumAddress(current),
      to: toChecksumAddress(next),
      entity,
      txHash: largest.hash,
      blockNumber: largest.blockNumber,
      timeStamp: largest.timeStamp,
      tokenSymbol: largest.tokenSymbol,
      amountDisplay: largest.amountDisplay,
      shareOfOutflowPct: sharePct,
      branchCount: outgoing.length,
      // One clear onward path is a strong inference; a 5-way split followed
      // down its biggest leg is not, and must not be drawn the same way.
      confidence: outgoing.length === 1 ? 'high' : sharePct >= 80 ? 'medium' : 'low',
      explorerUrl: `${net.explorer}/tx/${largest.hash}`,
    });

    visited.add(next);
    current = next;
    blockFloor = largest.blockNumber;

    if (sharePct < minFraction * 100 && outgoing.length > 1) {
      terminal = {
        reason: `Funds split across ${outgoing.length} destinations; the largest leg is only `
          + `${sharePct}% of the outflow. Tracing one branch past this point would be a guess.`,
      };
      break;
    }

    if (entity.type === 'CEX_DEPOSIT' || entity.type === 'CEX_EXCHANGE') {
      terminal = {
        reason: `Reached ${entity.name}, an exchange endpoint. On-chain tracing ends here: `
          + 'the account behind it is only visible to the exchange, via a law-enforcement request.',
        reachedExchange: true,
        exchangeName: entity.name,
      };
      break;
    }
  }

  return {
    ok: true,
    network: net.name,
    startAddress: validated.address,
    hops,
    terminal: terminal || { reason: `Stopped after the ${maxHops}-hop limit.` },
    method: 'Largest same-token outgoing transfer per hop, via the chain explorer API. '
      + 'Heuristic: it does not follow every branch.',
  };
}

/** Normalised token-transfer list for one address from the explorer API. */
async function fetchTokenTransfers(net, address, tokenContract = null) {
  const params = new URLSearchParams({
    module: 'account',
    action: 'tokentx',
    address,
    sort: 'asc',
    page: '1',
    offset: '100',
  });
  if (tokenContract) params.set('contractaddress', tokenContract);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), RPC_TIMEOUT_MS);
  try {
    const resp = await fetch(`${net.apiBase}?${params}`, { signal: controller.signal });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const json = await resp.json();
    if (!Array.isArray(json.result)) return [];

    return json.result.map((tx) => {
      const decimals = normaliseDecimals(tx.tokenDecimal);
      const rawValue = safeBigInt(tx.value);
      return {
        hash: tx.hash,
        from: tx.from,
        to: tx.to,
        blockNumber: Number(tx.blockNumber) || 0,
        timeStamp: Number(tx.timeStamp) * 1000 || null,
        tokenSymbol: tx.tokenSymbol || 'Unknown token',
        tokenContract: tx.contractAddress,
        decimals,
        rawValue,
        amountDisplay: decimals === null
          ? `${rawValue.toString()} (raw)`
          : formatAmountForDisplay(rawValue, decimals).text,
      };
    });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * `Number(tx.tokenDecimal) || 6` treated a legitimate 0 as 6, shifting the
 * amount for every zero-decimal token by a million. Absent stays absent.
 */
function normaliseDecimals(value) {
  if (value === null || value === undefined || value === '') return null;
  const n = Number(value);
  return Number.isInteger(n) && n >= 0 && n <= 36 ? n : null;
}

function safeBigInt(value) {
  try {
    return BigInt(value ?? '0');
  } catch {
    return 0n;
  }
}

export function generateLawEnforcementDossier(incident) {
  const dateStr = new Date().toUTCString();
  return `
================================================================================
          OFFICIAL CYBERCRIME & FRAUD INCIDENT REPORT (CHAINSHIELD)
================================================================================

DATE GENERATED: ${dateStr}
CLASSIFICATION: CONFIDENTIAL / LAW ENFORCEMENT & EXCHANGE DISCLOSURE
CASE REFERENCE: ${incident.incidentId || 'CS-FRAUD-' + Date.now()}

--------------------------------------------------------------------------------
1. EXECUTIVE SUMMARY
--------------------------------------------------------------------------------
This report documents an unauthorized account takeover, credential harvesting,
and cryptocurrency payout redirection fraud targeting a user of the platform:
"${incident.victimPlatform || '[platform not recorded]'}".

The attacker deployed a deceptive impersonation link to gain access to the victim's
account dashboard, removed the legitimate payout address, and substituted their own
intermediary wallet address: ${incident.scammerAddress}.

--------------------------------------------------------------------------------
2. FINANCIAL LOSS & ASSET DETAILS
--------------------------------------------------------------------------------
* Stolen Amount: ${incident.stolenAmount || 'not recorded'}
* Asset / Standard: ${incident.token || 'not recorded'}
* Token Contract: ${incident.tokenContract || 'not recorded'}
* Network: Ethereum Mainnet / EVM Compatible

--------------------------------------------------------------------------------
3. BLOCKCHAIN FORENSICS & ON-CHAIN TRAIL
--------------------------------------------------------------------------------
* Initial Payout Transaction Hash (TXID):
  ${incident.txHash}

* Scammer Intermediary / Collecting Wallet:
  ${incident.scammerAddress}

* Destination Wallet / Cashout Address:
  ${incident.destinationAddress || '[not recorded - no onward hop has been established]'}

--------------------------------------------------------------------------------
4. PERPETRATOR DE-ANONYMIZATION VECTOR (EXCHANGE KYC)
--------------------------------------------------------------------------------
Under standard KYC regulations, exchanges and service providers hold:
  1. Full legal name & government-issued identification / passport
  2. Verified phone number & primary email address
  3. Residential billing address and linked banking / withdrawal details
  4. IP address & device telemetry logs at the time of deposit

--------------------------------------------------------------------------------
5. REQUESTED LAW ENFORCEMENT & EXCHANGE ACTION
--------------------------------------------------------------------------------
1. EXCHANGE COMPLIANCE:
   - Place an immediate temporary compliance freeze on the beneficiary account
     linked to deposit address: ${incident.destinationAddress || '[not recorded]'}
   - Preserve all audit trails and IP connection logs.

2. LAW ENFORCEMENT AGENCIES (IC3 / POLICE):
   - Issue an official Law Enforcement Request (LER) via the exchange compliance portal
     requesting full KYC disclosure of the recipient.

--------------------------------------------------------------------------------
REPORT GENERATED VIA CHAINSHIELD - URL & BLOCKCHAIN FORENSICS SUITE
================================================================================
`.trim();
}
