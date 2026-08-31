/**
 * Blockchain Forensics Engine
 * Real-Time Multi-Chain JSON-RPC Live Scanner, Transaction History Indexer & Entity Tracing
 */

export const SUPPORTED_NETWORKS = {
  ethereum: {
    id: 'ethereum',
    name: 'Ethereum Mainnet',
    currency: 'ETH',
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
  stolenAmount: '$146.07 USD',
  token: 'USDC / USDT (ERC-20)',
  scammerAddress: '0xd23Ac29C1e1949D0c5864B4a23a01cc3e4dd236b',
  txHash: '0x44e5dbb257694dd3297e3a24808a6098f2bce9816bc9b202879104dccec911e7',
  destinationExchange: 'Binance / Receiving Wallet',
  destinationAddress: '0xdb254315a6abdcbebf65a7d538bb275790c07857',
  summary: 'Phishing attack compromised user credentials on Atlas Capture. Scammer altered payout wallet to 0xd23Ac2...236b, received funds, and swept them to 0xdb2543...7857.'
};

export const SAMPLE_INCIDENT = DEFAULT_INCIDENT;

/**
 * Execute RPC call with automatic failover across fallback nodes
 */
async function robustRpcCall(rpcUrls, method, params) {
  let lastError = null;

  for (const url of rpcUrls) {
    try {
      const payload = {
        jsonrpc: '2.0',
        method: method,
        params: params,
        id: Math.floor(Math.random() * 10000)
      };

      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!response.ok) throw new Error(`HTTP ${response.status}`);

      const json = await response.json();
      if (json.error) throw new Error(json.error.message || 'RPC error');

      return json.result;
    } catch (err) {
      lastError = err;
    }
  }

  throw lastError || new Error('All RPC endpoints failed to respond.');
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
 * Fetch Full On-Chain Transaction History for a Wallet
 */
export async function fetchWalletTransactionHistory(rawAddress, networkKey = 'ethereum') {
  const address = rawAddress.trim().toLowerCase();
  const net = SUPPORTED_NETWORKS[networkKey] || SUPPORTED_NETWORKS.ethereum;
  const history = [];

  if (!net.apiBase) return [];

  try {
    // 1. Fetch Token Transfers (USDT, USDC, etc.)
    const tokenUrl = `${net.apiBase}?module=account&action=tokentx&address=${address}&sort=desc&page=1&offset=25`;
    const tokenResp = await fetch(tokenUrl);
    if (tokenResp.ok) {
      const tokenData = await tokenResp.json();
      if (Array.isArray(tokenData.result)) {
        tokenData.result.forEach(tx => {
          const decimals = Number(tx.tokenDecimal) || 6;
          const formattedValue = Number(BigInt(tx.value || '0')) / 10 ** decimals;
          const isIncoming = tx.to?.toLowerCase() === address;
          const counterparty = isIncoming ? tx.from : tx.to;

          history.push({
            hash: tx.hash,
            blockNumber: Number(tx.blockNumber),
            timeStamp: Number(tx.timeStamp) * 1000,
            from: tx.from,
            to: tx.to,
            counterparty,
            counterpartyEntity: identifyEntity(counterparty),
            direction: isIncoming ? 'IN' : 'OUT',
            value: formattedValue,
            formattedAmount: `${isIncoming ? '+' : '-'}${formattedValue.toFixed(2)} ${tx.tokenSymbol || 'TOKEN'}`,
            tokenSymbol: tx.tokenSymbol || 'TOKEN',
            tokenName: tx.tokenName,
            isToken: true,
            status: 'SUCCESS',
            explorerUrl: `${net.explorer}/tx/${tx.hash}`
          });
        });
      }
    }

    // 2. Fetch Normal Native Transactions (ETH, BNB, etc.)
    const normalUrl = `${net.apiBase}?module=account&action=txlist&address=${address}&sort=desc&page=1&offset=15`;
    const normalResp = await fetch(normalUrl);
    if (normalResp.ok) {
      const normalData = await normalResp.json();
      if (Array.isArray(normalData.result)) {
        normalData.result.forEach(tx => {
          const formattedValue = Number(BigInt(tx.value || '0')) / 1e18;
          if (formattedValue > 0 || !history.some(h => h.hash === tx.hash)) {
            const isIncoming = tx.to?.toLowerCase() === address;
            const counterparty = isIncoming ? tx.from : tx.to;

            history.push({
              hash: tx.hash,
              blockNumber: Number(tx.blockNumber),
              timeStamp: Number(tx.timeStamp) * 1000,
              from: tx.from,
              to: tx.to,
              counterparty,
              counterpartyEntity: identifyEntity(counterparty),
              direction: isIncoming ? 'IN' : 'OUT',
              value: formattedValue,
              formattedAmount: `${isIncoming ? '+' : '-'}${formattedValue.toFixed(4)} ${net.currency}`,
              tokenSymbol: net.currency,
              tokenName: net.currency,
              isToken: false,
              status: tx.isError === '0' ? 'SUCCESS' : 'FAILED',
              explorerUrl: `${net.explorer}/tx/${tx.hash}`
            });
          }
        });
      }
    }

    // Sort by timestamp descending
    history.sort((a, b) => b.timeStamp - a.timeStamp);
    return history;
  } catch (err) {
    console.warn('Transaction history fetch error:', err);
    return [];
  }
}

/**
 * Scan a single Wallet on a specific chain in real time
 */
export async function scanWalletLive(rawAddress, networkKey = 'ethereum') {
  const address = rawAddress.trim();
  const net = SUPPORTED_NETWORKS[networkKey] || SUPPORTED_NETWORKS.ethereum;

  const results = {
    address,
    network: net.name,
    currency: net.currency,
    explorerUrl: `${net.explorer}/address/${address}`,
    isContract: false,
    nonce: 0,
    nativeBalance: 0,
    tokenBalances: [],
    transactions: [],
    riskScore: 0,
    riskLevel: 'LOW',
    riskFlags: [],
    entity: identifyEntity(address),
    timestamp: new Date().toISOString()
  };

  // 1. Check Native Balance
  try {
    const balHex = await robustRpcCall(net.rpcUrls, 'eth_getBalance', [address, 'latest']);
    if (balHex && balHex !== '0x') {
      results.nativeBalance = Number(BigInt(balHex)) / 1e18;
    }
  } catch (e) {
    console.warn('Native balance query note:', e.message);
  }

  // 2. Check Nonce / Transaction Count
  try {
    const countHex = await robustRpcCall(net.rpcUrls, 'eth_getTransactionCount', [address, 'latest']);
    if (countHex && countHex !== '0x') {
      results.nonce = Number(BigInt(countHex));
    }
  } catch (e) {
    console.warn('Nonce query note:', e.message);
  }

  // 3. Check Contract bytecode
  try {
    const codeHex = await robustRpcCall(net.rpcUrls, 'eth_getCode', [address, 'latest']);
    results.isContract = Boolean(codeHex && codeHex !== '0x' && codeHex !== '0x0');
  } catch (e) {
    console.warn('Code query note:', e.message);
  }

  // 4. Query ERC-20 Token Balances (USDT, USDC)
  const cleanAddress = address.startsWith('0x') ? address.slice(2) : address;
  const addressPadded = cleanAddress.toLowerCase().padStart(64, '0');
  const balanceOfSig = '0x70a08231' + addressPadded;

  for (const tok of net.tokens) {
    try {
      const tokenBalHex = await robustRpcCall(net.rpcUrls, 'eth_call', [
        { to: tok.address, data: balanceOfSig },
        'latest'
      ]);
      if (tokenBalHex && tokenBalHex !== '0x') {
        const rawVal = BigInt(tokenBalHex);
        const formatted = Number(rawVal) / 10 ** tok.decimals;
        results.tokenBalances.push({
          symbol: tok.symbol,
          balance: formatted,
          tokenAddress: tok.address
        });
      }
    } catch (e) {
      results.tokenBalances.push({
        symbol: tok.symbol,
        balance: 0.00,
        tokenAddress: tok.address
      });
    }
  }

  // 5. Fetch Full Live Transaction History
  try {
    results.transactions = await fetchWalletTransactionHistory(address, networkKey);
  } catch (e) {
    console.warn('History query note:', e);
  }

  // 6. Evaluate Forensic Risk Heuristics
  let score = 0;

  if (results.entity.type === 'FLAGGED_SCAMMER') {
    score += 85;
    results.riskFlags.push({
      title: 'Flagged Malicious Address',
      description: 'Explicitly indexed in threat intelligence database as an active scam intermediary.'
    });
  }

  const totalTokens = results.tokenBalances.reduce((acc, t) => acc + t.balance, 0);
  if (results.nonce > 0 && results.nativeBalance < 0.0001 && totalTokens === 0) {
    score += 35;
    results.riskFlags.push({
      title: 'Swept / Burner Wallet Signature',
      description: 'Non-zero transaction history with zero current balance (typical pattern for phishing cashout hops).'
    });
  }

  if (results.entity.type === 'CEX_EXCHANGE' || results.entity.type === 'CEX_DEPOSIT') {
    results.riskFlags.push({
      title: 'Centralized Exchange Endpoint',
      description: 'Deposits to this address are governed by mandatory KYC identity verification.'
    });
  }

  results.riskScore = Math.min(100, score);
  results.riskLevel = results.riskScore >= 70 ? 'CRITICAL' : results.riskScore >= 30 ? 'SUSPICIOUS' : 'LOW';

  return results;
}

/**
 * Scan a single Transaction Hash across EVM networks
 */
export async function scanTransactionLive(rawTxHash, networkKey = 'ethereum') {
  const txHash = rawTxHash.trim();
  const net = SUPPORTED_NETWORKS[networkKey] || SUPPORTED_NETWORKS.ethereum;

  const results = {
    txHash,
    network: net.name,
    explorerUrl: `${net.explorer}/tx/${txHash}`,
    status: 'UNKNOWN',
    from: null,
    to: null,
    value: 0,
    blockNumber: null,
    gasUsed: 0,
    isTokenTransfer: false,
    tokenTransferData: null,
    hops: [],
    timestamp: new Date().toISOString()
  };

  try {
    const tx = await robustRpcCall(net.rpcUrls, 'eth_getTransactionByHash', [txHash]);
    if (!tx) {
      return { found: false, message: `Transaction not found or not yet indexed on ${net.name}.` };
    }

    results.found = true;
    results.from = tx.from;
    results.to = tx.to;
    results.value = Number(BigInt(tx.value || '0x0')) / 1e18;
    results.blockNumber = tx.blockNumber ? Number(BigInt(tx.blockNumber)) : null;

    try {
      const receipt = await robustRpcCall(net.rpcUrls, 'eth_getTransactionReceipt', [txHash]);
      if (receipt) {
        results.status = receipt.status === '0x1' ? 'SUCCESS' : 'FAILED';
        results.gasUsed = Number(BigInt(receipt.gasUsed || '0x0'));

        const transferTopic = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
        const transferLogs = receipt.logs?.filter(l => l.topics?.[0] === transferTopic) || [];

        if (transferLogs.length > 0) {
          results.isTokenTransfer = true;
          // Primary transfer log (highest value or targeted)
          const primaryLog = transferLogs[0];
          const sender = '0x' + primaryLog.topics[1].slice(26);
          const recipient = '0x' + primaryLog.topics[2].slice(26);
          const rawAmount = BigInt(primaryLog.data || '0x0');

          const matchedToken = net.tokens.find(t => t.address.toLowerCase() === primaryLog.address.toLowerCase());
          const decimals = matchedToken ? matchedToken.decimals : 6;
          const symbol = matchedToken ? matchedToken.symbol : 'USDC / TOKEN';
          const formattedAmount = Number(rawAmount) / 10 ** decimals;

          results.tokenTransferData = {
            tokenContract: primaryLog.address,
            tokenSymbol: symbol,
            sender,
            recipient,
            amount: formattedAmount
          };

          results.hops = [
            {
              step: 1,
              label: 'Transaction Origin',
              address: sender,
              entity: identifyEntity(sender),
              action: `Transferred ${formattedAmount.toFixed(2)} ${symbol}`
            },
            {
              step: 2,
              label: 'Receiving Wallet',
              address: recipient,
              entity: identifyEntity(recipient),
              action: identifyEntity(recipient).type === 'CEX_DEPOSIT' ? 'Deposited into Exchange' : 'Received Funds'
            }
          ];
        }
      }
    } catch (e) {
      console.warn('Receipt query note:', e);
    }

    return results;
  } catch (err) {
    return { found: false, message: `Transaction query note: ${err.message}` };
  }
}

/**
 * Generate official Law Enforcement & Binance Dossier
 */
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
"${incident.victimPlatform || 'Atlas Capture'}".

The attacker deployed a deceptive impersonation link to gain access to the victim's
account dashboard, removed the legitimate ERC-20 USDT payout address, and substituted
their own intermediary wallet address. Upon execution of the contractual payout,
the funds were deposited to the attacker's wallet and promptly forwarded to an
external destination wallet: ${incident.destinationAddress || '0xdb2543...7857'}.

--------------------------------------------------------------------------------
2. FINANCIAL LOSS & ASSET DETAILS
--------------------------------------------------------------------------------
* Stolen Amount: ${incident.stolenAmount || '$146.07 USD'}
* Asset / Standard: ${incident.token || 'USDC / USDT (ERC-20)'}
* Network: Ethereum Mainnet / EVM Compatible

--------------------------------------------------------------------------------
3. BLOCKCHAIN FORENSICS & ON-CHAIN TRAIL
--------------------------------------------------------------------------------
* Initial Payout Transaction Hash (TXID):
  ${incident.txHash}

* Scammer Intermediary / Collecting Wallet:
  ${incident.scammerAddress}

* Destination Wallet / Cashout Address:
  ${incident.destinationAddress || '0xdb254315a6abdcbebf65a7d538bb275790c07857'}

--------------------------------------------------------------------------------
4. PERPETRATOR DE-ANONYMIZATION VECTOR (EXCHANGE KYC)
--------------------------------------------------------------------------------
Because the funds were routed through centralized and account abstraction channels,
the receiving wallet address is directly linked to exchange accounts and funding sources.
Under standard KYC (Know Your Customer) regulations, exchanges hold:
  1. Full legal name & government-issued identification / passport
  2. Verified phone number & primary email address
  3. Residential billing address and linked banking / withdrawal details
  4. IP address & device telemetry logs at the time of deposit

--------------------------------------------------------------------------------
5. REQUESTED LAW ENFORCEMENT & EXCHANGE ACTION
--------------------------------------------------------------------------------
1. EXCHANGE COMPLIANCE:
   - Place an immediate temporary compliance freeze on the beneficiary account
     linked to deposit address: ${incident.destinationAddress || '0xdb254...'}
   - Preserve all audit trails and IP connection logs.

2. LAW ENFORCEMENT AGENCIES (IC3 / POLICE):
   - Issue an official Law Enforcement Request (LER) via the exchange compliance portal
     requesting full KYC disclosure of the recipient.

--------------------------------------------------------------------------------
REPORT GENERATED VIA CHAINSHIELD - AI PHISHING & FORENSICS SUITE
================================================================================
`.trim();
}
