/**
 * Blockchain Forensics, Multi-Chain Transaction Parser & Flow Builder
 */

export const KNOWN_ENTITIES = {
  '0x28c6c06298d514db089934071355e5743bf21d60': { name: 'Binance: Hot Wallet 6', type: 'CEX_HOT_WALLET' },
  '0x21a31ee1afc51d94c2efccaa2092ad1028285549': { name: 'Binance: Hot Wallet 14', type: 'CEX_HOT_WALLET' },
  '0xdfd5293d8e347dFe59E90eFd55b2956a1343963d': { name: 'Binance: Deposit Gateway', type: 'CEX_DEPOSIT' },
  '0xd23ac29c1e1949d0c5864b4a23a01cc3e4dd236b': { name: 'Atlas Capture Scammer Intermediary', type: 'SCAMMER_COLLECTOR' },
  '0xdac17f958d2ee523a2206206994597c13d831ec7': { name: 'Tether USD (USDT)', type: 'TOKEN_CONTRACT' },
  '0x55d398326f99059ff775485246999027b3197955': { name: 'Binance-Peg BSC-USD', type: 'TOKEN_CONTRACT' }
};

export const SAMPLE_INCIDENT = {
  incidentId: 'INC-2026-ATLAS-01',
  victimPlatform: 'Atlas Capture Contractor Payout',
  stolenAmount: '$146.07 USD',
  token: 'USDT (ERC-20)',
  scammerAddress: '0xd23Ac29C1e1949D0c5864B4a23a01cc3e4dd236b',
  txHash: '0x44e5dbb257694dd3297e3a24808a6098f2bce9816bc9b202879104dccec911e7',
  destinationExchange: 'Binance (Deposit Address)',
  destinationAddress: '0x28C6c06298d514Db089934071355E5743bf21d60',
  summary: 'Phishing attack compromised user session on Atlas Capture. Scammer altered payout wallet to 0xd23Ac2...236b, received $146.07 USDT, and forwarded funds directly into a Binance KYC-verified deposit wallet.'
};

export function identifyEntity(address) {
  if (!address) return { name: 'Unknown Wallet', type: 'EOA' };
  const lower = address.toLowerCase();
  return KNOWN_ENTITIES[lower] || { name: `External Address (${address.slice(0, 6)}...${address.slice(-4)})`, type: 'EOA' };
}

export function buildTransactionFlowGraph(scammerAddr, txHash, amount = '146.07', token = 'USDT') {
  const victimNode = {
    id: 'node-victim',
    label: 'Atlas Capture Platform',
    sublabel: 'Legitimate Contractor Payout Source',
    type: 'VICTIM_SOURCE',
    color: '#38bdf8',
    icon: 'Briefcase'
  };

  const intermediaryNode = {
    id: 'node-scammer',
    label: 'Scammer Intercept Wallet',
    sublabel: `${scammerAddr.slice(0, 6)}...${scammerAddr.slice(-4)}`,
    fullAddress: scammerAddr,
    type: 'SCAMMER_INTERMEDIARY',
    color: '#ef4444',
    icon: 'AlertTriangle'
  };

  const binanceNode = {
    id: 'node-binance',
    label: 'Binance Deposit Wallet',
    sublabel: 'KYC Identity-Linked Cluster',
    fullAddress: '0x28C6c06298d514Db089934071355E5743bf21d60',
    type: 'CEX_DEPOSIT',
    color: '#f59e0b',
    icon: 'Building2'
  };

  const edges = [
    {
      id: 'edge-1',
      from: 'node-victim',
      to: 'node-scammer',
      label: `${amount} ${token}`,
      note: 'Unauthorized Payout Intercept',
      txHash: txHash
    },
    {
      id: 'edge-2',
      from: 'node-scammer',
      to: 'node-binance',
      label: `Swept ${amount} ${token}`,
      note: 'Forwarded to CEX for Cashout',
      txHash: '0x39a1f2b... (Forwarding TX)'
    }
  ];

  return {
    nodes: [victimNode, intermediaryNode, binanceNode],
    edges
  };
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
"${incident.victimPlatform || 'Atlas Capture'}".

The attacker deployed a deceptive impersonation link to gain access to the victim's
account dashboard, removed the legitimate ERC-20 USDT payout address, and substituted
their own intermediary wallet address. Upon execution of the contractual payout,
the funds were deposited to the attacker's wallet and promptly forwarded into a
Binance exchange deposit account.

--------------------------------------------------------------------------------
2. FINANCIAL LOSS & ASSET DETAILS
--------------------------------------------------------------------------------
* Stolen Amount: ${incident.stolenAmount || '$146.07 USD'}
* Asset / Standard: ${incident.token || 'USDT (Tether USD ERC-20)'}
* Network: Ethereum Mainnet / EVM Compatible

--------------------------------------------------------------------------------
3. BLOCKCHAIN FORENSICS & ON-CHAIN TRAIL
--------------------------------------------------------------------------------
* Initial Payout Transaction Hash (TXID):
  ${incident.txHash}

* Scammer Intermediary / Collecting Wallet:
  ${incident.scammerAddress}

* Destination Centralized Exchange (CEX):
  ${incident.destinationExchange || 'Binance'}

* CEX Deposit Wallet Address:
  ${incident.destinationAddress || '0x28C6c06298d514Db089934071355E5743bf21d60'}

--------------------------------------------------------------------------------
4. PERPETRATOR DE-ANONYMIZATION VECTOR (BINANCE KYC)
--------------------------------------------------------------------------------
Because the funds were deposited directly into a centralized exchange (Binance),
the receiving deposit address is permanently indexed to an internal Binance Account ID.
Under standard KYC (Know Your Customer) regulations, Binance holds:
  1. Full legal name & government-issued identification / passport
  2. Verified phone number & primary email address
  3. Residential billing address and linked banking / withdrawal details
  4. IP address & device telemetry logs at the time of deposit

--------------------------------------------------------------------------------
5. REQUESTED LAW ENFORCEMENT & EXCHANGE ACTION
--------------------------------------------------------------------------------
1. BINANCE SECURITY:
   - Place an immediate temporary compliance freeze on the beneficiary account
     linked to deposit address: ${incident.destinationAddress || '0x28C6c...'}
   - Preserve all audit trails and IP connection logs.

2. LAW ENFORCEMENT AGENCIES (IC3 / POLICE):
   - Issue an official Law Enforcement Request (LER) via Binance's Government
     & Law Enforcement Portal requesting full KYC disclosure of the recipient.

--------------------------------------------------------------------------------
REPORT GENERATED VIA CHAINSHIELD - AI PHISHING & FORENSICS SUITE
================================================================================
`.trim();
}
