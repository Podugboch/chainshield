# 🛡️ ChainShield | Phishing Detection & Crypto Forensics

**ChainShield** is a phishing-detection and cryptocurrency-forensics application. It
scores suspicious links and messages against named rules, reads ERC-20 transfers
straight off-chain, screens payout addresses against a shared blocklist, and
assembles an incident dossier you can file with police or an exchange.

Every score it reports is traceable to a rule you can read in the source. There is
no model, and no claim it cannot show its working for.

---

## ✨ Features

1. **URL scanner** — risk scores (0–100) from Levenshtein-distance typosquatting
   checks, brand-impersonation matching, throwaway-TLD inspection and raw-IP host
   detection. Every point of the score comes with the rule that produced it.
   Covers spoofs of **Atlas Capture**, **Binance**, **MetaMask** and **Coinbase**.
2. **Message & email analyser** — flags urgency and coercion patterns, and
   unsolicited requests to change a payout wallet.
3. **Crypto forensics** — reads transactions and ERC-20 `Transfer` logs from public
   RPC endpoints: exact integer amounts, per-token decimals, EIP-55 validation, and
   batch-payout detection so a disperser's funding leg is never mistaken for an
   individual payment. Addresses are matched against a list of known entities;
   where an onward hop is inferred rather than confirmed, the output says so.
4. **Payout firewall** — screens a destination address against the blocklist before
   funds are sent, and refuses to answer for an address that is not well-formed. It
   distinguishes a verified report (block) from an unverified one (hold for review)
   from no match at all (which is not a clean bill of health).
5. **Enforcement hub** — generates an issuer freeze request addressed to the party
   that can actually act (Tether for USDT, Circle for USDC — nobody for ETH or most
   tokens), an exchange compliance notice, and a law-enforcement dossier.
6. **Supabase sync** — PostgreSQL schema with row-level security in
   `supabase/schema.sql`: case files are private to their owner, the wallet
   blocklist is world-readable, scan bodies are never shared. Falls back to
   browser-local storage when no cloud session exists.

### What it does not do

- It cannot freeze, reverse or block a transfer. Only a token's issuer can
  blacklist an address, only an exchange can hold a deposit, and both are
  discretionary.
- A clean result means nothing matched the feeds that were queried. It is not a
  statement that an address or link is safe.
- Recovery is not the usual outcome of any of this. Filing quickly and completely
  is what improves the odds.

---

## 🚀 Quick Start

### 1. Install dependencies
```bash
npm install
```

### 2. Run the dev server
```bash
npm run dev
```
Open `http://localhost:3000`.

### 3. Run the tests
```bash
npm test
```
Two corpora, both offline. `scripts/test_url_scanner.mjs` scores 30 real
legitimate URLs (any non-SAFE verdict is a false positive) and 19 phishing
samples. `scripts/test_forensics.mjs` pins the EIP-55 checksum vectors, the
exact BigInt amount formatting, the ABI decoders, transfer selection from a
multi-log receipt, freeze-authority routing, and the difference between a
security feed answering "clean" and not answering at all.

### 4. Build for production
```bash
npm run build
```

---

## 🔬 Optional: the forensics API

`api/main.py` is a FastAPI service that decodes a transaction's ERC-20 transfers
server-side, with RPC failover, a CORS allowlist, rate limiting and a TTL cache.
The web app works without it.

```bash
pip install fastapi uvicorn httpx
uvicorn api.main:app --reload
```

It reads these environment variables, all optional:

| Variable | Default | Purpose |
| --- | --- | --- |
| `CHAINSHIELD_ALLOWED_ORIGINS` | localhost dev origins | Comma-separated CORS allowlist |
| `CHAINSHIELD_RATE_LIMIT` | `30` | Requests per window, per client |
| `CHAINSHIELD_RATE_WINDOW` | `60` | Window length in seconds |
| `CHAINSHIELD_UPSTREAM_TIMEOUT` | `6.0` | Per-RPC-call timeout in seconds |
| `CHAINSHIELD_CACHE_TTL` | `120` | Response cache TTL in seconds |
| `CHAINSHIELD_TRUST_PROXY` | unset | Set to `1` only behind a proxy you control, so `X-Forwarded-For` can be trusted for rate limiting |

`GET /health` reports which of these are in effect.

---

## 🗄️ Setting up Supabase

1. Create a free project at [Supabase](https://supabase.com).
2. In the **SQL Editor**, run the whole of `supabase/schema.sql`. It creates the
   tables, the row-level-security policies and the grants together — applying only
   part of it leaves the tables readable by anyone with the anon key.
3. Enable **Anonymous** sign-in under **Authentication → Sign In / Providers**. The
   RLS policies key off `auth.uid()`, so without a session the app stays local-only
   — which the **Cloud** panel in the navbar will tell you plainly.
4. Copy your **Project URL** and **anon public key** from Settings → API, then
   either paste them into the **Cloud** panel in the navbar or put them in `.env`:
   ```env
   VITE_SUPABASE_URL=https://your-project-ref.supabase.co
   VITE_SUPABASE_ANON_KEY=your-anon-key-here
   ```

The anon key ships in the JS bundle and is public by design; RLS is what protects
the data, which is why step 2 is not optional.

---

## 🧪 Research scripts

`scripts/train_phiusiil.py` trains a baseline classifier on the PhiUSIIL URL
dataset. **Nothing in the app loads it** — it exists so the heuristic detector's
performance can be compared against something. It drops the dataset's
label-leaking `URLSimilarityIndex` column by default, because keeping it is what
produces the ~99.9% figure usually quoted for this dataset.

---

## 📄 License
MIT License. Written to help victims of cyber fraud and to build open threat
intelligence.
