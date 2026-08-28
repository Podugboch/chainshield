# 🛡️ ChainShield | AI Phishing Detection & Crypto Forensics Platform

**ChainShield** is a cybersecurity and cryptocurrency forensics application designed to protect users from malicious phishing links, brand impersonation attacks (such as rogue platform links like *Atlas Capture*), and assist in tracing stolen crypto assets through intermediate hops to centralized exchanges (**Binance**).

---

## ✨ Features

1. **AI Phishing & URL Scanner**:
   - Computes live risk scores (0–100) using Levenshtein distance typosquatting checks, brand impersonation algorithms, high-risk throwaway TLD inspection, and IP host detection.
   - Specifically protects against spoofing of platforms like **Atlas Capture**, **Binance**, **MetaMask**, and **Coinbase**.
2. **Email & Direct Message Threat Analyzer**:
   - Evaluates psychological urgency triggers, social engineering coercion, and unauthorized wallet change requests.
3. **Crypto Scam Forensics & On-Chain Visualizer**:
   - Interactive transaction flow graph mapping: `Victim Payout Source` &rarr; `Scammer Intercept Wallet` &rarr; `Binance KYC Deposit Cluster`.
   - Identifies exchange deposit addresses and flags de-anonymization vectors.
4. **Law Enforcement & Binance Security Report Generator**:
   - One-click export of formal, subpoena-ready incident dossiers for **Binance Compliance** and Cybercrime agencies (**IC3 / Interpol / Police**).
5. **Supabase Cloud Database**:
   - PostgreSQL schema with Row Level Security (`threat_scans`, `scam_wallets`, `incident_cases`) with offline local-first fallback mode.

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
npm install
```

### 2. Run Development Server
```bash
npm run dev
```
Open your browser at `http://localhost:3000`.

### 3. Build for Production
```bash
npm run build
```

---

## 🗄️ Setting up Supabase

1. Create a free project at [Supabase](https://supabase.com).
2. Go to the **SQL Editor** in your Supabase dashboard and run the entire script found in:
   ```
   supabase/schema.sql
   ```
3. Copy your **Project URL** and **Anon Public Key** from Supabase Settings &rarr; API.
4. In the ChainShield UI, click the **Supabase: Local Mode** badge in the top right navbar to paste your keys, or create a `.env` file:
   ```env
   VITE_SUPABASE_URL=https://your-project-id.supabase.co
   VITE_SUPABASE_ANON_KEY=your-anon-key-here
   ```

---

## 📦 Committing to GitHub

To push this project to your GitHub repository:

```bash
# 1. Initialize git (if not already done)
git init

# 2. Add files and commit
git add .
git commit -m "feat: initial release of ChainShield AI anti-phishing & crypto forensics"

# 3. Link to your GitHub repository
git remote add origin https://github.com/YOUR_USERNAME/chainshield.git
git branch -M main

# 4. Push to GitHub
git push -u origin main
```

---

## 📄 License
MIT License. Created to assist victims of cyber fraud and build open threat intelligence.
