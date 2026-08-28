-- =========================================================
-- ChainShield Database Schema for Supabase
-- Anti-Phishing Intel & Crypto Forensics Platform
-- =========================================================

-- 1. Threat Scans (URLs & Messages Analyzed)
CREATE TABLE IF NOT EXISTS threat_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    scan_type TEXT NOT NULL CHECK (scan_type IN ('url', 'message')),
    input_content TEXT NOT NULL,
    target_domain TEXT,
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    risk_level TEXT NOT NULL CHECK (risk_level IN ('SAFE', 'SUSPICIOUS', 'MALICIOUS')),
    threat_reasons JSONB DEFAULT '[]'::jsonb,
    ip_metadata JSONB DEFAULT '{}'::jsonb
);

-- 2. Scam Wallets (Flagged Addresses & Entity Mapping)
CREATE TABLE IF NOT EXISTS scam_wallets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    wallet_address TEXT NOT NULL UNIQUE,
    network TEXT NOT NULL DEFAULT 'Ethereum',
    scam_category TEXT NOT NULL DEFAULT 'Phishing / Credential Theft',
    impersonated_brand TEXT DEFAULT 'Atlas Capture',
    total_stolen_usd NUMERIC(14, 2) DEFAULT 0.00,
    destination_entity TEXT, -- e.g. "Binance Deposit"
    destination_address TEXT,
    notes TEXT
);

-- 3. Incident Cases (Investigation Dossiers)
CREATE TABLE IF NOT EXISTS incident_cases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    title TEXT NOT NULL,
    platform_name TEXT NOT NULL DEFAULT 'Atlas Capture',
    victim_name TEXT DEFAULT 'Anonymous Victim',
    amount_lost_usd NUMERIC(14, 2) NOT NULL,
    token_symbol TEXT NOT NULL DEFAULT 'USDT (ERC-20)',
    scammer_intermediary_wallet TEXT NOT NULL,
    destination_wallet TEXT NOT NULL,
    destination_entity TEXT NOT NULL DEFAULT 'Binance',
    tx_hash TEXT NOT NULL,
    phishing_url TEXT,
    status TEXT NOT NULL DEFAULT 'REPORTED_TO_BINANCE' CHECK (status IN ('OPEN', 'EVIDENCE_COLLECTED', 'REPORTED_TO_BINANCE', 'POLICE_REPORTED', 'FROZEN', 'CLOSED')),
    law_enforcement_ref TEXT,
    dossier_notes TEXT
);

-- Row Level Security (RLS) Policies
ALTER TABLE threat_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE scam_wallets ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_cases ENABLE ROW LEVEL SECURITY;

-- Allow public read/insert for community intel (or restrict per user if Auth is used)
CREATE POLICY "Allow public read on threat_scans" ON threat_scans FOR SELECT USING (true);
CREATE POLICY "Allow public insert on threat_scans" ON threat_scans FOR INSERT WITH CHECK (true);

CREATE POLICY "Allow public read on scam_wallets" ON scam_wallets FOR SELECT USING (true);
CREATE POLICY "Allow public insert on scam_wallets" ON scam_wallets FOR INSERT WITH CHECK (true);

CREATE POLICY "Allow public read on incident_cases" ON incident_cases FOR SELECT USING (true);
CREATE POLICY "Allow public insert on incident_cases" ON incident_cases FOR INSERT WITH CHECK (true);
CREATE POLICY "Allow public update on incident_cases" ON incident_cases FOR UPDATE USING (true);

-- Seed Initial Verified Incident ($146.07 Atlas Capture Scam)
INSERT INTO scam_wallets (wallet_address, network, scam_category, impersonated_brand, total_stolen_usd, destination_entity, destination_address, notes)
VALUES (
    '0xd23Ac29C1e1949D0c5864B4a23a01cc3e4dd236b',
    'Ethereum (ERC-20)',
    'Phishing & Account Takeover',
    'Atlas Capture',
    146.07,
    'Binance Deposit Address',
    'Forwarded to Binance deposit cluster',
    'Phishing link used to alter payout wallet on Atlas Capture, then swept to Binance.'
) ON CONFLICT (wallet_address) DO NOTHING;

INSERT INTO incident_cases (
    title, 
    platform_name, 
    amount_lost_usd, 
    token_symbol, 
    scammer_intermediary_wallet, 
    destination_wallet, 
    destination_entity, 
    tx_hash, 
    phishing_url, 
    status,
    dossier_notes
) VALUES (
    'Atlas Capture Payout Redirection Scam',
    'Atlas Capture',
    146.07,
    'USDT (ERC-20)',
    '0xd23Ac29C1e1949D0c5864B4a23a01cc3e4dd236b',
    'Binance Deposit Cluster',
    'Binance',
    '0x44e5dbb257694dd3297e3a24808a6098f2bce9816bc9b202879104dccec911e7',
    'Atlas Capture Impersonation Link',
    'EVIDENCE_COLLECTED',
    'Malicious link compromised account credentials, replaced legitimate USDT payout address with attacker wallet, and forwarded payout to Binance.'
);
