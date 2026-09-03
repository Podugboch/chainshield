-- =========================================================
-- ChainShield Database Schema for Supabase
-- Anti-Phishing Intel & Crypto Forensics Platform
-- =========================================================
--
-- ACCESS MODEL
--
-- This file is written for a deployment where the browser holds only the
-- anon key. Everything below assumes that key is public knowledge, because it
-- is: it ships in the JS bundle. RLS is therefore the only access control that
-- exists, and each table gets the narrowest policy that still lets the feature
-- work.
--
--   threat_scans    private to the submitter. Scan input is pasted straight
--                   from a victim's inbox and routinely contains names, order
--                   numbers and addresses, so it is never world-readable.
--                   Aggregate community intel is exposed through the
--                   threat_domain_stats view instead.
--   scam_wallets    world-readable on purpose: a blocklist nobody can read is
--                   useless. Writes require a session and are marked unverified
--                   until a moderator promotes them.
--   incident_cases  private to the owner, with no anonymous access at all.
--                   These are fraud dossiers naming real victims.
--
-- Rows are owned via owner_id = auth.uid(). Anonymous sign-in (Supabase
-- Dashboard -> Authentication -> Sign In / Providers -> Anonymous) is enough:
-- it issues a real uid without a login screen. With no session at all the app
-- falls back to browser-local storage, which is the correct outcome for
-- private case files rather than a degraded one.
--
-- Safe to re-run: policies are dropped before being recreated.
-- =========================================================

-- ---------------------------------------------------------
-- 1. Threat Scans (URLs & Messages Analyzed)
-- ---------------------------------------------------------
CREATE TABLE IF NOT EXISTS threat_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    owner_id UUID REFERENCES auth.users (id) ON DELETE CASCADE,
    scan_type TEXT NOT NULL CHECK (scan_type IN ('url', 'message')),
    input_content TEXT NOT NULL,
    target_domain TEXT,
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    risk_level TEXT NOT NULL CHECK (risk_level IN ('SAFE', 'SUSPICIOUS', 'MALICIOUS', 'UNKNOWN')),
    threat_reasons JSONB DEFAULT '[]'::jsonb,
    ip_metadata JSONB DEFAULT '{}'::jsonb
);

ALTER TABLE threat_scans ADD COLUMN IF NOT EXISTS owner_id UUID REFERENCES auth.users (id) ON DELETE CASCADE;
ALTER TABLE threat_scans DROP CONSTRAINT IF EXISTS threat_scans_risk_level_check;
ALTER TABLE threat_scans ADD CONSTRAINT threat_scans_risk_level_check
    CHECK (risk_level IN ('SAFE', 'SUSPICIOUS', 'MALICIOUS', 'UNKNOWN'));

CREATE INDEX IF NOT EXISTS threat_scans_owner_idx ON threat_scans (owner_id, created_at DESC);
CREATE INDEX IF NOT EXISTS threat_scans_domain_idx ON threat_scans (target_domain);

-- ---------------------------------------------------------
-- 2. Scam Wallets (Flagged Addresses & Entity Mapping)
-- ---------------------------------------------------------
CREATE TABLE IF NOT EXISTS scam_wallets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    owner_id UUID REFERENCES auth.users (id) ON DELETE SET NULL,
    wallet_address TEXT NOT NULL UNIQUE,
    network TEXT NOT NULL DEFAULT 'Ethereum',
    scam_category TEXT NOT NULL DEFAULT 'Phishing / Credential Theft',
    impersonated_brand TEXT,
    -- No default. 0.00 for an unrecorded amount is a measured loss of nothing,
    -- which is a different claim from "we do not know"; the UI renders NULL as
    -- "not recorded" and cannot distinguish the two if the column invents a zero.
    total_stolen_usd NUMERIC(14, 2) CHECK (total_stolen_usd >= 0),
    destination_entity TEXT,
    destination_address TEXT,
    -- Community submissions start unverified. The UI must not present an
    -- unverified row as an established fact: anyone with the anon key can add
    -- one, so an unchecked blocklist is a way to defame an address.
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    notes TEXT
);

ALTER TABLE scam_wallets ADD COLUMN IF NOT EXISTS owner_id UUID REFERENCES auth.users (id) ON DELETE SET NULL;
ALTER TABLE scam_wallets ADD COLUMN IF NOT EXISTS verified BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE scam_wallets ALTER COLUMN impersonated_brand DROP DEFAULT;
ALTER TABLE scam_wallets ALTER COLUMN total_stolen_usd DROP DEFAULT;

-- wallet_address is UNIQUE, but Postgres compares text case-sensitively, so the
-- same address in checksummed and lowercase form counted as two distinct rows --
-- one of which could be verified and the other not. Lookups are case-insensitive
-- (dbService.isWalletFlagged uses ilike), so uniqueness has to be too.
CREATE UNIQUE INDEX IF NOT EXISTS scam_wallets_address_lower_idx
    ON scam_wallets (lower(wallet_address));

-- ---------------------------------------------------------
-- 3. Incident Cases (Investigation Dossiers)
-- ---------------------------------------------------------
CREATE TABLE IF NOT EXISTS incident_cases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    owner_id UUID REFERENCES auth.users (id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    platform_name TEXT NOT NULL,
    victim_name TEXT,
    amount_lost_usd NUMERIC(14, 2) NOT NULL CHECK (amount_lost_usd >= 0),
    token_symbol TEXT NOT NULL,
    scammer_intermediary_wallet TEXT NOT NULL,
    destination_wallet TEXT NOT NULL,
    destination_entity TEXT NOT NULL,
    tx_hash TEXT NOT NULL,
    phishing_url TEXT,
    status TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'EVIDENCE_COLLECTED', 'REPORTED_TO_BINANCE', 'POLICE_REPORTED', 'FROZEN', 'CLOSED')),
    law_enforcement_ref TEXT,
    dossier_notes TEXT
);

ALTER TABLE incident_cases ADD COLUMN IF NOT EXISTS owner_id UUID REFERENCES auth.users (id) ON DELETE CASCADE;
-- 'Atlas Capture' and 'Anonymous Victim' were column defaults. A default that
-- names one real platform and one real person is seed data leaking into the
-- schema; every case inserted without an explicit value inherited it.
ALTER TABLE incident_cases ALTER COLUMN platform_name DROP DEFAULT;
ALTER TABLE incident_cases ALTER COLUMN victim_name DROP DEFAULT;
ALTER TABLE incident_cases ALTER COLUMN token_symbol DROP DEFAULT;
ALTER TABLE incident_cases ALTER COLUMN destination_entity DROP DEFAULT;
ALTER TABLE incident_cases ALTER COLUMN status SET DEFAULT 'OPEN';

CREATE INDEX IF NOT EXISTS incident_cases_owner_idx ON incident_cases (owner_id, created_at DESC);

-- updated_at was declared but never maintained; nothing in the app wrote it.
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    NEW.updated_at := timezone('utc'::text, now());
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS incident_cases_set_updated_at ON incident_cases;
CREATE TRIGGER incident_cases_set_updated_at
    BEFORE UPDATE ON incident_cases
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- =========================================================
-- Row Level Security
-- =========================================================
ALTER TABLE threat_scans    ENABLE ROW LEVEL SECURITY;
ALTER TABLE scam_wallets    ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_cases  ENABLE ROW LEVEL SECURITY;

-- Force RLS on the table owner too, so a future SECURITY DEFINER function or a
-- server-side connection using the table owner role cannot quietly bypass it.
ALTER TABLE threat_scans    FORCE ROW LEVEL SECURITY;
ALTER TABLE scam_wallets    FORCE ROW LEVEL SECURITY;
ALTER TABLE incident_cases  FORCE ROW LEVEL SECURITY;

-- Drop the previous permissive policies. These granted SELECT/INSERT to every
-- caller on all three tables and UPDATE on incident_cases, which made every
-- fraud dossier world-readable and world-rewritable by anyone who loaded the
-- site. They are named explicitly so re-running this file is not a no-op on an
-- already-deployed project.
DROP POLICY IF EXISTS "Allow public read on threat_scans"    ON threat_scans;
DROP POLICY IF EXISTS "Allow public insert on threat_scans"  ON threat_scans;
DROP POLICY IF EXISTS "Allow public read on scam_wallets"    ON scam_wallets;
DROP POLICY IF EXISTS "Allow public insert on scam_wallets"  ON scam_wallets;
DROP POLICY IF EXISTS "Allow public read on incident_cases"  ON incident_cases;
DROP POLICY IF EXISTS "Allow public insert on incident_cases" ON incident_cases;
DROP POLICY IF EXISTS "Allow public update on incident_cases" ON incident_cases;

-- Also drop this file's own policies so edits here apply cleanly on re-run.
DROP POLICY IF EXISTS threat_scans_select_own       ON threat_scans;
DROP POLICY IF EXISTS threat_scans_insert_own       ON threat_scans;
DROP POLICY IF EXISTS threat_scans_delete_own       ON threat_scans;
DROP POLICY IF EXISTS scam_wallets_select_all       ON scam_wallets;
DROP POLICY IF EXISTS scam_wallets_insert_session   ON scam_wallets;
DROP POLICY IF EXISTS scam_wallets_update_own       ON scam_wallets;
DROP POLICY IF EXISTS incident_cases_select_own     ON incident_cases;
DROP POLICY IF EXISTS incident_cases_insert_own     ON incident_cases;
DROP POLICY IF EXISTS incident_cases_update_own     ON incident_cases;
DROP POLICY IF EXISTS incident_cases_delete_own     ON incident_cases;

-- --- threat_scans: private to the submitter -------------------------------
-- Scan input is pasted from the victim's own inbox. Treat it as their mail,
-- not as community intel.
CREATE POLICY threat_scans_select_own ON threat_scans
    FOR SELECT TO authenticated
    USING (owner_id = auth.uid());

CREATE POLICY threat_scans_insert_own ON threat_scans
    FOR INSERT TO authenticated
    WITH CHECK (owner_id = auth.uid());

CREATE POLICY threat_scans_delete_own ON threat_scans
    FOR DELETE TO authenticated
    USING (owner_id = auth.uid());

-- --- scam_wallets: readable blocklist, guarded writes ---------------------
CREATE POLICY scam_wallets_select_all ON scam_wallets
    FOR SELECT TO anon, authenticated
    USING (true);

-- A session is required to write, and the row is stamped with it. Submissions
-- cannot arrive pre-marked as verified.
CREATE POLICY scam_wallets_insert_session ON scam_wallets
    FOR INSERT TO authenticated
    WITH CHECK (owner_id = auth.uid() AND verified = FALSE);

CREATE POLICY scam_wallets_update_own ON scam_wallets
    FOR UPDATE TO authenticated
    USING (owner_id = auth.uid())
    WITH CHECK (owner_id = auth.uid() AND verified = FALSE);

-- --- incident_cases: owner only, no anonymous access ----------------------
CREATE POLICY incident_cases_select_own ON incident_cases
    FOR SELECT TO authenticated
    USING (owner_id = auth.uid());

CREATE POLICY incident_cases_insert_own ON incident_cases
    FOR INSERT TO authenticated
    WITH CHECK (owner_id = auth.uid());

CREATE POLICY incident_cases_update_own ON incident_cases
    FOR UPDATE TO authenticated
    USING (owner_id = auth.uid())
    WITH CHECK (owner_id = auth.uid());

CREATE POLICY incident_cases_delete_own ON incident_cases
    FOR DELETE TO authenticated
    USING (owner_id = auth.uid());

-- =========================================================
-- Aggregate community intel without exposing scan bodies
-- =========================================================
-- A plain view cannot do this: with security_invoker it returns only the
-- caller's own rows, and without it, it hands back everyone's input_content.
-- A SECURITY DEFINER function that projects nothing but a domain and a count
-- is the narrow exception. The HAVING clause is the point -- a domain scanned
-- once by one person is that person's business, so it is withheld until
-- several independent submissions exist.
CREATE OR REPLACE FUNCTION threat_domain_stats(min_reports INTEGER DEFAULT 3)
RETURNS TABLE (target_domain TEXT, report_count BIGINT, worst_risk_level TEXT, last_seen TIMESTAMPTZ)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
STABLE
AS $$
    SELECT
        s.target_domain,
        COUNT(*) AS report_count,
        CASE WHEN bool_or(s.risk_level = 'MALICIOUS') THEN 'MALICIOUS' ELSE 'SUSPICIOUS' END,
        MAX(s.created_at)
    FROM threat_scans s
    WHERE s.target_domain IS NOT NULL
      AND s.risk_level IN ('MALICIOUS', 'SUSPICIOUS')
    GROUP BY s.target_domain
    HAVING COUNT(DISTINCT s.owner_id) >= GREATEST(min_reports, 3)
    ORDER BY COUNT(*) DESC
    LIMIT 200;
$$;

REVOKE ALL ON FUNCTION threat_domain_stats(INTEGER) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION threat_domain_stats(INTEGER) TO anon, authenticated;

-- =========================================================
-- Table grants
-- =========================================================
-- RLS decides which rows; grants decide which verbs are reachable at all.
-- Both are needed -- a missing policy with a broad grant is the mistake this
-- schema previously made in reverse.
REVOKE ALL ON threat_scans, scam_wallets, incident_cases FROM anon, authenticated;

GRANT SELECT, INSERT, DELETE          ON threat_scans   TO authenticated;
GRANT SELECT                          ON scam_wallets   TO anon, authenticated;
GRANT INSERT, UPDATE                  ON scam_wallets   TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE  ON incident_cases TO authenticated;

-- =========================================================
-- Seed: known-scammer blocklist entry
-- =========================================================
-- A scammer's collecting address is threat intel and belongs in a shared
-- blocklist. Marked verified because it is being seeded deliberately by the
-- project owner, not submitted anonymously.
INSERT INTO scam_wallets (
    wallet_address, network, scam_category, impersonated_brand,
    total_stolen_usd, destination_entity, destination_address, verified, notes
) VALUES (
    '0xd23Ac29C1e1949D0c5864B4a23a01cc3e4dd236b',
    'Ethereum (ERC-20)',
    'Phishing & Account Takeover',
    'Atlas Capture',
    146.07,
    'Binance Deposit Address',
    NULL,
    TRUE,
    'Phishing link used to alter the payout wallet on Atlas Capture, then swept to Binance.'
) ON CONFLICT (wallet_address) DO NOTHING;

-- The incident_cases seed that used to live here has been removed on purpose.
-- It hardcoded one real victim's dossier -- amount lost, tx hash, wallet, and
-- a phishing_url -- into a file committed to a public repository, so the
-- dossier was published by cloning the repo, independently of any RLS policy.
-- Cases are private rows now: create them from the app, where they are stamped
-- with the owner's uid and readable by nobody else.

-- =========================================================
-- Post-install check
-- =========================================================
-- Run this after applying the file. Every row must report rls_enabled = true,
-- and no policy should show qual = 'true' on a table holding scan input or
-- case files.
--
--   SELECT relname, relrowsecurity AS rls_enabled, relforcerowsecurity AS forced
--   FROM pg_class
--   WHERE relname IN ('threat_scans', 'scam_wallets', 'incident_cases');
--
--   SELECT tablename, policyname, cmd, roles, qual, with_check
--   FROM pg_policies
--   WHERE tablename IN ('threat_scans', 'scam_wallets', 'incident_cases')
--   ORDER BY tablename, cmd;

