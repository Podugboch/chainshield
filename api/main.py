import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="ChainShield Multi-Chain Security & Forensics API",
    description="Multi-chain security scanner powered by GoPlus, on-chain heuristics, and threat intelligence.",
    version="1.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Multi-chain mapping for GoPlus API chain IDs
SUPPORTED_CHAINS = {
    "ethereum": "1",
    "bsc": "56",        # Binance Smart Chain / BscScan ecosystem
    "polygon": "137",
    "arbitrum": "42161",
    "avalanche": "43114",
    "base": "8453",
    "optimism": "10",
}

async def query_goplus_token_security(chain_id: str, address: str):
    """Queries GoPlus token security across different EVM-compatible chains."""
    url = f"https://api.gopluslabs.io/api/v1/token_security/{chain_id}?contract_addresses={address}"
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, timeout=6.0)
            if response.status_code == 200:
                data = response.json()
                return data.get("result", {}).get(address.lower(), {})
            return None
        except httpx.RequestError:
            return None

async def query_goplus_address_security(chain_id: str, address: str):
    """Queries GoPlus malicious address security across EVM chains."""
    url = f"https://api.gopluslabs.io/api/v1/address_security/{address}?chain_id={chain_id}"
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, timeout=6.0)
            if response.status_code == 200:
                data = response.json()
                return data.get("result", {})
            return None
        except httpx.RequestError:
            return None

@app.get("/api/v1/security/scan")
async def scan_crypto_asset(
    network: str = Query(..., description="Network name e.g., bsc, ethereum, polygon, arbitrum, base"),
    target: str = Query(..., description="Contract address, wallet address, or transaction hash")
):
    network_key = network.lower().strip()
    if network_key not in SUPPORTED_CHAINS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported network '{network}'. Choose from: {list(SUPPORTED_CHAINS.keys())}"
        )
    
    chain_id = SUPPORTED_CHAINS[network_key]
    target = target.strip()

    # 1. Handle Smart Contract / Token Address or Wallet Address Check
    if target.startswith("0x") and len(target) == 42:
        token_data = await query_goplus_token_security(chain_id, target)
        address_data = await query_goplus_address_security(chain_id, target)

        flags = []
        risk_score = 0
        risk_level = "Safe"
        is_contract = bool(token_data and token_data.get("token_name"))

        # --- A. Evaluate Token Contract Heuristics ---
        metrics = {}
        if is_contract:
            is_honeypot = token_data.get("is_honeypot", "0") == "1"
            is_open_source = token_data.get("is_open_source", "0") == "1"
            buy_tax = float(token_data.get("buy_tax", "0") or "0")
            sell_tax = float(token_data.get("sell_tax", "0") or "0")
            cannot_sell_all = token_data.get("cannot_sell_all", "0") == "1"
            is_mintable = token_data.get("is_mintable", "0") == "1"

            metrics = {
                "token_name": token_data.get("token_name"),
                "token_symbol": token_data.get("token_symbol"),
                "is_honeypot": is_honeypot,
                "buy_tax": buy_tax,
                "sell_tax": sell_tax,
                "is_open_source": is_open_source,
                "cannot_sell_all": cannot_sell_all,
                "is_mintable": is_mintable
            }

            if is_honeypot:
                risk_score += 90
                flags.append("Honeypot Detected: Users cannot sell this token.")
            if cannot_sell_all:
                risk_score += 50
                flags.append("Restricted Liquidity: Token transfer is artificially restricted.")
            if not is_open_source:
                risk_score += 25
                flags.append("Unverified Source Code: Contract bytecode is hidden/unverified.")
            if buy_tax > 10 or sell_tax > 10:
                risk_score += 30
                flags.append(f"Excessive Tax Warning (Buy: {buy_tax}%, Sell: {sell_tax}%)")

        # --- B. Evaluate Wallet / Address Security Heuristics ---
        if address_data:
            if address_data.get("phishing_activities", "0") == "1":
                risk_score += 85
                flags.append("Phishing Activity: Address has been reported for phishing/credential harvesting.")
            if address_data.get("stealing_attack", "0") == "1":
                risk_score += 90
                flags.append("Theft / Exploit: Address flagged in automated asset draining attacks.")
            if address_data.get("blacklist_doubt", "0") == "1":
                risk_score += 75
                flags.append("Issuer Blacklist: Address under doubt or flagged by stablecoin issuers (Tether/Circle).")
            if address_data.get("money_laundering", "0") == "1" or address_data.get("mixer", "0") == "1":
                risk_score += 40
                flags.append("Mixer / Money Laundering: Direct association with privacy mixing protocols.")
            if address_data.get("honeypot_related_address", "0") == "1":
                risk_score += 70
                flags.append("Honeypot Creator: Address has created or funded honeypot scams.")

        # Guard against False Positives: Granular Risk Tiers
        risk_score = min(100, risk_score)
        if risk_score >= 75:
            risk_level = "Critical Malicious"
        elif risk_score >= 45:
            risk_level = "High Risk"
        elif risk_score >= 20:
            risk_level = "Suspicious / Medium"
        elif risk_score > 0:
            risk_level = "Low Risk"
        else:
            risk_level = "Safe"

        return {
            "target": target,
            "network": network_key,
            "chain_id": chain_id,
            "is_contract": is_contract,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "flags": flags,
            "metrics": metrics,
            "raw_address_security": address_data
        }

    # 2. Handle Transaction Hash Check
    elif target.startswith("0x") and len(target) == 66:
        return {
            "target": target,
            "network": network_key,
            "chain_id": chain_id,
            "type": "transaction_hash",
            "status": "Verified format for EVM block explorer routing."
        }

    else:
        raise HTTPException(
            status_code=400,
            detail="Malformed address or transaction hash format."
        )

@app.get("/health")
def health_check():
    return {"status": "ok", "service": "ChainShield Security API", "version": "1.1.0"}
