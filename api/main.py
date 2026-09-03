"""
ChainShield security & forensics API.

Deployment notes that matter more than the code:

* CORS is an allowlist read from CHAINSHIELD_ALLOWED_ORIGINS. It is not "*".
  The previous configuration paired allow_origins=["*"] with
  allow_credentials=True, which browsers reject outright for credentialed
  requests -- and which, if it had worked, would have let any site on the
  internet make authenticated calls to this API.
* There is no authentication here. Every endpoint is read-only and every
  answer is derived from public chain data, so there is nothing to
  authorise -- but that also means anyone who finds the URL can spend your
  upstream API quota. Rate limiting below is per-process and best-effort;
  put a real gateway in front of this before exposing it publicly.
"""
from __future__ import annotations

import asyncio
import os
import re
import time
from collections import OrderedDict, defaultdict, deque
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

APP_VERSION = "1.2.0"

# --- Configuration -------------------------------------------------------

def _parse_origins(raw: str | None) -> list[str]:
    if not raw:
        # Local development defaults only. Production origins must be set
        # explicitly rather than inherited from a wildcard.
        return ["http://localhost:3000", "http://127.0.0.1:3000"]
    origins = [o.strip().rstrip("/") for o in raw.split(",") if o.strip()]
    if "*" in origins:
        raise RuntimeError(
            "CHAINSHIELD_ALLOWED_ORIGINS must not be '*'. List the exact origins "
            "that are allowed to call this API."
        )
    return origins


ALLOWED_ORIGINS = _parse_origins(os.getenv("CHAINSHIELD_ALLOWED_ORIGINS"))
RATE_LIMIT_REQUESTS = int(os.getenv("CHAINSHIELD_RATE_LIMIT", "30"))
RATE_LIMIT_WINDOW_S = int(os.getenv("CHAINSHIELD_RATE_WINDOW", "60"))
UPSTREAM_TIMEOUT_S = float(os.getenv("CHAINSHIELD_UPSTREAM_TIMEOUT", "6.0"))
CACHE_TTL_S = int(os.getenv("CHAINSHIELD_CACHE_TTL", "120"))
CACHE_MAX_ENTRIES = 512

app = FastAPI(
    title="ChainShield Multi-Chain Security & Forensics API",
    description=(
        "Multi-chain address and token risk lookup. Findings are derived from GoPlus "
        "threat intelligence plus on-chain reads; every response states which upstream "
        "sources answered, because an unreachable source is not a clean result."
    ),
    version=APP_VERSION,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    # No cookies or Authorization headers are used, so credentials stay off.
    # This is also what makes a narrow origin list meaningful.
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["Content-Type"],
    max_age=600,
)

SUPPORTED_CHAINS = {
    "ethereum": "1",
    "bsc": "56",
    "polygon": "137",
    "arbitrum": "42161",
    "avalanche": "43114",
    "base": "8453",
    "optimism": "10",
}

ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
TX_HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")

# --- EIP-55 address validation ------------------------------------------
# Implemented here rather than pulled in as a dependency: it is 20 lines and
# keccak is already available via pycryptodome-free pure Python below.

_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_KECCAK_ROTC = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
                27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44]
_KECCAK_PIL = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
               15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1]
_MASK64 = (1 << 64) - 1


def _rotl64(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & _MASK64


def keccak256(data: bytes) -> bytes:
    """Keccak-256 (the pre-NIST padding used by Ethereum, not SHA3-256)."""
    rate = 136  # 1088 bits
    state = [0] * 25

    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != 0:
        padded.append(0x00)
    padded[-1] |= 0x80

    for offset in range(0, len(padded), rate):
        block = padded[offset:offset + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[i * 8:(i + 1) * 8], "little")

        for rnd in range(24):
            c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
                 for x in range(5)]
            d = [c[(x + 4) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
            for x in range(5):
                for y in range(0, 25, 5):
                    state[y + x] ^= d[x]

            t = state[1]
            for i in range(24):
                j = _KECCAK_PIL[i]
                state[j], t = _rotl64(t, _KECCAK_ROTC[i]), state[j]

            for y in range(0, 25, 5):
                row = state[y:y + 5]
                for x in range(5):
                    state[y + x] = row[x] ^ ((~row[(x + 1) % 5]) & row[(x + 2) % 5]) & _MASK64

            state[0] ^= _KECCAK_RC[rnd]

    return b"".join(s.to_bytes(8, "little") for s in state)[:32]


def to_checksum_address(address: str) -> str:
    body = address.lower().removeprefix("0x")
    digest = keccak256(body.encode()).hex()
    return "0x" + "".join(
        ch.upper() if ch in "abcdef" and int(digest[i], 16) >= 8 else ch
        for i, ch in enumerate(body)
    )


def validate_address(raw: str) -> str:
    """Return the checksummed address, or raise 400 with a specific reason."""
    value = raw.strip()
    if not ADDRESS_RE.match(value):
        raise HTTPException(
            status_code=400,
            detail="Address must be 0x followed by 40 hex characters.",
        )
    body = value[2:]
    if any(c.isupper() for c in body) and any(c.islower() for c in body):
        # Mixed case carries an EIP-55 checksum, so a typo is detectable.
        if value != to_checksum_address(value):
            raise HTTPException(
                status_code=400,
                detail=(
                    "EIP-55 checksum mismatch: at least one character is wrong. "
                    "Re-copy the address instead of editing it by hand."
                ),
            )
    return to_checksum_address(value)

# --- Rate limiting -------------------------------------------------------
# Fixed-memory sliding window, per client IP, per process. Deliberately simple:
# it exists to stop one caller burning the upstream quota, not to withstand a
# distributed flood. Behind a proxy, X-Forwarded-For is only trusted when
# CHAINSHIELD_TRUST_PROXY is set, since a client can otherwise forge it and
# bypass the limit entirely.
TRUST_PROXY = os.getenv("CHAINSHIELD_TRUST_PROXY", "").lower() in {"1", "true", "yes"}
_hits: defaultdict[str, deque[float]] = defaultdict(deque)
_hits_lock = asyncio.Lock()


def client_key(request: Request) -> str:
    if TRUST_PROXY:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def enforce_rate_limit(request: Request) -> None:
    key = client_key(request)
    now = time.monotonic()
    async with _hits_lock:
        window = _hits[key]
        cutoff = now - RATE_LIMIT_WINDOW_S
        while window and window[0] < cutoff:
            window.popleft()
        if len(window) >= RATE_LIMIT_REQUESTS:
            retry_after = max(1, int(window[0] + RATE_LIMIT_WINDOW_S - now))
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit: {RATE_LIMIT_REQUESTS} requests per "
                       f"{RATE_LIMIT_WINDOW_S}s. Retry in {retry_after}s.",
                headers={"Retry-After": str(retry_after)},
            )
        window.append(now)
        # Stop unbounded growth from one-shot scanners hitting many IPs.
        if len(_hits) > 4096:
            for stale in [k for k, v in _hits.items() if not v or v[-1] < cutoff][:1024]:
                _hits.pop(stale, None)


# --- Response cache ------------------------------------------------------
# Chain risk data does not change second to second, and the upstream has a
# quota. Same target, same answer, for CACHE_TTL_S.
_cache: OrderedDict[str, tuple[float, Any]] = OrderedDict()


def cache_get(key: str) -> Any | None:
    entry = _cache.get(key)
    if not entry:
        return None
    stored_at, value = entry
    if time.monotonic() - stored_at > CACHE_TTL_S:
        _cache.pop(key, None)
        return None
    _cache.move_to_end(key)
    return value


def cache_put(key: str, value: Any) -> None:
    _cache[key] = (time.monotonic(), value)
    _cache.move_to_end(key)
    while len(_cache) > CACHE_MAX_ENTRIES:
        _cache.popitem(last=False)

# --- Upstream queries ----------------------------------------------------
GOPLUS_BASE = "https://api.gopluslabs.io/api/v1"


async def _get_json(client: httpx.AsyncClient, url: str) -> tuple[dict | None, str | None]:
    """Return (payload, error). An error is reported, never swallowed as empty."""
    try:
        response = await client.get(url, timeout=UPSTREAM_TIMEOUT_S)
        if response.status_code != 200:
            return None, f"HTTP {response.status_code}"
        return response.json(), None
    except httpx.TimeoutException:
        return None, "timed out"
    except httpx.RequestError as exc:
        return None, f"unreachable ({exc.__class__.__name__})"
    except ValueError:
        return None, "malformed JSON"


async def query_goplus_token_security(
    client: httpx.AsyncClient, chain_id: str, address: str
) -> tuple[dict | None, str | None]:
    url = f"{GOPLUS_BASE}/token_security/{chain_id}?contract_addresses={address.lower()}"
    payload, error = await _get_json(client, url)
    if error:
        return None, error
    result = (payload or {}).get("result") or {}
    return result.get(address.lower()) or {}, None


async def query_goplus_address_security(
    client: httpx.AsyncClient, chain_id: str, address: str
) -> tuple[dict | None, str | None]:
    url = f"{GOPLUS_BASE}/address_security/{address.lower()}?chain_id={chain_id}"
    payload, error = await _get_json(client, url)
    if error:
        return None, error
    return (payload or {}).get("result") or {}, None


def _flag(value: Any) -> bool:
    return str(value) == "1"


def _tax(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0

def score_address(address_data: dict) -> tuple[int, list[dict]]:
    """Score threat-intelligence hits on an address."""
    findings: list[dict] = []
    score = 0

    checks = [
        ("phishing_activities", 85, "critical", "Reported Phishing Operator",
         "Address is linked to phishing or credential-harvesting sites."),
        ("stealing_attack", 90, "critical", "Wallet Drainer Signature",
         "Address appears in automated asset-theft or sweep activity."),
        ("blacklist_doubt", 75, "high", "Stablecoin Issuer Flag",
         "Flagged or blacklisted by a centralised asset issuer such as Tether or Circle."),
        ("honeypot_related_address", 70, "high", "Honeypot Creator",
         "Address has created or funded honeypot token contracts."),
        ("darkweb_transactions", 45, "medium", "Darkweb Association",
         "Transactions associated with darkweb marketplaces."),
        ("sanctioned", 95, "critical", "Sanctions Match",
         "Address matches a sanctions listing in GoPlus's data."),
    ]
    for key, weight, severity, title, description in checks:
        if _flag(address_data.get(key)):
            score += weight
            findings.append(
                {"type": key.upper(), "severity": severity, "title": title,
                 "description": description}
            )

    if _flag(address_data.get("money_laundering")) or _flag(address_data.get("mixer")):
        score += 40
        findings.append({
            "type": "MIXER_ASSOCIATED", "severity": "medium",
            "title": "Privacy Mixer Interaction",
            "description": (
                "Interacted with a mixing protocol. Note this is not proof of wrongdoing "
                "on its own -- mixers have legitimate privacy uses."
            ),
        })

    return score, findings


def score_token(token_data: dict) -> tuple[int, list[dict], dict]:
    """Score contract-level risk. Only meaningful when the target is a token."""
    findings: list[dict] = []
    score = 0

    buy_tax = _tax(token_data.get("buy_tax"))
    sell_tax = _tax(token_data.get("sell_tax"))
    metrics = {
        "token_name": token_data.get("token_name"),
        "token_symbol": token_data.get("token_symbol"),
        "is_honeypot": _flag(token_data.get("is_honeypot")),
        "is_open_source": _flag(token_data.get("is_open_source")),
        "is_mintable": _flag(token_data.get("is_mintable")),
        "cannot_sell_all": _flag(token_data.get("cannot_sell_all")),
        "buy_tax_pct": round(buy_tax * 100, 2),
        "sell_tax_pct": round(sell_tax * 100, 2),
    }

    if metrics["is_honeypot"]:
        score += 90
        findings.append({
            "type": "HONEYPOT", "severity": "critical", "title": "Honeypot Contract",
            "description": "Contract code prevents holders from selling.",
        })
    if metrics["cannot_sell_all"]:
        score += 50
        findings.append({
            "type": "RESTRICTED_SELL", "severity": "high", "title": "Restricted Liquidity",
            "description": "Contract restricts selling the full balance.",
        })
    if not metrics["is_open_source"]:
        score += 25
        findings.append({
            "type": "UNVERIFIED_SOURCE", "severity": "medium",
            "title": "Unverified Source Code",
            "description": "Contract source is not verified, so its behaviour cannot be reviewed.",
        })
    # GoPlus reports tax as a fraction: 0.1 is 10%. Reading it as a percentage
    # meant the old threshold of 10 only fired at a 1000% tax.
    if buy_tax > 0.10 or sell_tax > 0.10:
        score += 30
        findings.append({
            "type": "EXCESSIVE_TAX", "severity": "medium", "title": "High Trading Tax",
            "description": f"Buy tax {metrics['buy_tax_pct']}%, sell tax {metrics['sell_tax_pct']}%.",
        })

    return score, findings, metrics


def risk_band(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 45:
        return "HIGH"
    if score >= 20:
        return "SUSPICIOUS"
    if score > 0:
        return "LOW"
    return "NONE_FOUND"

# --- Endpoints -----------------------------------------------------------

@app.get("/api/v1/security/scan")
async def scan_crypto_asset(
    request: Request,
    network: str = Query(..., description="ethereum, bsc, polygon, arbitrum, avalanche, base, optimism"),
    target: str = Query(..., min_length=4, max_length=100, description="Contract or wallet address"),
):
    """
    Risk lookup for an address on one chain.

    `risk_level` of NONE_FOUND means no listed threat matched -- not that the
    address is safe. `sources` reports which upstreams answered; if one failed,
    a quiet zero would otherwise be indistinguishable from a clean result.
    """
    await enforce_rate_limit(request)

    network_key = network.lower().strip()
    if network_key not in SUPPORTED_CHAINS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported network '{network}'. Choose from: {sorted(SUPPORTED_CHAINS)}",
        )

    chain_id = SUPPORTED_CHAINS[network_key]
    raw_target = target.strip()

    # A transaction hash reaches the address branch's length check otherwise and
    # fails with a misleading "malformed address" message.
    if TX_HASH_RE.match(raw_target):
        raise HTTPException(
            status_code=400,
            detail=(
                "That is a transaction hash, not an address. Use "
                "/api/v1/forensics/transaction to inspect a transaction."
            ),
        )

    address = validate_address(raw_target)
    cache_key = f"scan:{chain_id}:{address.lower()}"
    if (cached := cache_get(cache_key)) is not None:
        return JSONResponse({**cached, "cached": True})

    async with httpx.AsyncClient(headers={"Accept": "application/json"}) as client:
        (token_data, token_err), (address_data, address_err) = await asyncio.gather(
            query_goplus_token_security(client, chain_id, address),
            query_goplus_address_security(client, chain_id, address),
        )

    is_contract = bool(token_data and token_data.get("token_name"))

    score = 0
    findings: list[dict] = []
    metrics: dict = {}

    if is_contract:
        token_score, token_findings, metrics = score_token(token_data)
        score += token_score
        findings += token_findings

    if address_data:
        address_score, address_findings = score_address(address_data)
        score += address_score
        findings += address_findings

    score = min(100, score)
    sources = {
        "goplus_token_security": token_err or "ok",
        "goplus_address_security": address_err or "ok",
    }
    degraded = bool(token_err or address_err)

    payload = {
        "target": address,
        "network": network_key,
        "chain_id": chain_id,
        "is_contract": is_contract,
        "risk_score": score,
        "risk_level": risk_band(score),
        "findings": findings,
        "metrics": metrics,
        "sources": sources,
        "degraded": degraded,
        "caveat": (
            "One or more threat feeds did not answer, so this result is incomplete."
            if degraded else
            "A score of 0 means nothing matched the feeds queried, which is not a "
            "guarantee the address is safe."
        ),
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "cached": False,
    }

    # Only cache a complete answer; caching a degraded one pins the failure for
    # the whole TTL.
    if not degraded:
        cache_put(cache_key, payload)
    return JSONResponse(payload)

RPC_ENDPOINTS = {
    "ethereum": ["https://ethereum-rpc.publicnode.com", "https://eth.llamarpc.com"],
    "bsc": ["https://bsc-rpc.publicnode.com", "https://bsc-dataseed1.binance.org"],
    "polygon": ["https://polygon-bor-rpc.publicnode.com", "https://polygon-rpc.com"],
    "arbitrum": ["https://arbitrum-one-rpc.publicnode.com", "https://arb1.arbitrum.io/rpc"],
    "avalanche": ["https://avalanche-c-chain-rpc.publicnode.com"],
    "base": ["https://base-rpc.publicnode.com", "https://mainnet.base.org"],
    "optimism": ["https://optimism-rpc.publicnode.com", "https://mainnet.optimism.io"],
}

TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
ERC20_DECIMALS_SELECTOR = "0x313ce567"
ERC20_SYMBOL_SELECTOR = "0x95d89b41"

# Above this many Transfer logs the transaction is a batch and "the largest
# transfer" stops meaning "the payment".
BATCH_TRANSFER_THRESHOLD = 5
MAX_LISTED_TRANSFERS = 50
METADATA_CONCURRENCY = 6


async def rpc_call(client: httpx.AsyncClient, network_key: str, method: str, params: list) -> Any:
    """Try each endpoint for a chain until one answers."""
    failures = []
    for url in RPC_ENDPOINTS.get(network_key, []):
        try:
            response = await client.post(
                url,
                json={"jsonrpc": "2.0", "method": method, "params": params, "id": 1},
                timeout=UPSTREAM_TIMEOUT_S,
            )
            if response.status_code != 200:
                failures.append(f"HTTP {response.status_code}")
                continue
            body = response.json()
            if "error" in body:
                failures.append(str(body["error"].get("message", "RPC error")))
                continue
            return body.get("result")
        except (httpx.RequestError, ValueError) as exc:
            failures.append(exc.__class__.__name__)
    raise HTTPException(
        status_code=502,
        detail=f"No RPC endpoint answered {method} on {network_key}: {'; '.join(failures)}",
    )


def format_units(raw: int, decimals: int) -> str:
    """Exact decimal string. Integer arithmetic only -- no float anywhere."""
    negative = raw < 0
    digits = str(abs(raw)).rjust(decimals + 1, "0")
    whole = digits[: len(digits) - decimals] or "0"
    frac = digits[len(digits) - decimals:].rstrip("0") if decimals else ""
    return f"{'-' if negative else ''}{whole}{'.' + frac if frac else ''}"


def decode_string_result(hex_value: str | None) -> str | None:
    """Decode a `string` return, falling back to bytes32 for older tokens."""
    if not hex_value or hex_value == "0x":
        return None
    body = hex_value.removeprefix("0x")
    if len(body) >= 128:
        try:
            offset = int(body[:64], 16) * 2
            length = int(body[offset:offset + 64], 16) * 2
            if 0 < length <= len(body) - offset - 64:
                text = bytes.fromhex(body[offset + 64:offset + 64 + length]).decode("utf-8", "ignore")
                if text.strip():
                    return text.strip()[:16]
        except (ValueError, IndexError):
            pass
    text = bytes.fromhex(body[:64]).decode("utf-8", "ignore").replace("\x00", "").strip()
    return text[:16] or None


async def resolve_token_meta(
    client: httpx.AsyncClient, network_key: str, contract: str
) -> tuple[int | None, str | None]:
    """Read decimals and symbol from the contract. No default is invented."""
    decimals: int | None = None
    symbol: str | None = None
    try:
        dec_hex = await rpc_call(client, network_key, "eth_call",
                                 [{"to": contract, "data": ERC20_DECIMALS_SELECTOR}, "latest"])
        if dec_hex and dec_hex != "0x":
            candidate = int(dec_hex, 16)
            if 0 <= candidate <= 36:
                decimals = candidate
    except HTTPException:
        pass
    try:
        sym_hex = await rpc_call(client, network_key, "eth_call",
                                 [{"to": contract, "data": ERC20_SYMBOL_SELECTOR}, "latest"])
        symbol = decode_string_result(sym_hex)
    except HTTPException:
        pass
    return decimals, symbol

@app.get("/api/v1/forensics/transaction")
async def inspect_transaction(
    request: Request,
    network: str = Query(..., description="ethereum, bsc, polygon, arbitrum, avalanche, base, optimism"),
    # No min/max_length here on purpose: FastAPI's own 422 for a 42-character
    # address would pre-empt the "that is an address, not a hash" message below,
    # which is the mistake a user pasting from a block explorer actually makes.
    tx_hash: str = Query(..., max_length=100, description="0x-prefixed 32-byte hash"),
    focus: str | None = Query(
        None,
        max_length=100,
        description="Optional address whose transfers to isolate, e.g. the victim's wallet",
    ),
):
    """
    Read a transaction and its receipt, and report every ERC-20 Transfer it
    logged.

    This replaces a stub that only checked the hash was 66 characters long and
    answered "Verified format for EVM block explorer routing" -- a response that
    looked like a result while confirming nothing about the chain.

    Amounts are exact decimal strings scaled by the token's own on-chain
    `decimals()`. When that call fails the amount is reported raw and flagged,
    because a wrong scale factor misstates a loss by orders of magnitude.
    """
    await enforce_rate_limit(request)

    network_key = network.lower().strip()
    if network_key not in SUPPORTED_CHAINS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported network '{network}'. Choose from: {sorted(SUPPORTED_CHAINS)}",
        )
    if network_key not in RPC_ENDPOINTS:
        raise HTTPException(
            status_code=501,
            detail=f"No RPC endpoint is configured for {network_key}.",
        )

    candidate = tx_hash.strip()
    if not TX_HASH_RE.match(candidate):
        if ADDRESS_RE.match(candidate):
            raise HTTPException(
                status_code=400,
                detail=(
                    "That is an address, not a transaction hash. Use "
                    "/api/v1/security/scan to check an address."
                ),
            )
        raise HTTPException(
            status_code=400,
            detail=(
                "Transaction hash must be 0x followed by 64 hex characters "
                f"(received {len(candidate)} characters)."
            ),
        )
    normalised = candidate.lower()

    # Validate `focus` before the cache lookup. Doing it after meant a cache hit
    # (the key is lowercased, so a mistyped-case address maps to the same entry)
    # returned 200 for an address whose EIP-55 checksum was wrong -- the exact
    # typo this check exists to catch.
    focus_checked = validate_address(focus) if focus else None

    cache_key = f"tx:{network_key}:{normalised}:{(focus or '').lower()}"
    if (cached := cache_get(cache_key)) is not None:
        return JSONResponse({**cached, "cached": True})

    notes: list[str] = []

    async with httpx.AsyncClient(headers={"Accept": "application/json"}) as client:
        tx, receipt = await asyncio.gather(
            rpc_call(client, network_key, "eth_getTransactionByHash", [normalised]),
            rpc_call(client, network_key, "eth_getTransactionReceipt", [normalised]),
        )

        if not tx:
            raise HTTPException(
                status_code=404,
                detail=(
                    f"No transaction with that hash on {network_key}. It may be on a "
                    "different chain, or never have been broadcast."
                ),
            )

        # No receipt means the node has the transaction in its pool but no block
        # has included it. Nothing has moved yet, and saying otherwise would be
        # wrong.
        if not receipt:
            payload = {
                "tx_hash": normalised,
                "network": network_key,
                "status": "PENDING",
                "from": to_checksum_address(tx["from"]) if tx.get("from") else None,
                "to": to_checksum_address(tx["to"]) if tx.get("to") else None,
                "transfers": [],
                "transfer_count": 0,
                "notes": ["Transaction is pending: not yet included in a block, no funds moved."],
                "inspected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "cached": False,
            }
            return JSONResponse(payload)

        succeeded = str(receipt.get("status", "0x1")).lower() in ("0x1", "1")
        gas_used = int(receipt.get("gasUsed", "0x0"), 16)
        gas_price = int(receipt.get("effectiveGasPrice") or tx.get("gasPrice") or "0x0", 16)
        native_raw = int(tx.get("value", "0x0"), 16)

        transfers: list[dict] = []
        if succeeded:
            logs = [
                log for log in (receipt.get("logs") or [])
                if (log.get("topics") or [])
                and log["topics"][0].lower() == TRANSFER_TOPIC
                and len(log["topics"]) >= 3
            ]
            # An ERC-721 Transfer shares the topic but carries a fourth indexed
            # topic (the token id) and an empty data field. Treating one as a
            # fungible amount would report a token id as a balance.
            fungible = [log for log in logs if len(log["topics"]) == 3]
            if len(logs) != len(fungible):
                notes.append(
                    f"{len(logs) - len(fungible)} NFT (ERC-721/1155) transfer log(s) "
                    "present and not decoded as amounts."
                )

            # One metadata lookup per distinct token, not per log. A swap route
            # can touch a dozen tokens, so concurrency is bounded rather than
            # firing 2N calls at a public node at once.
            contracts = sorted({log["address"].lower() for log in fungible})
            gate = asyncio.Semaphore(METADATA_CONCURRENCY)

            async def _meta(contract: str) -> tuple[int | None, str | None]:
                async with gate:
                    return await resolve_token_meta(client, network_key, contract)

            resolved = await asyncio.gather(*(_meta(c) for c in contracts))
            meta = dict(zip(contracts, resolved))

            for log in fungible:
                contract = log["address"].lower()
                decimals, symbol = meta.get(contract, (None, None))
                raw = int(log.get("data") or "0x0", 16)
                entry = {
                    "token_contract": to_checksum_address(contract),
                    "token_symbol": symbol,
                    "from": to_checksum_address("0x" + log["topics"][1][-40:]),
                    "to": to_checksum_address("0x" + log["topics"][2][-40:]),
                    "raw_amount": str(raw),
                    "decimals": decimals,
                }
                if decimals is None:
                    entry["amount"] = None
                    entry["amount_display"] = f"{raw} (raw, decimals unknown)"
                    entry["decimals_known"] = False
                else:
                    entry["amount"] = format_units(raw, decimals)
                    entry["amount_display"] = f"{entry['amount']} {symbol or 'tokens'}"
                    entry["decimals_known"] = True
                transfers.append(entry)

            if any(not t["decimals_known"] for t in transfers):
                notes.append(
                    "At least one token's decimals() call failed. Those amounts are raw "
                    "integers and must not be read as token units."
                )

    if not succeeded:
        notes.append("Transaction reverted: gas was spent but no funds moved.")
    if tx.get("to") is None:
        notes.append("Contract creation: this transaction deployed code rather than paying an address.")
    if not transfers and succeeded and native_raw == 0:
        notes.append("No ERC-20 Transfer logs and zero native value: this moved no funds.")

    # Which transfer is "the" transfer?
    #
    # Tested against the tx in this repo's own case file, which turns out to be a
    # 300-transfer batch payout: one 34,823.14 USDC funding leg into a
    # distributor contract, then 299 payouts out of it. "The largest transfer" is
    # the funding leg -- not the 146.07 USDC the case is actually about. The old
    # code took transferLogs[0] and would have reported the same wrong number.
    #
    # So: the largest transfer is offered only as `largest_transfer`, never as an
    # unqualified answer, and a caller who knows whose money they are tracing
    # passes `focus` to get their own leg.
    largest = None
    decodable = [t for t in transfers if t["decimals_known"]]
    if decodable:
        # Group by token first: a fee paid in a second token must not be able to
        # outrank the payment.
        totals: dict[str, int] = defaultdict(int)
        for t in decodable:
            totals[t["token_contract"]] += int(t["raw_amount"])
        dominant = max(totals, key=lambda c: totals[c])
        largest = max(
            (t for t in decodable if t["token_contract"] == dominant),
            key=lambda t: int(t["raw_amount"]),
        )
    elif transfers:
        largest = max(transfers, key=lambda t: int(t["raw_amount"]))

    focus_address = None
    focus_transfers: list[dict] = []
    primary = largest
    if focus_checked:
        focus_address = focus_checked
        low = focus_checked.lower()
        focus_transfers = [
            t for t in transfers
            if t["from"].lower() == low or t["to"].lower() == low
        ]
        incoming = [t for t in focus_transfers if t["to"].lower() == low and t["decimals_known"]]
        if incoming:
            primary = max(incoming, key=lambda t: int(t["raw_amount"]))
        elif focus_transfers:
            primary = focus_transfers[0]
        else:
            primary = None
            notes.append(
                f"{focus_checked} does not appear in any Transfer log of this "
                "transaction, in either direction."
            )

    if len(transfers) > BATCH_TRANSFER_THRESHOLD:
        senders = {t["from"] for t in transfers}
        notes.append(
            f"Batch transaction: {len(transfers)} Transfer logs from "
            f"{len(senders)} sender(s). The largest transfer is most likely the leg "
            "that funded the batch, not any individual payment. Pass "
            "?focus=<address> to isolate one party's transfers."
        )

    # A 300-transfer receipt is a large response and most of it is other
    # people's payments. Truncate, but never drop a focused transfer, and say so.
    listed = focus_transfers if focus_transfers else transfers
    truncated = len(listed) > MAX_LISTED_TRANSFERS
    if truncated:
        notes.append(
            f"Showing {MAX_LISTED_TRANSFERS} of {len(listed)} transfers. "
            "Pass ?focus=<address> to see only the transfers involving one address."
        )

    payload = {
        "tx_hash": normalised,
        "network": network_key,
        "chain_id": SUPPORTED_CHAINS[network_key],
        "status": "SUCCESS" if succeeded else "FAILED",
        "block_number": int(receipt["blockNumber"], 16) if receipt.get("blockNumber") else None,
        "from": to_checksum_address(tx["from"]) if tx.get("from") else None,
        "to": to_checksum_address(tx["to"]) if tx.get("to") else None,
        "is_contract_creation": tx.get("to") is None,
        "native_value": format_units(native_raw, 18),
        "fee_paid": format_units(gas_used * gas_price, 18),
        "transfers": listed[:MAX_LISTED_TRANSFERS],
        "transfers_truncated": truncated,
        "transfer_count": len(transfers),
        "focus_address": focus_address,
        "focus_transfer_count": len(focus_transfers) if focus_checked else None,
        "primary_transfer": primary,
        "largest_transfer": largest,
        "notes": notes,
        "method": (
            "Decoded from the transaction receipt over public JSON-RPC. Reports only "
            "what this transaction logged; it does not attribute addresses to entities "
            "or trace onward hops. With no `focus` address, `primary_transfer` is "
            "simply the largest transfer of the dominant token and carries no claim "
            "about which payment matters."
        ),
        "inspected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "cached": False,
    }

    # A mined transaction is immutable, so caching it is safe. A pending one is
    # never cached, and it returns before this point. The key carries `focus`,
    # since that changes which transfers are listed.
    cache_put(cache_key, payload)
    return JSONResponse(payload)


@app.get("/health")
async def health():
    """Liveness plus the configuration that changes how answers are produced."""
    return {
        "status": "ok",
        "version": APP_VERSION,
        "supported_networks": sorted(SUPPORTED_CHAINS),
        "rpc_configured_networks": sorted(RPC_ENDPOINTS),
        "threat_feed": GOPLUS_BASE,
        "allowed_origins": ALLOWED_ORIGINS,
        "rate_limit": f"{RATE_LIMIT_REQUESTS} requests / {RATE_LIMIT_WINDOW_S}s per client",
        "cache_ttl_seconds": CACHE_TTL_S,
        "trust_proxy_headers": TRUST_PROXY,
    }
