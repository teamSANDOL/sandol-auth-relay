import base64, hashlib, json, secrets, time
from typing import Any, Dict, Optional

import httpx
import jwt

from app.config.config import Config

OIDC_AUTH  = f"{Config.KC_BASE}/protocol/openid-connect/auth"
OIDC_TOKEN = f"{Config.KC_BASE}/protocol/openid-connect/token"
OIDC_JWKS  = f"{Config.KC_BASE}/protocol/openid-connect/certs"

SESS: Dict[str, Dict[str, Any]] = {}   # state -> {...}
JWKS_CACHE: Dict[str, Any] = {"keys": None, "ts": 0}

def now_ts() -> int:
    return int(time.time())

def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return b64url(digest)

def make_lit(chatbot_user_id: str, callback_url: str, redirect_after: Optional[str]) -> str:
    iat = now_ts()
    payload = {
        "iss": "auth-relay",
        "aud": "login",
        "jti": secrets.token_urlsafe(16),
        "iat": iat,
        "nbf": iat,
        "exp": iat + Config.LIT_TTL_SECONDS,
        "chatbot_user_id": chatbot_user_id,
        "callback_url": callback_url,
    }
    if redirect_after:
        payload["redirect_after"] = redirect_after
    return jwt.encode(payload, Config.JWT_SECRET, algorithm="HS256")

def redirect_allowed(url: Optional[str]) -> bool:
    if not url:
        return True
    return any(url.startswith(p) for p in Config.REDIRECT_AFTER_ALLOWLIST)

async def get_jwk_by_kid(kid: str):
    t = now_ts()
    if not JWKS_CACHE["keys"] or (t - JWKS_CACHE["ts"] > 3600):
        async with httpx.AsyncClient(timeout=8.0) as cx:
            r = await cx.get(OIDC_JWKS)
            r.raise_for_status()
            JWKS_CACHE["keys"] = r.json()["keys"]
            JWKS_CACHE["ts"] = t
    for k in JWKS_CACHE["keys"]:
        if k.get("kid") == kid:
            return jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(k))
    raise RuntimeError("jwks_key_not_found")
