from __future__ import annotations
import base64
import hashlib
import secrets
import time
from typing import Dict, Any, Optional
from urllib.parse import urlencode

import jwt
from fastapi import HTTPException
from app.config import Config

def now_ts() -> int:
    """현재 epoch seconds 반환."""
    return int(time.time())

def gen_code_verifier(n: int = 64) -> str:
    """PKCE code_verifier 생성.

    Args:
        n: 바이트 길이(43~128 문자를 만족하도록 충분히 크게).
    Returns:
        base64url 패딩 제거 문자열.
    """
    return base64.urlsafe_b64encode(secrets.token_bytes(n)).decode().rstrip("=")

def code_challenge_s256(verifier: str) -> str:
    """PKCE code_challenge(S256) 생성.

    Args:
        verifier: code_verifier 문자열.
    Returns:
        base64url(SHA-256(verifier)) 문자열.
    """
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")

def redirect_allowed(dest: Optional[str]) -> bool:
    """최종 리다이렉트 목적지 검증(allowlist prefix 매칭).

    Args:
        dest: 목적지 문자열.
    Returns:
        허용 여부.
    """
    if not dest:
        return True
    for prefix in Config.REDIRECT_ALLOWLIST:
        if dest.startswith(prefix):
            return True
    return False

def resolve_client(client_key: str) -> Dict[str, Any]:
    """client_key로 클라이언트 설정 조회.

    Args:
        client_key: 등록된 클라이언트 키.
    Returns:
        설정 dict.
    Raises:
        HTTPException: 등록되지 않은 키.
    """
    cfg = Config.CLIENTS.get(client_key)
    if not cfg:
        raise HTTPException(400, "unknown_client_key")
    return cfg

def make_lit(*, chatbot_user_id: str, callback_url: str, client_key: str, redirect_after: Optional[str]) -> str:
    """로그인 링크 토큰(LIT) 발급.

    Args:
        chatbot_user_id: 챗봇 사용자 식별자.
        callback_url: 챗봇 콜백 URL.
        client_key: 등록된 클라이언트 키.
        redirect_after: 최종 리다이렉트 목적지.
    Returns:
        HS256 서명된 LIT 문자열.
    """
    now = now_ts()
    claims = {
        "iss": Config.LIT_ISSUER,
        "aud": Config.LIT_AUDIENCE,
        "iat": now,
        "nbf": now,
        "exp": now + Config.STATE_TTL_SECONDS,
        "chatbot_user_id": chatbot_user_id,
        "callback_url": callback_url,
        "client_key": client_key,
        "redirect_after": redirect_after,
    }
    return jwt.encode(claims, Config.JWT_SECRET, algorithm="HS256")

def decode_lit(lit: str) -> Dict[str, Any]:
    """LIT 디코드 및 검증.

    Args:
        lit: lit 값.
    Returns:
        클레임 dict.
    Raises:
        HTTPException: 유효하지 않거나 만료된 경우.
    """
    from jwt import InvalidTokenError
    try:
        data = jwt.decode(
            lit,
            Config.JWT_SECRET,
            algorithms=["HS256"],
            options={"require": ["exp", "iat", "nbf"]},
            issuer=Config.LIT_ISSUER,
            audience=Config.LIT_AUDIENCE,
            leeway=5,
        )
        return data
    except InvalidTokenError:
        raise HTTPException(400, "invalid_or_expired_link")

def build_authorize_url(*, auth_endpoint: str, cfg: Dict[str, Any], state: str, nonce: str, code_challenge: str) -> str:
    """인가 URL 생성(수동 빌드, PKCE 포함).

    Args:
        auth_endpoint: authorization_endpoint.
        cfg: 클라이언트 설정.
        state: CSRF 방지 state.
        nonce: 재사용 방지 nonce.
        code_challenge: PKCE 코드 챌린지(S256).
    Returns:
        사용자 리다이렉트용 인가 URL.
    """
    params = {
        "client_id": cfg["client_id"],
        "redirect_uri": cfg["redirect_uri"],
        "response_type": "code",
        "scope": cfg.get("scope", "openid"),
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return f"{auth_endpoint}?{urlencode(params)}"
