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
from app.utils.clients import get_client_registry, ClientConfig


def now_ts() -> int:
    """현재 epoch seconds를 반환한다.

    Returns:
        int: 현재 epoch seconds.
    """
    return int(time.time())


def gen_code_verifier(n: int = 64) -> str:
    """PKCE code_verifier를 생성한다.

    Args:
        n (int): 토큰 바이트 길이로, 43~128 문자를 만족하도록 충분히 크게 설정한다.

    Returns:
        str: base64url 패딩이 제거된 문자열 code_verifier.
    """
    return base64.urlsafe_b64encode(secrets.token_bytes(n)).decode().rstrip("=")


def code_challenge_s256(verifier: str) -> str:
    """PKCE code_challenge(S256)를 생성한다.

    Args:
        verifier (str): code_verifier 문자열.

    Returns:
        str: base64url(SHA-256(verifier))로 생성된 code_challenge.
    """
    return (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )


def redirect_allowed(dest: Optional[str]) -> bool:
    """최종 리다이렉트 목적지를 allowlist로 검증한다.

    Args:
        dest (Optional[str]): 리다이렉트 대상 문자열.

    Returns:
        bool: 허용된 목적지면 True, 아니면 False.
    """
    if not dest:
        return True
    for prefix in Config.REDIRECT_ALLOWLIST:
        if dest.startswith(prefix):
            return True
    return False


def resolve_client(client_key: str) -> ClientConfig:
    """client_key에 해당하는 클라이언트 설정을 조회한다.

    Args:
        client_key (str): 등록된 클라이언트 키.

    Returns:
        ClientConfig: 매칭된 클라이언트 설정.

    Raises:
        HTTPException: 등록되지 않은 클라이언트 키인 경우.
    """
    cfg: ClientConfig = get_client_registry()[client_key]
    if not cfg:
        raise HTTPException(400, "unknown_client_key")
    return cfg


def make_lit(
    *,
    chatbot_user_id: str,
    callback_url: str,
    client_key: str,
    redirect_after: Optional[str],
) -> str:
    """로그인 링크 토큰(LIT)을 발급한다.

    Args:
        chatbot_user_id (str): 챗봇 사용자 식별자.
        callback_url (str): 챗봇 서버 콜백 URL.
        client_key (str): 등록된 클라이언트 키.
        redirect_after (Optional[str]): 최종 리다이렉트 목적지.

    Returns:
        str: HS256으로 서명된 LIT 문자열.
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
    """LIT 토큰을 디코드하고 유효성을 검증한다.

    Args:
        lit (str): 검증 대상 LIT 문자열.

    Returns:
        Dict[str, Any]: 디코드된 클레임 딕셔너리.

    Raises:
        HTTPException: 토큰이 유효하지 않거나 만료된 경우.
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


def build_authorize_url(
    *,
    auth_endpoint: str,
    cfg: ClientConfig,
    state: str,
    nonce: str,
    code_challenge: str,
) -> str:
    """PKCE 정보를 포함한 인가 URL을 생성한다.

    Args:
        auth_endpoint (str): authorization_endpoint URL.
        cfg (Dict[str, Any]): 클라이언트 설정 딕셔너리.
        state (str): CSRF 방지용 state 값.
        nonce (str): 재사용 방지 nonce 값.
        code_challenge (str): PKCE 코드 챌린지(S256).

    Returns:
        str: 사용자 리다이렉트용 인가 URL.
    """
    params = {
        "client_id": cfg.client_id,
        "redirect_uri": cfg.redirect_uri,
        "response_type": "code",
        "scope": "openid profile email offline_access",
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return f"{auth_endpoint}?{urlencode(params)}"
