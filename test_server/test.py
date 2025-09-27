"""Chatbot Stub (Single File) — Token Exchange with client_secret

- 목적: auth-relay가 전달한 relay_access_token을 받아서
        Token Exchange(client_secret)로 챗봇 오디언스 토큰을 획득하는 최소 서버.
- 외부 저장소: 없음(메모리 nonce 캐시)
- 보안: HMAC 서명 검증 + timestamp 스큐 제한 + nonce 1회용

실행:
  pip install fastapi uvicorn[standard] python-keycloak
  uvicorn chatbot_stub:app --reload --port 9000
"""

from __future__ import annotations

import json
import os
import time
import hmac
from hashlib import sha256
from base64 import urlsafe_b64encode
from typing import Any, Dict

from fastapi import FastAPI, APIRouter, Header, HTTPException
from fastapi.responses import JSONResponse
from keycloak import KeycloakOpenID


# =============================
# 설정 (환경변수 기반)
# =============================

KC_SERVER_URL = os.getenv(
    "KC_SERVER_URL", "https://kc.example.com/"
)  # 예: v18+는 /auth 없음
KC_REALM = os.getenv("KC_REALM", "myrealm")
KC_CLIENT_ID = os.getenv("KC_CLIENT_ID", "chatbot-client")
KC_CLIENT_SECRET = os.getenv("KC_CLIENT_SECRET", "REDACTED")  # client_secret_basic/post

HMAC_SECRET = os.getenv("RELAY_TO_CHATBOT_HMAC_SECRET", "dev-hmac-secret-please-change")
TS_SKEW_SECONDS = int(os.getenv("TS_SKEW_SECONDS", "60"))  # 허용 스큐(초)
NONCE_TTL_SECONDS = int(os.getenv("NONCE_TTL_SECONDS", "300"))  # 1회용 nonce TTL


# =============================
# 유틸/보안
# =============================

_NONCE_CACHE: Dict[str, int] = {}  # 아주 단순한 메모리 캐시


def _canonical_json(data: Dict[str, Any]) -> str:
    """HMAC 서명을 위한 정규화 JSON 문자열.

    Args:
        data: 페이로드 dict.

    Returns:
        정렬된 키 순서로 직렬화된 JSON 문자열.
    """
    return json.dumps(data, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def _sign_payload(payload: Dict[str, Any]) -> str:
    """HMAC-SHA256 서명 생성.

    Args:
        payload: 서명 대상 페이로드.

    Returns:
        base64url 인코딩된 서명 문자열.
    """
    msg = _canonical_json(payload).encode("utf-8")
    mac = hmac.new(HMAC_SECRET.encode("utf-8"), msg, sha256).digest()
    return urlsafe_b64encode(mac).decode().rstrip("=")


def _verify_signature(header_sig: str | None, payload: Dict[str, Any]) -> None:
    """X-Relay-Signature와 자체 계산 서명을 비교(상수시간).

    Args:
        header_sig: 헤더의 서명 문자열.
        payload: 본문 페이로드(dict).

    Raises:
        HTTPException: 서명이 불일치할 때.
    """
    if not header_sig:
        raise HTTPException(status_code=400, detail="missing_signature")
    expected = _sign_payload(payload)
    if not hmac.compare_digest(header_sig, expected):
        raise HTTPException(status_code=400, detail="bad_signature")


def _verify_timestamp(ts: int, skew: int = TS_SKEW_SECONDS) -> None:
    """timestamp 스큐 검증.

    Args:
        ts: epoch seconds.
        skew: 허용 오차(초).

    Raises:
        HTTPException: 스큐 초과 시.
    """
    now = int(time.time())
    if abs(now - ts) > skew:
        raise HTTPException(status_code=400, detail="timestamp_skew")


def _mark_nonce_once(nonce: str, ttl: int = NONCE_TTL_SECONDS) -> None:
    """nonce를 1회용으로 마킹(메모리). 중복 사용 시 거부.

    Args:
        nonce: 고유 nonce 문자열.
        ttl: 만료(초).

    Raises:
        HTTPException: 재사용된 nonce인 경우.
    """
    if not nonce:
        raise HTTPException(status_code=400, detail="missing_nonce")
    now = int(time.time())
    # 만료된 항목 청소(대충)
    expired = [k for k, v in _NONCE_CACHE.items() if now - v > ttl]
    for k in expired:
        _NONCE_CACHE.pop(k, None)
    if nonce in _NONCE_CACHE:
        raise HTTPException(status_code=400, detail="reused_nonce")
    _NONCE_CACHE[nonce] = now


# =============================
# Keycloak 클라이언트
# =============================


def kc_client() -> KeycloakOpenID:
    """KeycloakOpenID 인스턴스 생성.

    Returns:
        KeycloakOpenID: TE 및 userinfo 호출에 사용.
    """
    return KeycloakOpenID(
        server_url=KC_SERVER_URL,
        realm_name=KC_REALM,
        client_id=KC_CLIENT_ID,
        client_secret_key=KC_CLIENT_SECRET,
        timeout=10,
    )


# =============================
# FastAPI 라우터
# =============================

router = APIRouter(tags=["relay-callback"])


@router.post("/auth/relay/callback")
async def relay_callback(
    payload: Dict[str, Any], x_relay_signature: str | None = Header(default=None)
):
    """auth-relay → 챗봇 서버 콜백 수신 핸들러.

    Relay가 Access Token(=subject_token) 등을 전달하면,
    여기서 HMAC/타임스탬프/nonce 검증 후 Token Exchange(client_secret)를 수행한다.

    Args:
        payload: relay가 전송한 JSON 페이로드. 필드:
            - relay_access_token: relay가 받은 Access Token
            - issuer: Keycloak Issuer(참고용)
            - aud: relay-client (참고용)
            - chatbot_user_id: 내부 사용자 식별자(참고용)
            - client_key: 통합 키(참고용)
            - ts: 타임스탬프(epoch)
            - nonce: 1회용 난수
        x_relay_signature: HMAC-SHA256(base64url). canonical_json(payload)에 대한 서명.

    Returns:
        JSONResponse: TE 결과 요약 및(옵션) userinfo 일부.
    """
    # 1) 서명 검증
    _verify_signature(x_relay_signature, payload)

    # 2) 타임스탬프 검증
    ts = int(payload.get("ts", 0))
    _verify_timestamp(ts)

    # 3) nonce 1회용
    _mark_nonce_once(str(payload.get("nonce", "")))

    # 4) 필수 필드 확인
    relay_access_token = payload.get("relay_access_token")
    if not relay_access_token:
        raise HTTPException(status_code=400, detail="missing_relay_access_token")

    # 5) Token Exchange (client_secret)
    kc = kc_client()
    try:
        te = kc.exchange_token(
            token=relay_access_token,
            audience=KC_CLIENT_ID,  # 챗봇 오디언스
            requested_token_type="urn:ietf:params:oauth:token-type:access_token",
            scope="openid profile",
        )
    except Exception as e:
        # Keycloak 정책/권한 문제 시 흔히 발생: unauthorized_client / invalid_target 등
        raise HTTPException(status_code=502, detail=f"token_exchange_failed: {e}")

    # 6) (옵션) userinfo로 간단 유효성 체크
    ui = None
    try:
        ui = kc.userinfo(te["access_token"])
    except Exception:
        ui = None  # 필수 아님

    # 7) 민감한 값은 그대로 반환하지 않고 요약 전달
    summary = {
        "status": "ok",
        "exchanged_aud": KC_CLIENT_ID,
        "expires_in": te.get("expires_in"),
        "has_refresh_token": bool(te.get("refresh_token")),
        "userinfo_sub": (ui or {}).get("sub"),
    }
    return JSONResponse(summary, status_code=200)


# =============================
# FastAPI 앱
# =============================


def create_app() -> FastAPI:
    """FastAPI 앱 생성.

    Returns:
        FastAPI: 애플리케이션 인스턴스.
    """
    app = FastAPI(title="Chatbot Stub (TE via client_secret)")
    app.include_router(router)
    return app


app = create_app()
