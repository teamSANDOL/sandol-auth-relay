r"""서버 간 요청 서명(HMAC-SHA256) 생성·검증.

호출자(예: kakao-bot)가 relay의 서버 간 API(현재 issue_login_link)를 부를 때
아래 canonical 문자열에 client별 비밀로 HMAC-SHA256 서명을 붙인다.

    SANDOL-RELAY-HMAC-V1\n<METHOD>\n<PATH>\n<TIMESTAMP>\n<NONCE>\n<CLIENT_KEY>\n<SHA256_HEX(BODY)>

- PATH: relay 기준 경로(root_path "/relay" 제외, 예: "/issue_login_link").
  게이트웨이·직접 호출 어느 경로로 와도 같은 값이 되도록 라우트 경로를 쓴다.
- 서명: base64url(패딩 제거), relay→chatbot 콜백 서명과 같은 인코딩.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import time
from base64 import urlsafe_b64encode
from typing import NamedTuple

from fastapi import HTTPException, Request

from app.config import Config, logger
from app.utils.clients import get_client_registry
from app.utils.storage import nonce_add_once

SIGNATURE_VERSION = "SANDOL-RELAY-HMAC-V1"
HEADER_CLIENT_KEY = "X-Relay-Client-Key"
HEADER_TIMESTAMP = "X-Relay-Timestamp"
HEADER_NONCE = "X-Relay-Nonce"
HEADER_SIGNATURE = "X-Relay-Request-Signature"

_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_TS_RE = re.compile(r"^\d{1,12}$")


class SignatureError(Exception):
    """서명 검증 실패. reason은 로그용 사유 코드다(응답에 노출하지 않음)."""

    def __init__(self, reason: str) -> None:
        """사유 코드를 보관한다."""
        super().__init__(reason)
        self.reason = reason


class SignedRequest(NamedTuple):
    """서명 대상 요청 요소."""

    method: str
    path: str
    ts: str
    nonce: str
    client_key: str
    body: bytes


def canonical_request(req: SignedRequest) -> str:
    """서명 대상 canonical 문자열을 만든다."""
    body_hash = hashlib.sha256(req.body).hexdigest()
    return "\n".join(
        [
            SIGNATURE_VERSION,
            req.method.upper(),
            req.path,
            req.ts,
            req.nonce,
            req.client_key,
            body_hash,
        ]
    )


def sign_request(secret: str, req: SignedRequest) -> str:
    """canonical 문자열의 HMAC-SHA256 서명(base64url, 패딩 제거)을 만든다."""
    msg = canonical_request(req).encode("utf-8")
    mac = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256)
    return urlsafe_b64encode(mac.digest()).decode().rstrip("=")


def _lookup_secret(client_key: str) -> str:
    try:
        cfg = get_client_registry()[client_key]
    except KeyError:
        raise SignatureError("unknown_client") from None
    if not cfg.issue_link_secret:
        raise SignatureError("no_client_secret")
    return cfg.issue_link_secret


def verify_request(
    *,
    method: str,
    path: str,
    headers: dict[str, str],
    body: bytes,
    body_client_key: str,
) -> str:
    """서명 헤더를 검증하고 인증된 client_key를 반환한다.

    Raises:
        SignatureError: 검증 실패(사유 코드 포함).
    """
    client_key = headers.get(HEADER_CLIENT_KEY.lower(), "")
    ts = headers.get(HEADER_TIMESTAMP.lower(), "")
    nonce = headers.get(HEADER_NONCE.lower(), "")
    signature = headers.get(HEADER_SIGNATURE.lower(), "")
    if not (client_key and ts and nonce and signature):
        raise SignatureError("missing_headers")
    if not _TS_RE.match(ts):
        raise SignatureError("bad_timestamp")
    if abs(int(time.time()) - int(ts)) > Config.ISSUE_LINK_AUTH_SKEW_SECONDS:
        raise SignatureError("timestamp_skew")
    if not _NONCE_RE.match(nonce):
        raise SignatureError("bad_nonce")

    secret = _lookup_secret(client_key)
    req = SignedRequest(method, path, ts, nonce, client_key, body)
    expected = sign_request(secret, req)
    if not hmac.compare_digest(signature.encode(), expected.encode()):
        raise SignatureError("bad_signature")
    # 본문이 서명으로 보호되므로, 본문 client_key가 서명자와 같아야 한다.
    if body_client_key != client_key:
        raise SignatureError("client_mismatch")
    # 서명이 맞은 요청만 nonce를 소비한다(위조 요청으로 캐시를 채우지 못하게).
    # 창(±skew) 전체를 덮도록 TTL을 2배로 둔다.
    ttl = Config.ISSUE_LINK_AUTH_SKEW_SECONDS * 2
    if not nonce_add_once(f"issue-link-nonce:{client_key}:{nonce}", ttl):
        raise SignatureError("nonce_reused")
    return client_key


async def authorize_issue_link(request: Request, body_client_key: str) -> None:
    """ISSUE_LINK_AUTH_MODE에 따라 issue_login_link 호출자를 검증한다.

    - off: 검증하지 않는다.
    - warn: 실패해도 통과시키고 사유 코드만 경고 로그로 남긴다.
    - enforce: 실패 시 401(본문에 사유 미노출).
    """
    mode = Config.ISSUE_LINK_AUTH_MODE
    if mode == "off":
        return
    route = request.scope.get("route")
    path = getattr(route, "path", request.url.path)
    try:
        verify_request(
            method=request.method,
            path=path,
            headers={k.lower(): v for k, v in request.headers.items()},
            body=await request.body(),
            body_client_key=body_client_key,
        )
    except SignatureError as exc:
        if mode == "enforce":
            logger.warning(
                "issue_login_link auth rejected: reason=%s client_key=%s",
                exc.reason,
                body_client_key,
            )
            raise HTTPException(
                Config.HttpStatus.UNAUTHORIZED, "unauthorized"
            ) from None
        logger.warning(
            "issue_login_link auth failed (warn mode, allowed): reason=%s client_key=%s",
            exc.reason,
            body_client_key,
        )
        return
    logger.info("issue_login_link auth ok: client_key=%s", body_client_key)
