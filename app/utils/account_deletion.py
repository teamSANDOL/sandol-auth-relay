"""회원 탈퇴 정보의 복호화, 검사, 저장을 담당하는 모듈입니다."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from diskcache import Cache
from fastapi import HTTPException, status

from app.config import Config, logger

KEY_BYTES = 32
IV_BYTES = 12
REQUIRED_FIELDS = ("event_id", "realm", "user_id")
SQLITE_SYNCHRONOUS_FULL = 2


def _reject(status_code: int, reason: str) -> HTTPException:
    """거절 사유만 로그에 남기고 응답용 예외를 만든다."""
    logger.warning("account_deletion: rejected (reason=%s)", reason)
    return HTTPException(status_code, reason)


def load_key() -> bytes:
    """설정된 키를 읽는다. 없거나 형식이 틀리면 503으로 거절한다."""
    try:
        key = base64.b64decode(Config.SANDOL_DELETION_KEY, validate=True)
    except ValueError as e:
        raise _reject(
            status.HTTP_503_SERVICE_UNAVAILABLE, "deletion_key_not_configured"
        ) from e
    if len(key) != KEY_BYTES:
        raise _reject(
            status.HTTP_503_SERVICE_UNAVAILABLE, "deletion_key_not_configured"
        )
    return key


def parse_envelope(raw_body: bytes) -> dict[str, str]:
    """요청 본문에서 kid, iv, ciphertext를 꺼내 확인한다. 틀리면 400으로 거절한다."""
    try:
        body = json.loads(raw_body)
    except ValueError as e:
        raise _reject(status.HTTP_400_BAD_REQUEST, "invalid_envelope") from e
    if not isinstance(body, dict):
        raise _reject(status.HTTP_400_BAD_REQUEST, "invalid_envelope")

    envelope = {name: body.get(name) for name in ("kid", "iv", "ciphertext")}
    if not all(value and isinstance(value, str) for value in envelope.values()):
        raise _reject(status.HTTP_400_BAD_REQUEST, "invalid_envelope")
    if envelope["kid"] != Config.SANDOL_DELETION_KEY_ID:
        raise _reject(status.HTTP_400_BAD_REQUEST, "unknown_kid")
    return envelope


def decrypt_payload(key: bytes, envelope: dict[str, str]) -> dict[str, Any]:
    """암호문을 풀고 필수 값을 확인한다. 위조나 다른 키면 401, 형식 오류면 400이다."""
    try:
        iv = base64.b64decode(envelope["iv"], validate=True)
        ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
    except ValueError as e:
        raise _reject(status.HTTP_400_BAD_REQUEST, "invalid_envelope") from e
    if len(iv) != IV_BYTES:
        raise _reject(status.HTTP_400_BAD_REQUEST, "invalid_envelope")

    try:
        plaintext = AESGCM(key).decrypt(iv, ciphertext, None)
    except InvalidTag as e:
        raise _reject(status.HTTP_401_UNAUTHORIZED, "decryption_failed") from e

    try:
        payload = json.loads(plaintext)
    except ValueError as e:
        raise _reject(status.HTTP_400_BAD_REQUEST, "invalid_payload") from e
    if not isinstance(payload, dict):
        raise _reject(status.HTTP_400_BAD_REQUEST, "invalid_payload")
    for field in REQUIRED_FIELDS:
        if not payload.get(field) or not isinstance(payload[field], str):
            raise _reject(status.HTTP_400_BAD_REQUEST, "invalid_payload")
    return payload


def save_deletion(envelope: dict[str, str], payload: dict[str, Any]) -> bool:
    """암호문과 찾기용 메타데이터를 저장한다. 이미 있으면 그대로 두고 False를 돌려준다."""
    record = {
        "event_id": payload["event_id"],
        "realm": payload["realm"],
        "user_id": payload["user_id"],
        "received_at": datetime.now(timezone.utc).isoformat(),
        "envelope": envelope,
    }
    # eviction_policy: 용량이 차도 자동 삭제 안 함, sqlite_synchronous: 정전에도 남도록 디스크에 바로 기록
    with Cache(
        Config.DELETION_STORE_DIR,
        eviction_policy="none",
        sqlite_synchronous=SQLITE_SYNCHRONOUS_FULL,
    ) as cache:
        return cache.add(f"{payload['realm']}:{payload['user_id']}", record)
