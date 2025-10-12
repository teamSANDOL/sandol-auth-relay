from __future__ import annotations
import hmac
import json
import time
from typing import Dict, Any
from hashlib import sha256
from base64 import urlsafe_b64encode

from fastapi import HTTPException
from app.config import Config


def canonical_json(data: Dict[str, Any]) -> str:
    """HMAC 서명을 위한 정규화 JSON 문자열을 생성한다.

    Args:
        data (Dict[str, Any]): 서명 대상 페이로드.

    Returns:
        str: 정렬된 키 순서로 직렬화된 JSON 문자열.
    """
    return json.dumps(data, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def sign_payload(payload: Dict[str, Any]) -> str:
    """relay→chatbot HMAC-SHA256 서명을 생성한다.

    Args:
        payload (Dict[str, Any]): 서명 대상 페이로드.

    Returns:
        str: base64url 인코딩된 서명 문자열.
    """
    msg = canonical_json(payload).encode("utf-8")
    mac = hmac.new(
        Config.RELAY_TO_CHATBOT_HMAC_SECRET.encode("utf-8"), msg, sha256
    ).digest()
    return urlsafe_b64encode(mac).decode().rstrip("=")


def verify_timestamps(ts: int, skew: int = 60) -> None:
    """타임스탬프 유효성을 검증한다.

    Args:
        ts (int): 요청에 포함된 epoch seconds.
        skew (int): 허용 오차(초).

    Raises:
        HTTPException: 허용 범위를 벗어난 경우.
    """
    now = int(time.time())
    if abs(now - ts) > skew:
        raise HTTPException(
            status_code=Config.HttpStatus.BAD_REQUEST, detail="timestamp_skew"
        )
