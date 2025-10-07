from __future__ import annotations
import time
from typing import Dict, Any, Optional
from app.config import Config

# 메모리 세션(운영에서는 Redis/DB를 권장)
_SESS: Dict[str, Dict[str, Any]] = {}


def sess_set(state: str, data: Dict[str, Any]) -> None:
    """state 기반 세션 저장.

    Args:
        state: 세션 키.
        data: 저장 데이터.
    """
    _SESS[state] = data


def sess_pop(state: str) -> Optional[Dict[str, Any]]:
    """state 기반 세션 조회 및 삭제.

    Args:
        state: 세션 키.

    Returns:
        저장 데이터 또는 None.
    """
    return _SESS.pop(state, None)


def sess_expired(ts: int) -> bool:
    """세션 만료 여부 판정.

    Args:
        ts: 생성 시각(epoch seconds).

    Returns:
        True 만료 / False 유효.
    """
    return (int(time.time()) - ts) > Config.STATE_TTL_SECONDS
