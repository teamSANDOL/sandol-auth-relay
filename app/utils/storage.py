from __future__ import annotations
import os
import time
from typing import Dict, Any, Optional
from diskcache import FanoutCache
from app.config import Config

# Disk-backed 세션 스토리지(FanoutCache 기반, 기본 디렉터리는 프로젝트 루트/.cache/sessions)
_UTILS_DIR = os.path.dirname(__file__)
_DEFAULT_CACHE_DIR = os.path.abspath(os.path.join(_UTILS_DIR, "../..", ".cache", "sessions"))
_CACHE_DIR = os.getenv("SESSION_CACHE_DIR", _DEFAULT_CACHE_DIR)
_CACHE = FanoutCache(directory=_CACHE_DIR, shards=8)


def sess_set(state: str, data: Dict[str, Any]) -> None:
    """state 키로 세션 데이터를 저장한다.

    Args:
        state (str): 세션 식별 키.
        data (Dict[str, Any]): 저장할 세션 데이터.
    """
    _CACHE.set(state, data, expire=Config.STATE_TTL_SECONDS)


def sess_pop(state: str) -> Optional[Dict[str, Any]]:
    """state 키로 세션을 조회하고 삭제한다.

    Args:
        state (str): 세션 식별 키.

    Returns:
        Optional[Dict[str, Any]]: 존재하면 저장 데이터, 없으면 None.
    """
    return _CACHE.pop(state, default=None)


def sess_expired(ts: int) -> bool:
    """세션 만료 여부를 판정한다.

    Args:
        ts (int): 세션 생성 시각(epoch seconds).

    Returns:
        bool: 만료 시 True, 유효 시 False.
    """
    return (int(time.time()) - ts) > Config.STATE_TTL_SECONDS
