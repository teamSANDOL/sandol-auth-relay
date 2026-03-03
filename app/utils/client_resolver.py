from __future__ import annotations

from fastapi import HTTPException

from app.utils.clients import ClientConfig, get_client_registry


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
