from __future__ import annotations
from typing import Dict, Any
from keycloak import KeycloakOpenID


def kc_client(cfg: Dict[str, Any]) -> KeycloakOpenID:
    """KeycloakOpenID 클라이언트 생성.

    Args:
        cfg: client 설정(dict).

    Returns:
        KeycloakOpenID 인스턴스.
    """
    return KeycloakOpenID(
        server_url=cfg["server_url"],
        realm_name=cfg["realm"],
        client_id=cfg["client_id"],
        client_secret_key=cfg.get("client_secret"),
        timeout=10,
    )


def kc_well_known(kc: KeycloakOpenID) -> Dict[str, Any]:
    """Well-known OpenID Provider 메타데이터 조회.

    Args:
        kc: KeycloakOpenID 인스턴스.

    Returns:
        well-known JSON dict.
    """
    return kc.well_known()
