from __future__ import annotations
from typing import Dict, Any
from keycloak import KeycloakOpenID


def kc_client(cfg: Dict[str, Any]) -> KeycloakOpenID:
    """KeycloakOpenID 클라이언트를 생성한다.

    Args:
        cfg (Dict[str, Any]): 클라이언트 설정 딕셔너리.

    Returns:
        KeycloakOpenID: KeycloakOpenID 인스턴스.
    """
    return KeycloakOpenID(
        server_url=cfg["server_url"],
        realm_name=cfg["realm"],
        client_id=cfg["client_id"],
        client_secret_key=cfg.get("client_secret"),
        timeout=10,
    )


def kc_well_known(kc: KeycloakOpenID) -> Dict[str, Any]:
    """Well-known OpenID Provider 메타데이터를 조회한다.

    Args:
        kc (KeycloakOpenID): KeycloakOpenID 인스턴스.

    Returns:
        Dict[str, Any]: well-known JSON 메타데이터.
    """
    return kc.well_known()
