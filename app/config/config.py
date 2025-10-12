"""Config: FastAPI 앱의 설정을 정의하는 모듈입니다."""

from __future__ import annotations
import json
import os
import logging
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

# 현재 파일이 위치한 디렉터리 (config 폴더의 절대 경로)
CONFIG_DIR = os.path.dirname(__file__)
CONFIG_DIR = os.path.abspath(CONFIG_DIR)

CLIENTS_FILE = os.path.join(CONFIG_DIR, "clients.json")

SERVICE_DIR = os.path.abspath(os.path.join(CONFIG_DIR, "../.."))
# 로깅 설정
logger = logging.getLogger("sandol-auth-relay-service")
logger.setLevel(logging.DEBUG)  # 모든 로그 기록

console_handler = logging.StreamHandler()
if os.getenv("DEBUG", "False").lower() == "true":
    console_handler.setLevel(logging.DEBUG)  # DEBUG 이상 출력
else:
    # DEBUG 모드가 아닐 때는 INFO 이상만 출력
    console_handler.setLevel(logging.INFO)  # INFO 이상만 출력
console_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
console_handler.setFormatter(console_formatter)


logger.addHandler(console_handler)


def _derive_from_issuer(issuer: str) -> Tuple[str | None, str | None]:
    """Helper: issuer에서 server_url과 realm을 추론한다.

    Args:
        issuer (str): Keycloak issuer URL 문자열.

    Returns:
        Tuple[str | None, str | None]: 추론된 server_url과 realm, 실패 시에는 None.
    """
    try:
        parsed = urlparse(issuer)
    except ValueError:
        return None, None

    if not parsed.scheme or not parsed.netloc:
        return None, None

    path = parsed.path.rstrip("/")
    if not path:
        return None, None

    parts = [segment for segment in path.split("/") if segment]
    try:
        idx = parts.index("realms")
    except ValueError:
        return None, None

    if idx + 1 >= len(parts):
        return None, None

    realm = parts[idx + 1]
    base_parts = parts[:idx]
    base_path = "/".join(base_parts)
    if base_path:
        base_path = f"/{base_path}/"
    else:
        base_path = "/"
    server_url = f"{parsed.scheme}://{parsed.netloc}{base_path}"
    return server_url, realm


def _secret_env_name(client_key: str) -> str:
    """Helper: client 키를 ENV 변수 키 형식으로 정규화한다.

    Args:
        client_key (str): 클라이언트 식별자 문자열.

    Returns:
        str: 표준화된 환경 변수 키.
    """
    normalized = "".join(ch if ch.isalnum() else "_" for ch in client_key.upper())
    return f"{normalized}__SECRETS"


def _inject_client_secret(client_key: str, prepared: Dict[str, Any]) -> None:
    """Helper: client_secret이 없을 때 환경 변수로부터 채워 넣는다.

    Args:
        client_key (str): 클라이언트 식별자.
        prepared (Dict[str, Any]): 전처리된 클라이언트 설정.
    """
    if prepared.get("client_secret"):
        return

    candidates = [
        _secret_env_name(client_key),
        f"{client_key}__secrets",
    ]

    for env_key in candidates:
        secret = os.getenv(env_key)
        if secret:
            prepared["client_secret"] = secret
            logger.debug("client_secret hydrated from ENV: %s", env_key)
            return

    logger.info("client_secret missing for client '%s'", client_key)


def _load_clients(base_url: str) -> Dict[str, Dict[str, Any]]:
    """Loader: clients.json을 로드해 최소 전처리를 수행한다.

    Args:
        base_url (str): BASE_URL 환경 변수 값.

    Returns:
        Dict[str, Dict[str, Any]]: 클라이언트 키와 설정 딕셔너리 매핑.
    """
    try:
        with open(CLIENTS_FILE, encoding="utf-8") as fp:
            raw = json.load(fp)
    except FileNotFoundError:
        logger.warning("clients.json not found, Config.CLIENTS set to empty dict")
        return {}
    except json.JSONDecodeError as exc:
        logger.error("clients.json parsing failed: %s", exc)
        return {}

    clients: Dict[str, Dict[str, Any]] = {}
    for client_key, cfg in raw.items():
        if not isinstance(cfg, dict):
            logger.warning(
                "clients.json entry '%s' ignored (expected object)", client_key
            )
            continue

        prepared: Dict[str, Any] = {}
        for key, value in cfg.items():
            if isinstance(value, str):
                prepared[key] = value.replace("{BASE_URL}", base_url)
            else:
                prepared[key] = value

        issuer = prepared.get("issuer")
        if issuer:
            derived_server, derived_realm = _derive_from_issuer(issuer)
            if derived_server and "server_url" not in prepared:
                prepared["server_url"] = derived_server
            if derived_realm and "realm" not in prepared:
                prepared["realm"] = derived_realm

        _inject_client_secret(client_key, prepared)

        clients[client_key] = prepared

    return clients


class Config:
    """Config: 애플리케이션 전역 설정을 제공한다.

    Attributes:
        BASE_URL (str): 외부에서 접근 가능한 relay의 기준 URL.
        JWT_SECRET (str): LIT 서명/검증에 사용하는 HS256 시크릿.
        LIT_ISSUER (str): LIT 토큰의 발급자 식별자.
        LIT_AUDIENCE (str): LIT 토큰의 대상자 식별자.
        STATE_TTL_SECONDS (int): state/nonce/code_verifier의 만료 시간(초).
        RELAY_TO_CHATBOT_HMAC_SECRET (str): relay→chatbot HMAC 서명 공유 시크릿.
        REDIRECT_ALLOWLIST (List[str]): 최종 리다이렉트 허용 도메인 또는 경로 prefix 목록.
        CLIENTS (dict[str, dict[str, Any]]): 등록된 클라이언트 설정 매핑.
    """

    BASE_URL: str = os.getenv("BASE_URL", "https://relay.example.com")
    JWT_SECRET: str = os.getenv("JWT_SECRET", "dev-secret-please-change")
    LIT_ISSUER: str = os.getenv("LIT_ISSUER", "auth-relay")
    LIT_AUDIENCE: str = os.getenv("LIT_AUDIENCE", "lit-consumer")
    STATE_TTL_SECONDS: int = int(os.getenv("STATE_TTL_SECONDS", "600"))

    RELAY_TO_CHATBOT_HMAC_SECRET: str = os.getenv(
        "RELAY_TO_CHATBOT_HMAC_SECRET", "dev-hmac-secret-please-change"
    )

    # 내부 허용 리다이렉트(prefix 매칭). 환경 변수로 설정, 기본값은 "/"만 허용.
    REDIRECT_ALLOWLIST: List[str] = [
        s.strip() for s in os.getenv("REDIRECT_ALLOWLIST", "/").split(",") if s.strip()
    ]

    CLIENTS: dict[str, dict[str, Any]] = _load_clients(BASE_URL)

    class HttpStatus:
        """Enum: HTTP 상태 코드를 정의한다.

        Attributes:
            OK (int): 200 OK.
            CREATED (int): 201 Created.
            NO_CONTENT (int): 204 No Content.
            MULTIPLE_CHOICES (int): 300 Multiple Choices.
            MOVED_PERMANENTLY (int): 301 Moved Permanently.
            FOUND (int): 302 Found.
            BAD_REQUEST (int): 400 Bad Request.
            UNAUTHORIZED (int): 401 Unauthorized.
            FORBIDDEN (int): 403 Forbidden.
            NOT_FOUND (int): 404 Not Found.
            NOT_ACCEPTABLE (int): 406 Not Acceptable.
            CONFLICT (int): 409 Conflict.
            UNSUPPORTED_MEDIA_TYPE (int): 415 Unsupported Media Type.
            INTERNAL_SERVER_ERROR (int): 500 Internal Server Error.
            NOT_IMPLEMENTED (int): 501 Not Implemented.
            BAD_GATEWAY (int): 502 Bad Gateway.
        """

        OK = 200
        CREATED = 201
        NO_CONTENT = 204
        MULTIPLE_CHOICES = 300
        MOVED_PERMANENTLY = 301
        FOUND = 302
        BAD_REQUEST = 400
        UNAUTHORIZED = 401
        FORBIDDEN = 403
        NOT_FOUND = 404
        NOT_ACCEPTABLE = 406
        CONFLICT = 409
        UNSUPPORTED_MEDIA_TYPE = 415
        INTERNAL_SERVER_ERROR = 500
        NOT_IMPLEMENTED = 501
        BAD_GATEWAY = 502
