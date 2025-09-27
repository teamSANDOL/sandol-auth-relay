"""FastAPI 앱의 설정을 정의하는 모듈입니다."""

from __future__ import annotations
import os
import logging
from typing import Any, List

# 현재 파일이 위치한 디렉터리 (config 폴더의 절대 경로)
CONFIG_DIR = os.path.dirname(__file__)
CONFIG_DIR = os.path.abspath(CONFIG_DIR)

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

class Config:
    """애플리케이션 전역 설정.

    Attributes:
        BASE_URL: 공개 접근 가능한 relay의 베이스 URL.
        JWT_SECRET: LIT 서명/검증용 내부 공유 시크릿(HS256).
        LIT_ISSUER: LIT 발급자(내부 식별자).
        LIT_AUDIENCE: LIT 대상자(내부 식별자).
        STATE_TTL_SECONDS: state/nonce/code_verifier의 유효 시간(초).
        RELAY_TO_CHATBOT_HMAC_SECRET: relay→chatbot 서명용 공유 시크릿.
        REDIRECT_ALLOWLIST: 최종 리다이렉트 허용 도메인 혹은 경로 prefix.
        CLIENTS: client_key → Keycloak 클라이언트 설정 맵.
    """

    BASE_URL: str = os.getenv("BASE_URL", "https://relay.example.com")
    JWT_SECRET: str = os.getenv("JWT_SECRET", "dev-secret-please-change")
    LIT_ISSUER: str = os.getenv("LIT_ISSUER", "auth-relay")
    LIT_AUDIENCE: str = os.getenv("LIT_AUDIENCE", "lit-consumer")
    STATE_TTL_SECONDS: int = int(os.getenv("STATE_TTL_SECONDS", "600"))

    RELAY_TO_CHATBOT_HMAC_SECRET: str = os.getenv(
        "RELAY_TO_CHATBOT_HMAC_SECRET", "dev-hmac-secret-please-change"
    )

    # 내부 허용 리다이렉트(prefix 매칭). 필요에 맞게 구체화.
    REDIRECT_ALLOWLIST: List[str] = [
        "/",
        "https://app.example.com",
        "https://chat.example.com",
    ]

    # 예시: client_key → 클라이언트 설정
    CLIENTS: dict[str, dict[str, Any]] = {
        "kakao-bot": {
            "server_url": "https://sandol.house.sio2.kr/auth/",
            "realm": "sandori",
            "client_id": "sandol-kakao-bot",
            "client_secret": "REDACTED",  # relay가 code 교환에 secret 쓰는 경우
            "scope": "openid profile email",
            "redirect_uri": f"{BASE_URL}/oidc/callback",  # 반드시 Keycloak에 등록
            "issuer": "https://auth.sio2.kr/realms/sandol",
            "authorization_endpoint": "https://auth.sio2.kr/realms/sandol/protocol/openid-connect/auth",
        },
        "discord-bot": {
            "client_id": "sandol-discord-bot",
            "issuer": "https://auth.sio2.kr/realms/sandol",
            "redirect_uri": "https://relay.sio2.kr/oidc/callback",
            "scope": "openid",
            "client_secret": "xxxxxx",
            "aud_override": None,
        },
    }

    class HttpStatus:
        """HTTP 상태 코드를 정의하는 클래스"""

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
