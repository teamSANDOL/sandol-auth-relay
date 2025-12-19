"""Config: FastAPI 앱의 설정을 정의하는 모듈입니다."""

from __future__ import annotations
import os
import logging
from typing import List

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

if not logger.handlers:
    logger.addHandler(console_handler)


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
    """

    CLIENTS_FILE = os.path.join(CONFIG_DIR, "clients.json")
    BASE_URL: str = os.getenv("BASE_URL", "https://relay.example.com")
    JWT_SECRET: str = os.getenv("JWT_SECRET", "dev-secret-please-change")
    LIT_ISSUER: str = os.getenv("LIT_ISSUER", "auth-relay")
    LIT_AUDIENCE: str = os.getenv("LIT_AUDIENCE", "lit-consumer")
    STATE_TTL_SECONDS: int = int(os.getenv("STATE_TTL_SECONDS", "600"))

    CHATBOT_CALLBACK_TIMEOUT_SECONDS: float = float(
        os.getenv("CHATBOT_CALLBACK_TIMEOUT_SECONDS", "8.0")
    )

    RELAY_TO_CHATBOT_HMAC_SECRET: str = os.getenv(
        "RELAY_TO_CHATBOT_HMAC_SECRET", "dev-hmac-secret-please-change"
    )

    # 내부 허용 리다이렉트(prefix 매칭). 환경 변수로 설정, 기본값은 "/"만 허용.
    REDIRECT_ALLOWLIST: List[str] = [
        s.strip() for s in os.getenv("REDIRECT_ALLOWLIST", "/").split(",") if s.strip()
    ]

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
