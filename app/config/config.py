"""FastAPI 앱의 설정을 정의하는 모듈입니다."""

import os
import logging

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
    """FastAPI 설정 값을 관리하는 클래스"""
    KC_BASE: str = os.getenv("KC_BASE", "https://sandol.sio2.kr/auth").rstrip("/")

    BASE_URL: str = "https://sandol.sio2.kr/auth-relay"
    JWT_SECRET: str = os.getenv("CHANGE_ME_32B_RANDOM")

    DEBUG = os.getenv("DEBUG", "False").lower() == "true"

    LIT_TTL_SECONDS: int = 300
    STATE_TTL_SECONDS: int = 300

    # redirect_after 허용 접두어(화이트리스트)
    REDIRECT_AFTER_ALLOWLIST: list[str] = ["sandol://", "https://sandol.sio2.kr/"]
    DEFAULT_REDIRECT_AFTER: str = "sandol://auth/success"

    class HttpStatus:
        """HTTP 상태 코드를 정의하는 클래스"""

        OK = 200
        CREATED = 201
        NO_CONTENT = 204
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
