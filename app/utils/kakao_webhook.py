from __future__ import annotations

from urllib.parse import parse_qs

from fastapi import Request

from app.config import Config, logger
from app.utils.storage import sess_delete_by_chatbot_user_id

MASK_MIN_LENGTH = 8


def mask_token(value: str | None) -> str:
    if not value:
        return "none"
    if len(value) <= MASK_MIN_LENGTH:
        return "****"
    return f"{value[:4]}...{value[-4:]}"


def mask_user_id(user_id: str | None) -> str:
    if not user_id:
        return "none"
    if len(user_id) <= MASK_MIN_LENGTH:
        return "****"
    return f"{user_id[:2]}***{user_id[-2:]}"


def extract_admin_key(authorization: str | None) -> str | None:
    if not authorization:
        return None

    prefix = "KakaoAK "
    if not authorization.startswith(prefix):
        return None

    admin_key = authorization[len(prefix) :].strip()
    return admin_key or None


def is_valid_primary_admin_key(admin_key: str | None) -> bool:
    primary_admin_key = Config.KAKAO_WEBHOOK_PRIMARY_ADMIN_KEY
    if not primary_admin_key:
        logger.error(
            "kakao_unlink_webhook: missing KAKAO_WEBHOOK_PRIMARY_ADMIN_KEY configuration"
        )
        return False

    if admin_key != primary_admin_key:
        return False

    allowed_admin_keys = set(Config.KAKAO_WEBHOOK_ALLOWED_ADMIN_KEYS)
    if allowed_admin_keys and admin_key not in allowed_admin_keys:
        return False

    return True


async def parse_webhook_payload(request: Request) -> dict[str, str]:
    payload = dict(request.query_params)
    if request.method == "GET":
        return payload

    content_type = request.headers.get("Content-Type", "")
    if "application/x-www-form-urlencoded" in content_type:
        form_body = (await request.body()).decode("utf-8")
        parsed_form = parse_qs(form_body, keep_blank_values=True)
        payload.update({key: values[-1] for key, values in parsed_form.items()})

    return payload


def process_kakao_unlink_event(
    app_id: str,
    user_id: str,
    referrer_type: str,
    group_user_token: str | None,
) -> None:
    #TODO: unlink 이벤트 처리 실제 로직 구현(Keycloak 연결 해제)
    deleted_session_count = sess_delete_by_chatbot_user_id(user_id)
    masked_user_id = mask_user_id(user_id)
    logger.info(
        "kakao_unlink_webhook: unlink processed (app_id=%s, user_id=%s, referrer_type=%s, group_user_token=%s, deleted_sessions=%s)",
        app_id,
        masked_user_id,
        referrer_type,
        group_user_token,
        deleted_session_count,
    )
