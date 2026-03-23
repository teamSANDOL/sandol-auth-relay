from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Request, Response

from app.config import Config, logger
from app.utils.kakao_webhook import (
    extract_admin_key,
    is_valid_primary_admin_key,
    mask_token,
    mask_user_id,
    parse_webhook_payload,
    process_kakao_unlink_event,
)

router = APIRouter(tags=["webhook"])


@router.api_route("/webhooks/kakao/unlink", methods=["GET", "POST"])
async def kakao_unlink_webhook(request: Request, background_tasks: BackgroundTasks):
    try:
        authorization = request.headers.get("Authorization")
        admin_key = extract_admin_key(authorization)

        if not is_valid_primary_admin_key(admin_key):
            logger.warning(
                "kakao_unlink_webhook: invalid admin key (token=%s)",
                mask_token(admin_key),
            )
            return Response(status_code=Config.HttpStatus.OK)

        payload = await parse_webhook_payload(request)

        app_id = payload.get("app_id")
        user_id = payload.get("user_id")
        referrer_type = payload.get("referrer_type")
        group_user_token = payload.get("group_user_token")
        masked_user_id = mask_user_id(user_id)

        if not app_id or not user_id or not referrer_type:
            logger.warning(
                "kakao_unlink_webhook: missing required payload fields (payload_keys=%s)",
                sorted(payload.keys()),
            )
            return Response(status_code=Config.HttpStatus.OK)

        if Config.KAKAO_BOT_APP_ID and app_id != Config.KAKAO_BOT_APP_ID:
            logger.warning(
                "kakao_unlink_webhook: app_id mismatch (received=%s, expected=%s)",
                app_id,
                Config.KAKAO_BOT_APP_ID,
            )
            return Response(status_code=Config.HttpStatus.OK)

        logger.info(
            "kakao_unlink_webhook: event accepted (app_id=%s, user_id=%s, referrer_type=%s)",
            app_id,
            masked_user_id,
            referrer_type,
        )
        background_tasks.add_task(
            process_kakao_unlink_event,
            app_id,
            user_id,
            referrer_type,
            group_user_token,
        )
    except Exception:
        logger.exception(
            "kakao_unlink_webhook: unexpected error while handling webhook"
        )

    return Response(status_code=Config.HttpStatus.OK)
