"""회원 탈퇴 정보 수신 라우터입니다."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import JSONResponse

from app.config import logger
from app.utils.account_deletion import (
    decrypt_payload,
    load_key,
    parse_envelope,
    save_deletion,
)

router = APIRouter(tags=["internal"])


@router.post("/internal/account-deletions")
async def receive_account_deletion(request: Request) -> JSONResponse:
    """Keycloak이 보낸 탈퇴 정보를 검증해 저장하고 202로 응답한다."""
    # 게이트웨이는 항상 이 헤더를 붙이므로, 있으면 외부 요청으로 보고 없는 주소처럼 응답한다
    if "x-forwarded-for" in request.headers or "x-real-ip" in request.headers:
        logger.warning("account_deletion: blocked request through gateway")
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")

    key = load_key()
    envelope = parse_envelope(await request.body())
    payload = decrypt_payload(key, envelope)
    event_id = payload["event_id"]

    try:
        created = save_deletion(envelope, payload)
    except Exception as e:
        logger.exception("account_deletion: store failed (event_id=%s)", event_id)
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR, "storage_failed"
        ) from e

    logger.info(
        "account_deletion: accepted (event_id=%s, realm=%s, user_id=%s, created=%s)",
        event_id,
        payload["realm"],
        payload["user_id"],
        created,
    )
    return JSONResponse({"event_id": event_id}, status_code=status.HTTP_202_ACCEPTED)
