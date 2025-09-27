from __future__ import annotations
from pydantic import BaseModel, HttpUrl
from typing import Optional

class IssueLinkReq(BaseModel):
    """로그인 링크 발급 요청 스키마.

    Args:
        chatbot_user_id: 챗봇 내부 사용자 ID.
        callback_url: 챗봇 서버 콜백 URL(서버 간 POST 수신).
        client_key: relay에 등록된 클라이언트 키.
        redirect_after: 로그인 완료 후 사용자 브라우저 최종 리다이렉트 목적지.
    """
    chatbot_user_id: str
    callback_url: HttpUrl
    client_key: str
    redirect_after: Optional[str] = None


class IssueLinkRes(BaseModel):
    """로그인 링크 발급 응답 스키마.

    Args:
        login_link: 사용자 브라우저가 열어야 할 로그인 시작 URL.
        expires_in: 링크 만료까지 남은 시간(초).
    """
    login_link: str
    expires_in: int
