from pydantic import BaseModel, AnyHttpUrl

class IssueLinkReq(BaseModel):
    chatbot_user_id: str
    callback_url: AnyHttpUrl
    redirect_after: str | None = None  # sandol:// 등

class IssueLinkRes(BaseModel):
    login_link: AnyHttpUrl
    expires_in: int
