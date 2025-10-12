from __future__ import annotations
import secrets
import time

import httpx
from fastapi import APIRouter, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse

from app.config import Config
from app.schemas import IssueLinkReq, IssueLinkRes
from app.utils import (
    gen_code_verifier,
    code_challenge_s256,
    make_lit,
    decode_lit,
    resolve_client,
    redirect_allowed,
    build_authorize_url,
    now_ts,
)
from app.utils.storage import sess_set, sess_pop, sess_expired
from app.utils.kc_client import kc_client, kc_well_known
from app.utils.security import sign_payload

router = APIRouter(tags=["auth-relay"])


@router.post("/issue_login_link", response_model=IssueLinkRes)
async def issue_login_link(body: IssueLinkReq) -> IssueLinkRes:
    """로그인 링크(LIT)를 발급한다.

    Args:
        body (IssueLinkReq): 로그인 링크 발급 요청 본문.

    Returns:
        IssueLinkRes: 생성된 로그인 링크와 만료 시간 정보.

    Raises:
        HTTPException: redirect_after가 허용되지 않는 경우.

    HTTP Response:
        200 OK: 로그인 링크 발급 성공 응답을 반환한다.
    """
    if body.redirect_after and not redirect_allowed(body.redirect_after):
        raise HTTPException(Config.HttpStatus.BAD_REQUEST, "redirect_after_not_allowed")

    cfg = resolve_client(body.client_key)
    lit = make_lit(
        chatbot_user_id=body.chatbot_user_id,
        callback_url=str(body.callback_url),
        client_key=body.client_key,
        redirect_after=body.redirect_after,
    )
    login_link = f"{Config.BASE_URL}/login/{lit}"
    return IssueLinkRes(login_link=login_link, expires_in=Config.STATE_TTL_SECONDS)


@router.get("/login/{lit}")
async def login_init(lit: str):
    """인가 플로우를 시작해 인가 URL로 리다이렉트한다.

    Args:
        lit (str): 로그인 링크 토큰(LIT) 값.

    Returns:
        RedirectResponse: Keycloak 인가 URL로 리다이렉트한다.

    Raises:
        HTTPException: LIT에 필수 클레임이 없거나 유효하지 않을 때.

    HTTP Response:
        302 Found: Keycloak 인가 URL로 리다이렉트한다.
    """
    data = decode_lit(lit)
    client_key = data.get("client_key")
    chatbot_user_id = data.get("chatbot_user_id")
    callback_url = data.get("callback_url")
    redirect_after = data.get("redirect_after")
    if not (client_key and chatbot_user_id and callback_url):
        raise HTTPException(Config.HttpStatus.BAD_REQUEST, "missing_required_claims")

    cfg = resolve_client(client_key)
    kc = kc_client(cfg)
    wk = kc_well_known(kc)

    # state/nonce/PKCE
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    code_verifier = gen_code_verifier()
    code_challenge = code_challenge_s256(code_verifier)

    authorize_url = build_authorize_url(
        auth_endpoint=wk["authorization_endpoint"],
        cfg=cfg,
        state=state,
        nonce=nonce,
        code_challenge=code_challenge,
    )

    # 세션 저장(메모리)
    sess_set(
        state,
        {
            "nonce": nonce,
            "code_verifier": code_verifier,
            "client_key": client_key,
            "chatbot_user_id": chatbot_user_id,
            "callback_url": callback_url,
            "redirect_after": redirect_after,
            "ts": now_ts(),
        },
    )
    return RedirectResponse(authorize_url, status_code=Config.HttpStatus.FOUND)


@router.get("/oidc/callback")
async def oidc_callback(code: str, state: str):
    """Keycloak 콜백을 처리해 토큰 교환과 최종 리다이렉트를 수행한다.

    Args:
        code (str): Authorization Code.
        state (str): CSRF 방지 state 값.

    Returns:
        RedirectResponse | JSONResponse: 성공 시 최종 리다이렉트, 실패 시 에러 JSON.

    Raises:
        HTTPException: state가 유효하지 않거나 토큰 교환이 실패할 때.

    HTTP Response:
        302 Found: redirect_after 또는 기본 경로로 리다이렉트한다.
        502 Bad Gateway: 챗봇 서버 콜백 실패 시 JSON 에러를 반환한다.
    """
    sess = sess_pop(state)
    if not sess or sess_expired(sess["ts"]):
        raise HTTPException(400, "invalid_or_expired_state")

    cfg = resolve_client(sess["client_key"])
    kc = kc_client(cfg)

    # code → token (PKCE)
    try:
        token = kc.token(
            grant_type="authorization_code",
            code=code,
            redirect_uri=cfg["redirect_uri"],
            scope=cfg.get("scope", "openid"),
            code_verifier=sess["code_verifier"],
        )
    except Exception as e:
        raise HTTPException(
            Config.HttpStatus.BAD_GATEWAY, "token_exchange_failed"
        ) from e

    if "access_token" not in token:
        raise HTTPException(Config.HttpStatus.BAD_GATEWAY, "no_access_token")

    # 챗봇 서버 콜백(Access Token 전달; 챗봇은 TE 수행)
    payload = {
        "relay_access_token": token["access_token"],
        "issuer": cfg["issuer"],
        "aud": cfg["client_id"],
        "chatbot_user_id": sess["chatbot_user_id"],
        "client_key": sess["client_key"],
        "ts": int(time.time()),
        "nonce": secrets.token_urlsafe(16),
    }
    headers = {"X-Relay-Signature": sign_payload(payload)}

    try:
        async with httpx.AsyncClient(timeout=8.0) as http_client:
            response = await http_client.post(
                sess["callback_url"],
                json=payload,
                headers=headers,
            )
            response.raise_for_status()
    except httpx.TimeoutException:
        return JSONResponse({"error": "callback_timeout"}, status_code=502)
    except httpx.HTTPStatusError:
        return JSONResponse({"error": "callback_invalid_status"}, status_code=502)
    except httpx.RequestError:
        return JSONResponse({"error": "callback_request_error"}, status_code=502)

    # 최종 리다이렉트
    dest = sess.get("redirect_after") or "/"
    if not redirect_allowed(dest):
        dest = "/"
    return RedirectResponse(dest, status_code=Config.HttpStatus.FOUND)
