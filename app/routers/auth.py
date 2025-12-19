from __future__ import annotations
import secrets
import time

import httpx
from fastapi import APIRouter, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse

from app.config import Config, logger
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
from app.utils.kc_client import kc_well_known
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
    logger.info(
        "issue_login_link: client_key=%s redirect_after=%s",
        body.client_key,
        body.redirect_after,
    )
    if body.redirect_after and not redirect_allowed(body.redirect_after):
        logger.warning(
            "issue_login_link: redirect_after not allowed (client_key=%s, redirect_after=%s)",
            body.client_key,
            body.redirect_after,
        )
        raise HTTPException(Config.HttpStatus.BAD_REQUEST, "redirect_after_not_allowed")

    resolve_client(body.client_key)
    lit = make_lit(
        chatbot_user_id=body.chatbot_user_id,
        callback_url=str(body.callback_url),
        client_key=body.client_key,
        redirect_after=body.redirect_after,
    )
    login_link = f"{Config.BASE_URL}/login/{lit}"
    logger.info(
        "issue_login_link: LIT issued (client_key=%s, expires_in=%s)",
        body.client_key,
        Config.STATE_TTL_SECONDS,
    )
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
    logger.info("login_init: request received")
    data = decode_lit(lit)
    client_key = data.get("client_key")
    chatbot_user_id = data.get("chatbot_user_id")
    callback_url = data.get("callback_url")
    redirect_after = data.get("redirect_after")
    if not (client_key and chatbot_user_id and callback_url):
        logger.warning("login_init: missing required claims")
        raise HTTPException(Config.HttpStatus.BAD_REQUEST, "missing_required_claims")

    cfg = resolve_client(client_key)
    kc = cfg.build_kc()
    wk = kc_well_known(kc)
    logger.debug(
        "login_init: discovered authorization_endpoint for client_key=%s",
        client_key,
    )

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
    logger.info(
        "login_init: redirecting to authorization endpoint (client_key=%s)",
        client_key,
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
    logger.info("oidc_callback: received (state redacted)")
    sess = sess_pop(state)
    if not sess or sess_expired(sess["ts"]):
        logger.warning("oidc_callback: invalid or expired state")
        raise HTTPException(400, "invalid_or_expired_state")

    cfg = resolve_client(sess["client_key"])
    kc = cfg.build_kc()

    # code → token (PKCE)
    try:
        token = kc.token(
            grant_type="authorization_code",
            code=code,
            redirect_uri=cfg.redirect_uri,
            scope="openid offiline_access",
            code_verifier=sess["code_verifier"],
        )
        logger.info("oidc_callback token: %s", token)
    except Exception as e:
        logger.exception(
            "oidc_callback: token exchange failed (client_key=%s)",
            sess["client_key"],
        )
        raise HTTPException(
            Config.HttpStatus.BAD_GATEWAY, "token_exchange_failed"
        ) from e

    if "access_token" not in token:
        logger.error(
            "oidc_callback: no access_token in token response (client_key=%s)",
            sess["client_key"],
        )
        raise HTTPException(Config.HttpStatus.BAD_GATEWAY, "no_access_token")
    if "refresh_token" not in token:
        logger.error(
            "oidc_callback: no refresh_token (offline) in token response (client_key=%s)",
            sess["client_key"],
        )
        raise HTTPException(Config.HttpStatus.BAD_GATEWAY, "no_offline_refresh_token")

    # 2) 챗봇 서버 콜백으로 '오프라인 토큰' 전달  🔒
    #    - 기존: relay_access_token만 전달 + 챗봇이 TE 수행  ❌ (offline 불가)
    #    - 변경: 챗봇이 자신의 refresh flow로 AT 갱신  ✅
    payload = {
        "issuer": cfg.issuer,
        "aud": cfg.client_id,  # 이 토큰의 클라이언트 (챗봇)
        "chatbot_user_id": sess["chatbot_user_id"],
        "client_key": sess["client_key"],
        "relay_access_token": token["access_token"],  # 즉시 사용 가능
        "offline_refresh_token": token["refresh_token"],  # ← 핵심: 챗봇 보관/갱신용
        "expires_in": token.get("expires_in"),
        "refresh_expires_in": token.get("refresh_expires_in"),
        "ts": int(time.time()),
        "nonce": secrets.token_urlsafe(16),
    }
    headers = {"X-Relay-Signature": sign_payload(payload)}

    try:
        logger.info(
            "oidc_callback: posting tokens to chatbot callback (client_key=%s, callback_url=%s)",
            sess["client_key"],
            sess["callback_url"],
        )
        logger.debug(
            "oidc_callback: payload=%s",
            payload,
        )
        async with httpx.AsyncClient(
            timeout=Config.CHATBOT_CALLBACK_TIMEOUT_SECONDS
        ) as http_client:
            response = await http_client.post(
                sess["callback_url"], json=payload, headers=headers
            )
            response.raise_for_status()
    except httpx.TimeoutException:
        logger.error(
            "oidc_callback: callback timeout (client_key=%s, callback_url=%s)",
            sess["client_key"],
            sess["callback_url"],
        )
        return JSONResponse({"error": "callback_timeout"}, status_code=502)
    except httpx.HTTPStatusError:
        logger.error(
            "oidc_callback: callback invalid status (client_key=%s, callback_url=%s)",
            sess["client_key"],
            sess["callback_url"],
        )
        return JSONResponse({"error": "callback_invalid_status"}, status_code=502)
    except httpx.RequestError:
        logger.error(
            "oidc_callback: callback request error (status=%s, client_key=%s, callback_url=%s)",
            response.status_code,
            sess["client_key"],
            sess["callback_url"],
        )
        logger.error(
            "oidc_callback: exception details: %s",
            response.text,
        )
        return JSONResponse({"error": "callback_request_error"}, status_code=502)

    dest = sess.get("redirect_after") or "/"
    if not redirect_allowed(dest):
        dest = "/"
    logger.info("oidc_callback: redirecting user to %s", dest)
    return RedirectResponse(dest, status_code=Config.HttpStatus.FOUND)
