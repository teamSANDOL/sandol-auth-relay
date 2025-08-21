from urllib.parse import urlencode
import time, secrets

import httpx
import jwt
from fastapi import APIRouter, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse

from app.config.config import Config
from app.schemas import IssueLinkReq, IssueLinkRes
from app.utils import (
    OIDC_AUTH, OIDC_TOKEN, make_lit, pkce_challenge,
    get_jwk_by_kid, now_ts, SESS, redirect_allowed
)

router = APIRouter(tags=["auth-relay"])

@router.post("/issue_login_link", response_model=IssueLinkRes)
async def issue_login_link(body: IssueLinkReq):
    if body.redirect_after and not redirect_allowed(body.redirect_after):
        raise HTTPException(400, "redirect_after_not_allowed")

    lit = make_lit(body.chatbot_user_id, str(body.callback_url), body.redirect_after)
    login_link = f"{Config.BASE_URL}/login/{lit}"
    return IssueLinkRes(login_link=login_link, expires_in=Config.LIT_TTL_SECONDS)

@router.get("/login/{lit}")
async def login_init(lit: str):
    # LIT 검증
    try:
        data = jwt.decode(
            lit,
            Config.JWT_SECRET,
            algorithms=["HS256"],
            audience="login",
            issuer="auth-relay",
        )
    except jwt.PyJWTError:
        raise HTTPException(400, "invalid_or_expired_link")

    chatbot_user_id = data["chatbot_user_id"]
    callback_url    = data["callback_url"]
    redirect_after  = data.get("redirect_after")

    # state/nonce/PKCE 준비 및 저장
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    code_verifier  = secrets.token_urlsafe(64)
    code_challenge = pkce_challenge(code_verifier)

    SESS[state] = {
        "nonce": nonce,
        "code_verifier": code_verifier,
        "chatbot_user_id": chatbot_user_id,
        "callback_url": callback_url,
        "redirect_after": redirect_after,
        "ts": now_ts(),
    }

    # Keycloak로 리다이렉트
    redirect_uri = f"{Config.BASE_URL}/oidc/callback"
    params = {
        "client_id": Config.KC_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid profile email",
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return RedirectResponse(f"{OIDC_AUTH}?{urlencode(params)}", status_code=302)

@router.get("/oidc/callback")
async def oidc_callback(code: str, state: str):
    sess = SESS.pop(state, None)
    if not sess or (now_ts() - sess["ts"] > Config.STATE_TTL_SECONDS):
        raise HTTPException(400, "invalid_or_expired_state")

    redirect_uri = f"{Config.BASE_URL}/oidc/callback"
    form = {
        "grant_type": "authorization_code",
        "client_id": Config.KC_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "code": code,
        "code_verifier": sess["code_verifier"],
    }
    if Config.KC_CLIENT_SECRET:
        form["client_secret"] = Config.KC_CLIENT_SECRET

    # 코드→토큰 교환
    async with httpx.AsyncClient(timeout=10.0) as cx:
        tok = await cx.post(OIDC_TOKEN, data=form)
    if tok.status_code != 200:
        raise HTTPException(502, "token_exchange_failed")

    tokens = tok.json()
    id_token = tokens.get("id_token")
    if not id_token:
        raise HTTPException(502, "no_id_token")

    # ID 토큰 검증(서명 + nonce)
    kid = jwt.get_unverified_header(id_token).get("kid")
    key = await get_jwk_by_kid(kid)
    try:
        claims = jwt.decode(id_token, key=key, algorithms=["RS256"], audience=Config.KC_CLIENT_ID)
    except jwt.PyJWTError:
        raise HTTPException(400, "invalid_id_token")
    if claims.get("nonce") != sess["nonce"]:
        raise HTTPException(400, "nonce_mismatch")

    keycloak_sub = claims.get("sub")
    if not keycloak_sub:
        raise HTTPException(400, "missing_sub")

    # 챗봇 콜백(내부망 전제: http, 서명/HMAC/HTTPS 없음)
    payload = {
        "chatbot_user_id": sess["chatbot_user_id"],
        "keycloak_user_id": keycloak_sub,
        "status": "success",
        "access_token": tokens.get("access_token"),
        "refresh_token": tokens.get("refresh_token"),
        "expires_at": int(time.time()) + int(tokens.get("expires_in", 0)),
    }

    try:
        async with httpx.AsyncClient(timeout=8.0) as cx:
            r = await cx.post(sess["callback_url"], json=payload)
            r.raise_for_status()
    except Exception:
        return JSONResponse({"error": "callback_failed"}, status_code=502)

    # 사용자 최종 리다이렉트
    dest = sess.get("redirect_after")
    if not redirect_allowed(dest):
        dest = Config.DEFAULT_REDIRECT_AFTER
    if not dest:
        dest = Config.DEFAULT_REDIRECT_AFTER
    return RedirectResponse(dest, status_code=302)
