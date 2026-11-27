import json
import secrets
import time

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.config import Config, logger
from app.routers import auth as auth_router
from app.utils import request_signing
from app.utils.clients import ClientConfig
from app.utils.request_signing import SignedRequest, sign_request
from main import app

SECRET = "test-issue-link-secret"  # noqa: S105
CLIENT_KEY = "sandol-kakao-bot"
CALLBACK = "https://sandol.sio2.kr/kakao-bot/users/callback"


def make_client_config() -> ClientConfig:
    return ClientConfig(
        key=CLIENT_KEY,
        base_url="https://relay.example.com",
        raw={
            "issuer": "https://auth.example.com/realms/Sandori",
            "client_id": CLIENT_KEY,
            "client_secret": "test-secret",
            "issue_link_secret": SECRET,
            "redirect_uri": "https://relay.example.com/oidc/callback",
            "callback_url_allowlist": [CALLBACK],
            "redirect_after_allowlist": ["/"],
        },
    )


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    cfg = make_client_config()

    def fake_resolve_client(client_key: str) -> ClientConfig:
        if client_key != cfg.key:
            raise HTTPException(400, "unknown_client_key")
        return cfg

    def fake_lookup(client_key: str) -> str:
        if client_key != cfg.key:
            raise request_signing.SignatureError("unknown_client")
        return cfg.issue_link_secret

    monkeypatch.setattr(auth_router, "resolve_client", fake_resolve_client)
    monkeypatch.setattr(request_signing, "_lookup_secret", fake_lookup)
    monkeypatch.setattr(Config, "ISSUE_LINK_AUTH_MODE", "enforce")
    return TestClient(app)


def body_bytes(client_key: str = CLIENT_KEY, user: str = "kakao-user-1") -> bytes:
    return json.dumps(
        {"chatbot_user_id": user, "callback_url": CALLBACK, "client_key": client_key}
    ).encode()


def signed_headers(  # noqa: PLR0913
    body: bytes,
    *,
    secret: str = SECRET,
    client_key: str = CLIENT_KEY,
    ts: int | None = None,
    nonce: str | None = None,
    path: str = "/issue_login_link",
) -> dict[str, str]:
    ts_s = str(int(time.time()) if ts is None else ts)
    nonce = nonce or secrets.token_urlsafe(16)
    sig = sign_request(
        secret, SignedRequest("POST", path, ts_s, nonce, client_key, body)
    )
    return {
        "Content-Type": "application/json",
        "X-Relay-Client-Key": client_key,
        "X-Relay-Timestamp": ts_s,
        "X-Relay-Nonce": nonce,
        "X-Relay-Request-Signature": sig,
    }


def post(
    client: TestClient,
    body: bytes,
    headers: dict[str, str],
    url: str = "/issue_login_link",
):
    return client.post(url, content=body, headers=headers)


def test_valid_signature_issues_link(client: TestClient) -> None:
    body = body_bytes()
    res = post(client, body, signed_headers(body))
    assert res.status_code == 200
    assert res.json()["login_link"].startswith(f"{Config.BASE_URL}/login/")


def test_valid_signature_with_root_path_prefix(client: TestClient) -> None:
    # 게이트웨이/직접 호출은 /relay/issue_login_link로 들어오지만 서명 경로는 같다.
    body = body_bytes()
    res = post(client, body, signed_headers(body), url="/relay/issue_login_link")
    assert res.status_code == 200


def test_missing_signature_rejected(client: TestClient) -> None:
    res = post(client, body_bytes(), {"Content-Type": "application/json"})
    assert res.status_code == 401
    assert res.json() == {"detail": "unauthorized"}


def test_forged_signature_rejected(client: TestClient) -> None:
    body = body_bytes()
    res = post(client, body, signed_headers(body, secret="wrong-secret"))  # noqa: S106
    assert res.status_code == 401


def test_expired_timestamp_rejected(client: TestClient) -> None:
    body = body_bytes()
    old = int(time.time()) - Config.ISSUE_LINK_AUTH_SKEW_SECONDS - 5
    res = post(client, body, signed_headers(body, ts=old))
    assert res.status_code == 401


def test_nonce_reuse_rejected(client: TestClient) -> None:
    body = body_bytes()
    headers = signed_headers(body)
    assert post(client, body, headers).status_code == 200
    assert post(client, body, headers).status_code == 401


def test_tampered_body_rejected(client: TestClient) -> None:
    headers = signed_headers(body_bytes(user="kakao-user-1"))
    res = post(client, body_bytes(user="attacker"), headers)
    assert res.status_code == 401


def test_wrong_path_rejected(client: TestClient) -> None:
    body = body_bytes()
    res = post(client, body, signed_headers(body, path="/other"))
    assert res.status_code == 401


def test_client_key_mismatch_rejected(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 다른 client의 비밀로 서명하고 본문에는 sandol-kakao-bot을 적는 경우
    monkeypatch.setattr(request_signing, "_lookup_secret", lambda _key: SECRET)
    body = body_bytes(client_key=CLIENT_KEY)
    res = post(client, body, signed_headers(body, client_key="discord-bot"))
    assert res.status_code == 401


def test_unknown_client_rejected(client: TestClient) -> None:
    body = body_bytes(client_key="ghost")
    res = post(client, body, signed_headers(body, client_key="ghost"))
    assert res.status_code == 401


def test_warn_mode_allows_unsigned(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(Config, "ISSUE_LINK_AUTH_MODE", "warn")
    logger.addHandler(caplog.handler)
    try:
        res = post(client, body_bytes(), {"Content-Type": "application/json"})
    finally:
        logger.removeHandler(caplog.handler)
    assert res.status_code == 200
    assert "reason=missing_headers" in caplog.text


def test_warn_mode_allows_forged_but_valid_passes(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Config, "ISSUE_LINK_AUTH_MODE", "warn")
    body = body_bytes()
    assert post(client, body, signed_headers(body, secret="x")).status_code == 200  # noqa: S106
    assert post(client, body, signed_headers(body)).status_code == 200


def test_off_mode_skips_verification(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Config, "ISSUE_LINK_AUTH_MODE", "off")
    res = post(client, body_bytes(), {"Content-Type": "application/json"})
    assert res.status_code == 200


def test_canonical_request_format() -> None:
    canonical = request_signing.canonical_request(
        SignedRequest(
            "post", "/issue_login_link", "1700000000", "n" * 16, CLIENT_KEY, b"{}"
        )
    )
    assert canonical.split("\n") == [
        "SANDOL-RELAY-HMAC-V1",
        "POST",
        "/issue_login_link",
        "1700000000",
        "n" * 16,
        CLIENT_KEY,
        "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
    ]
