from fastapi import HTTPException
from fastapi.testclient import TestClient
import pytest

from app.config import Config
from app.routers import auth as auth_router
from app.utils.clients import ClientConfig
from app.utils.oidc_helpers import decode_lit
from main import app


def make_client_config() -> ClientConfig:
    return ClientConfig(
        key="sandol-kakao-bot",
        base_url="https://relay.example.com",
        raw={
            "issuer": "https://auth.example.com/realms/Sandori",
            "client_id": "sandol-kakao-bot",
            "client_secret": "test-secret",
            "redirect_uri": "https://relay.example.com/oidc/callback",
            "callback_url_allowlist": [
                "https://sandol.sio2.kr/kakao-bot/users/callback",
            ],
            "redirect_after_allowlist": ["/", "/login"],
        },
    )


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    cfg = make_client_config()

    def fake_resolve_client(client_key: str) -> ClientConfig:
        if client_key != cfg.key:
            raise HTTPException(400, "unknown_client_key")
        return cfg

    monkeypatch.setattr(auth_router, "resolve_client", fake_resolve_client)
    return TestClient(app)


def test_issue_login_link_returns_lit_for_allowed_callback_url(
    client: TestClient,
) -> None:
    response = client.post(
        "/issue_login_link",
        json={
            "chatbot_user_id": "kakao-user-1",
            "callback_url": "https://sandol.sio2.kr/kakao-bot/users/callback",
            "client_key": "sandol-kakao-bot",
            "redirect_after": "/login/success",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["expires_in"] == Config.STATE_TTL_SECONDS
    assert body["login_link"].startswith(f"{Config.BASE_URL}/login/")

    lit = body["login_link"].rsplit("/", maxsplit=1)[-1]
    decoded = decode_lit(lit)
    assert decoded["chatbot_user_id"] == "kakao-user-1"
    assert decoded["callback_url"] == "https://sandol.sio2.kr/kakao-bot/users/callback"
    assert decoded["client_key"] == "sandol-kakao-bot"
    assert decoded["redirect_after"] == "/login/success"


def test_issue_login_link_rejects_callback_url_outside_allowlist(
    client: TestClient,
) -> None:
    response = client.post(
        "/issue_login_link",
        json={
            "chatbot_user_id": "kakao-user-1",
            "callback_url": "https://evil.example/callback",
            "client_key": "sandol-kakao-bot",
            "redirect_after": "/login/success",
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "callback_url_not_allowed"


def test_issue_login_link_rejects_redirect_after_outside_allowlist(
    client: TestClient,
) -> None:
    response = client.post(
        "/issue_login_link",
        json={
            "chatbot_user_id": "kakao-user-1",
            "callback_url": "https://sandol.sio2.kr/kakao-bot/users/callback",
            "client_key": "sandol-kakao-bot",
            "redirect_after": "https://evil.example/steal",
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "redirect_after_not_allowed"


def test_issue_login_link_rejects_unknown_client_key(client: TestClient) -> None:
    response = client.post(
        "/issue_login_link",
        json={
            "chatbot_user_id": "kakao-user-1",
            "callback_url": "https://sandol.sio2.kr/kakao-bot/users/callback",
            "client_key": "unknown-client",
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "unknown_client_key"
