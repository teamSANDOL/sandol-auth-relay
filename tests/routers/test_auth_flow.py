from urllib.parse import parse_qs, urlparse

from fastapi import HTTPException
from fastapi.testclient import TestClient
import httpx
import pytest

from app.routers import auth as auth_router
from app.utils.clients import ClientConfig
from app.utils.oidc_helpers import decode_lit
from app.utils.security import sign_payload
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


class FakeKeycloakClient:
    def __init__(self, token_response: dict[str, object] | None = None) -> None:
        self.token_response = token_response or {}
        self.token_calls: list[dict[str, object]] = []

    def token(self, **kwargs: object) -> dict[str, object]:
        self.token_calls.append(kwargs)
        if isinstance(self.token_response, Exception):
            raise self.token_response
        return self.token_response


class FakeResponse:
    def __init__(
        self,
        url: str,
        *,
        status_code: int = 200,
        should_raise_status: bool = False,
    ) -> None:
        self.url = url
        self.status_code = status_code
        self.should_raise_status = should_raise_status

    def raise_for_status(self) -> None:
        if not self.should_raise_status:
            return
        request = httpx.Request("POST", self.url)
        response = httpx.Response(self.status_code, request=request)
        raise httpx.HTTPStatusError("callback error", request=request, response=response)


class FakeAsyncClient:
    def __init__(
        self,
        response: FakeResponse,
        calls: list[tuple[str, dict[str, object], dict[str, str]]],
        **_: object,
    ) -> None:
        self.response = response
        self.calls = calls

    async def __aenter__(self) -> "FakeAsyncClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def post(
        self, url: str, *, json: dict[str, object], headers: dict[str, str]
    ) -> FakeResponse:
        self.calls.append((url, json, headers))
        return self.response


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    cfg = make_client_config()

    def fake_resolve_client(client_key: str) -> ClientConfig:
        if client_key != cfg.key:
            raise HTTPException(400, "unknown_client_key")
        return cfg

    monkeypatch.setattr(auth_router, "resolve_client", fake_resolve_client)
    return TestClient(app)


def test_issue_login_link_and_login_init_redirect_to_keycloak(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = make_client_config()
    stored_session: dict[str, object] = {}

    def fake_kc_well_known(_: object) -> dict[str, str]:
        return {
            "authorization_endpoint": (
                "https://auth.example.com/realms/Sandori/protocol/openid-connect/auth"
            )
        }

    def fake_sess_set(state: str, data: dict[str, object]) -> None:
        stored_session["state"] = state
        stored_session["data"] = data

    monkeypatch.setattr(auth_router, "kc_well_known", fake_kc_well_known)
    monkeypatch.setattr(auth_router, "sess_set", fake_sess_set)
    monkeypatch.setattr(cfg, "build_kc", lambda: object())
    monkeypatch.setattr(auth_router, "resolve_client", lambda _: cfg)

    issue_response = client.post(
        "/issue_login_link",
        json={
            "chatbot_user_id": "kakao-user-1",
            "callback_url": "https://sandol.sio2.kr/kakao-bot/users/callback",
            "client_key": "sandol-kakao-bot",
            "redirect_after": "/login/success",
        },
    )

    assert issue_response.status_code == 200

    login_path = urlparse(issue_response.json()["login_link"]).path
    login_response = client.get(login_path, follow_redirects=False)

    assert login_response.status_code == 302
    location = login_response.headers["location"]
    parsed = urlparse(location)
    query = parse_qs(parsed.query)

    assert parsed.scheme == "https"
    assert parsed.netloc == "auth.example.com"
    assert query["client_id"] == [cfg.client_id]
    assert query["redirect_uri"] == [cfg.redirect_uri]
    assert query["response_type"] == ["code"]
    assert query["scope"] == ["openid profile email offline_access"]
    assert stored_session["data"] == {
        "nonce": stored_session["data"]["nonce"],
        "code_verifier": stored_session["data"]["code_verifier"],
        "client_key": "sandol-kakao-bot",
        "chatbot_user_id": "kakao-user-1",
        "callback_url": "https://sandol.sio2.kr/kakao-bot/users/callback",
        "redirect_after": "/login/success",
        "ts": stored_session["data"]["ts"],
    }

    lit = login_path.rsplit("/", maxsplit=1)[-1]
    decoded = decode_lit(lit)
    assert decoded["chatbot_user_id"] == "kakao-user-1"


def test_oidc_callback_posts_tokens_and_redirects_when_callback_succeeds(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = make_client_config()
    kc = FakeKeycloakClient(
        token_response={
            "access_token": "access-token",
            "refresh_token": "refresh-token",
            "expires_in": 300,
            "refresh_expires_in": 0,
            "scope": "openid offline_access",
            "token_type": "Bearer",
        }
    )
    callback_calls: list[tuple[str, dict[str, object], dict[str, str]]] = []
    session = {
        "ts": 1700000000,
        "client_key": "sandol-kakao-bot",
        "chatbot_user_id": "kakao-user-1",
        "callback_url": "https://sandol.sio2.kr/kakao-bot/users/callback",
        "redirect_after": "/login/success",
        "code_verifier": "verifier-1",
    }

    monkeypatch.setattr(auth_router, "resolve_client", lambda _: cfg)
    monkeypatch.setattr(cfg, "build_kc", lambda: kc)
    monkeypatch.setattr(auth_router, "sess_pop", lambda _: session)
    monkeypatch.setattr(auth_router, "sess_expired", lambda _: False)
    monkeypatch.setattr(auth_router.httpx, "AsyncClient", lambda **kwargs: FakeAsyncClient(FakeResponse(session["callback_url"]), callback_calls, **kwargs))

    response = client.get(
        "/oidc/callback",
        params={"code": "auth-code-1", "state": "state-1"},
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["location"] == "/login/success"
    assert kc.token_calls == [
        {
            "grant_type": "authorization_code",
            "code": "auth-code-1",
            "redirect_uri": cfg.redirect_uri,
            "scope": "openid offline_access",
            "code_verifier": "verifier-1",
        }
    ]
    assert len(callback_calls) == 1

    callback_url, payload, headers = callback_calls[0]
    assert callback_url == session["callback_url"]
    assert payload["issuer"] == cfg.issuer
    assert payload["aud"] == cfg.client_id
    assert payload["chatbot_user_id"] == "kakao-user-1"
    assert payload["client_key"] == "sandol-kakao-bot"
    assert payload["relay_access_token"] == "access-token"
    assert payload["offline_refresh_token"] == "refresh-token"
    assert headers["X-Relay-Signature"] == sign_payload(payload)


def test_oidc_callback_returns_bad_gateway_for_invalid_callback_status(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = make_client_config()
    kc = FakeKeycloakClient(
        token_response={
            "access_token": "access-token",
            "refresh_token": "refresh-token",
            "expires_in": 300,
            "refresh_expires_in": 0,
        }
    )
    session = {
        "ts": 1700000000,
        "client_key": "sandol-kakao-bot",
        "chatbot_user_id": "kakao-user-1",
        "callback_url": "https://sandol.sio2.kr/kakao-bot/users/callback",
        "redirect_after": "/login/success",
        "code_verifier": "verifier-1",
    }

    monkeypatch.setattr(auth_router, "resolve_client", lambda _: cfg)
    monkeypatch.setattr(cfg, "build_kc", lambda: kc)
    monkeypatch.setattr(auth_router, "sess_pop", lambda _: session)
    monkeypatch.setattr(auth_router, "sess_expired", lambda _: False)
    monkeypatch.setattr(
        auth_router.httpx,
        "AsyncClient",
        lambda **kwargs: FakeAsyncClient(
            FakeResponse(session["callback_url"], status_code=401, should_raise_status=True),
            [],
            **kwargs,
        ),
    )

    response = client.get("/oidc/callback", params={"code": "auth-code-1", "state": "state-1"})

    assert response.status_code == 502
    assert response.json() == {"error": "callback_invalid_status"}
