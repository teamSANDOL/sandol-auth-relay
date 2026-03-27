from app.utils.clients import ClientConfig
from app.utils.redirects import callback_url_allowed, redirect_allowed


def make_client_config(
    *,
    callback_url_allowlist: list[str] | None = None,
    redirect_after_allowlist: list[str] | None = None,
) -> ClientConfig:
    return ClientConfig(
        key="sandol-kakao-bot",
        base_url="https://relay.example.com",
        raw={
            "issuer": "https://auth.example.com/realms/Sandori",
            "client_id": "sandol-kakao-bot",
            "client_secret": "test-secret",
            "redirect_uri": "https://relay.example.com/oidc/callback",
            "callback_url_allowlist": callback_url_allowlist
            or ["https://sandol.sio2.kr/kakao-bot/users/callback"],
            "redirect_after_allowlist": redirect_after_allowlist or ["/"],
        },
    )


def test_callback_url_allowed_accepts_exact_match() -> None:
    cfg = make_client_config()

    assert callback_url_allowed(
        cfg,
        "https://sandol.sio2.kr/kakao-bot/users/callback",
    )


def test_callback_url_allowed_normalizes_default_https_port() -> None:
    cfg = make_client_config(
        callback_url_allowlist=["https://sandol.sio2.kr/kakao-bot/users/callback"]
    )

    assert callback_url_allowed(
        cfg,
        "https://sandol.sio2.kr:443/kakao-bot/users/callback",
    )


def test_callback_url_allowed_rejects_different_path() -> None:
    cfg = make_client_config()

    assert not callback_url_allowed(
        cfg,
        "https://sandol.sio2.kr/kakao-bot/users/other-callback",
    )


def test_callback_url_allowed_rejects_fragment_url() -> None:
    cfg = make_client_config()

    assert not callback_url_allowed(
        cfg,
        "https://sandol.sio2.kr/kakao-bot/users/callback#fragment",
    )


def test_redirect_allowed_accepts_safe_relative_path() -> None:
    cfg = make_client_config(redirect_after_allowlist=["/", "/login"])

    assert redirect_allowed(cfg, "/login/success")


def test_redirect_allowed_rejects_absolute_url() -> None:
    cfg = make_client_config(redirect_after_allowlist=["/"])

    assert not redirect_allowed(cfg, "https://evil.example/steal")


def test_redirect_allowed_rejects_protocol_relative_path() -> None:
    cfg = make_client_config(redirect_after_allowlist=["/"])

    assert not redirect_allowed(cfg, "//evil.example/steal")
