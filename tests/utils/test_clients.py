import pytest

from app.utils.clients import ClientConfig, ClientRegistry


def make_client_config(extra: dict[str, object] | None = None) -> ClientConfig:
    raw: dict[str, object] = {
        "issuer": "https://auth.example.com/realms/Sandori",
        "client_id": "sandol-kakao-bot",
        "client_secret": "test-secret",
        "redirect_uri": "https://relay.example.com/oidc/callback",
        "callback_url_allowlist": [
            "https://sandol.sio2.kr/kakao-bot/users/callback",
        ],
        "redirect_after_allowlist": ["/"],
    }
    if extra:
        raw.update(extra)

    return ClientConfig(
        key="sandol-kakao-bot",
        base_url="https://relay.example.com",
        raw=raw,
    )


def make_registry(cfg: ClientConfig) -> ClientRegistry:
    return ClientRegistry(base_url="https://relay.example.com", clients={cfg.key: cfg})


def test_validate_accepts_valid_callback_allowlist() -> None:
    registry = make_registry(make_client_config())

    registry.validate()


def test_validate_rejects_missing_callback_allowlist() -> None:
    registry = make_registry(make_client_config(extra={"callback_url_allowlist": None}))

    with pytest.raises(RuntimeError, match="callback_url_allowlist missing or empty"):
        registry.validate()


def test_validate_rejects_empty_callback_allowlist() -> None:
    registry = make_registry(make_client_config(extra={"callback_url_allowlist": []}))

    with pytest.raises(RuntimeError, match="callback_url_allowlist missing or empty"):
        registry.validate()


def test_validate_rejects_invalid_callback_url() -> None:
    registry = make_registry(
        make_client_config(extra={"callback_url_allowlist": ["/users/callback"]})
    )

    with pytest.raises(RuntimeError, match="invalid callback URL"):
        registry.validate()


def test_validate_rejects_callback_url_with_invalid_port() -> None:
    registry = make_registry(
        make_client_config(
            extra={
                "callback_url_allowlist": [
                    "https://sandol.sio2.kr:99999/kakao-bot/users/callback"
                ]
            }
        )
    )

    with pytest.raises(RuntimeError, match="invalid callback URL"):
        registry.validate()
