import base64
import json
import logging
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from diskcache import Cache
from fastapi.testclient import TestClient
import pytest

from app.config import Config
from app.routers import account_deletion as account_deletion_router
from main import app

# 운영에서 Keycloak이 부르는 주소 그대로 (/relay 접두사 포함)
URL = "/relay/internal/account-deletions"
KEY = os.urandom(32)
EMAIL = "secret-user@example.com"
APPLE_REFRESH = "secret-apple-refresh-token"
STORE_KEY = "Sandori:user-1"


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode()


def make_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "event_id": "event-1",
        "occurred_at": "2026-10-30T09:16:20.358Z",
        "realm": "Sandori",
        "user_id": "user-1",
        "email": EMAIL,
        "identities": [
            {
                "provider": "apple",
                "provider_user_id": "apple-1",
                "refresh_token": APPLE_REFRESH,
            },
            {"provider": "kakao", "provider_user_id": "kakao-1"},
        ],
    }
    payload.update(overrides)
    return payload


# Keycloak의 PayloadEncryptor와 같은 방식으로 암호화한다
def encrypt(plaintext: bytes, key: bytes = KEY, kid: str = "v1") -> dict[str, str]:
    iv = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(iv, plaintext, None)
    return {"kid": kid, "iv": b64(iv), "ciphertext": b64(ciphertext)}


def make_envelope(**overrides: object) -> dict[str, str]:
    return encrypt(json.dumps(make_payload(**overrides)).encode())


def read_stored(store_dir: Path, key: str = STORE_KEY) -> dict[str, object] | None:
    with Cache(str(store_dir)) as cache:
        return cache.get(key)


@pytest.fixture
def store_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.setattr(Config, "SANDOL_DELETION_KEY", b64(KEY))
    monkeypatch.setattr(Config, "SANDOL_DELETION_KEY_ID", "v1")
    monkeypatch.setattr(Config, "DELETION_STORE_DIR", str(tmp_path))
    return tmp_path


@pytest.fixture
def client(store_dir: Path) -> TestClient:
    return TestClient(app)


def test_accepts_and_stores_envelope(client: TestClient, store_dir: Path) -> None:
    envelope = make_envelope()

    response = client.post(URL, json=envelope)

    assert response.status_code == 202
    assert response.json() == {"event_id": "event-1"}
    stored = read_stored(store_dir)
    assert stored["envelope"] == envelope
    assert stored["event_id"] == "event-1"
    assert stored["realm"] == "Sandori"
    assert stored["user_id"] == "user-1"
    assert stored["received_at"]


def test_store_keeps_no_plaintext_secrets(client: TestClient, store_dir: Path) -> None:
    assert client.post(URL, json=make_envelope()).status_code == 202

    contents = b"".join(
        path.read_bytes() for path in store_dir.rglob("*") if path.is_file()
    )
    # 메타데이터가 보이면 파일을 제대로 훑었다는 뜻이다
    assert b"event-1" in contents
    assert EMAIL.encode() not in contents
    assert APPLE_REFRESH.encode() not in contents


def test_logs_keep_no_secrets(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.DEBUG, logger="sandol-auth-relay-service"):
        assert client.post(URL, json=make_envelope()).status_code == 202

    assert "event-1" in caplog.text
    assert EMAIL not in caplog.text
    assert APPLE_REFRESH not in caplog.text
    assert b64(KEY) not in caplog.text


@pytest.mark.parametrize(
    "overrides",
    [{"identities": []}, {"email": None}],
)
def test_accepts_user_without_optional_values(
    client: TestClient, overrides: dict[str, object]
) -> None:
    payload = make_payload(**overrides)
    payload = {name: value for name, value in payload.items() if value is not None}

    response = client.post(URL, json=encrypt(json.dumps(payload).encode()))

    assert response.status_code == 202


def test_duplicate_request_keeps_first_record(
    client: TestClient, store_dir: Path
) -> None:
    first = make_envelope()
    second = make_envelope(event_id="event-2")

    assert client.post(URL, json=first).status_code == 202
    response = client.post(URL, json=second)

    assert response.status_code == 202
    assert response.json() == {"event_id": "event-2"}
    stored = read_stored(store_dir)
    assert stored["event_id"] == "event-1"
    assert stored["envelope"] == first


@pytest.mark.parametrize("header", ["X-Forwarded-For", "X-Real-IP"])
def test_gateway_request_gets_not_found(
    client: TestClient, store_dir: Path, header: str
) -> None:
    response = client.post(URL, json=make_envelope(), headers={header: "203.0.113.1"})

    assert response.status_code == 404
    assert response.json() == {"detail": "Not Found"}
    assert read_stored(store_dir) is None


def test_gateway_check_comes_before_key_check(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Config, "SANDOL_DELETION_KEY", "")

    response = client.post(URL, json={}, headers={"X-Real-IP": "203.0.113.1"})

    assert response.status_code == 404


@pytest.mark.parametrize("key", ["", "not-base64!", b64(os.urandom(16))])
def test_unusable_key_returns_service_unavailable(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, key: str
) -> None:
    monkeypatch.setattr(Config, "SANDOL_DELETION_KEY", key)

    response = client.post(URL, json=make_envelope())

    assert response.status_code == 503


@pytest.mark.parametrize(
    "body",
    [b"not json", b"[]", b"{}", b"\xff\xfe"],
)
def test_malformed_body_returns_bad_request(client: TestClient, body: bytes) -> None:
    response = client.post(URL, content=body)

    assert response.status_code == 400


@pytest.mark.parametrize("field", ["kid", "iv", "ciphertext"])
def test_missing_envelope_field_returns_bad_request(
    client: TestClient, field: str
) -> None:
    envelope = make_envelope()
    del envelope[field]

    response = client.post(URL, json=envelope)

    assert response.status_code == 400


def test_kid_mismatch_returns_bad_request(client: TestClient) -> None:
    envelope = encrypt(json.dumps(make_payload()).encode(), kid="v2")

    response = client.post(URL, json=envelope)

    assert response.status_code == 400
    assert response.json()["detail"] == "unknown_kid"


@pytest.mark.parametrize(
    "overrides",
    [
        {"iv": "%%%not-base64%%%"},
        {"ciphertext": "%%%not-base64%%%"},
        {"iv": b64(os.urandom(16))},
    ],
)
def test_bad_encoding_returns_bad_request(
    client: TestClient, overrides: dict[str, str]
) -> None:
    response = client.post(URL, json={**make_envelope(), **overrides})

    assert response.status_code == 400


@pytest.mark.parametrize(
    "plaintext",
    [
        b"not json",
        b"[]",
        json.dumps({"realm": "Sandori", "user_id": "user-1"}).encode(),
        json.dumps({"event_id": "event-1", "user_id": "user-1"}).encode(),
        json.dumps({"event_id": "event-1", "realm": "Sandori"}).encode(),
        json.dumps({"event_id": 1, "realm": "Sandori", "user_id": "user-1"}).encode(),
    ],
)
def test_invalid_payload_returns_bad_request(
    client: TestClient, store_dir: Path, plaintext: bytes
) -> None:
    response = client.post(URL, json=encrypt(plaintext))

    assert response.status_code == 400
    assert response.json()["detail"] == "invalid_payload"
    assert read_stored(store_dir) is None


def test_wrong_key_returns_unauthorized(client: TestClient) -> None:
    envelope = encrypt(json.dumps(make_payload()).encode(), key=os.urandom(32))

    response = client.post(URL, json=envelope)

    assert response.status_code == 401


def test_tampered_ciphertext_returns_unauthorized(
    client: TestClient, store_dir: Path
) -> None:
    envelope = make_envelope()
    tampered = bytearray(base64.b64decode(envelope["ciphertext"]))
    tampered[0] ^= 1
    envelope["ciphertext"] = b64(bytes(tampered))

    response = client.post(URL, json=envelope)

    assert response.status_code == 401
    assert read_stored(store_dir) is None


def test_too_short_ciphertext_returns_unauthorized(client: TestClient) -> None:
    response = client.post(URL, json={**make_envelope(), "ciphertext": b64(b"short")})

    assert response.status_code == 401


def test_store_failure_returns_server_error(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_save(*_args: object) -> bool:
        raise OSError("disk full")

    monkeypatch.setattr(account_deletion_router, "save_deletion", fail_save)

    response = client.post(URL, json=make_envelope())

    assert response.status_code == 500
    assert response.json()["detail"] == "storage_failed"


def test_store_settings_prevent_data_loss(client: TestClient, store_dir: Path) -> None:
    assert client.post(URL, json=make_envelope()).status_code == 202

    with Cache(str(store_dir)) as cache:
        assert cache.eviction_policy == "none"
        assert cache.sqlite_synchronous == 2
        assert cache.expire() == 0
        assert STORE_KEY in cache
