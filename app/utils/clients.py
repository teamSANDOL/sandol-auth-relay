from __future__ import annotations

import json
import os
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Tuple
from urllib.parse import urlparse

from keycloak import KeycloakOpenID

from app.config import Config, logger

client_registry: ClientRegistry | None = None  # 모듈 상단


def _derive_from_issuer(issuer: str) -> Tuple[str, str]:
    try:
        parsed = urlparse(issuer)
    except ValueError:
        return "", ""

    if not parsed.scheme or not parsed.netloc:
        return "", ""
    path = parsed.path.rstrip("/")
    if not path:
        return "", ""

    parts = [segment for segment in path.split("/") if segment]
    try:
        idx = parts.index("realms")
    except ValueError:
        return "", ""

    if idx + 1 >= len(parts):
        return "", ""

    realm = parts[idx + 1]
    base_parts = parts[:idx]
    base_path = "/".join(base_parts)
    if base_path:
        base_path = f"/{base_path}/"
    else:
        base_path = "/"

    server_url = f"{parsed.scheme}://{parsed.netloc}{base_path}"
    return server_url, realm


def _secret_env_name(client_key: str) -> str:
    normalized = re.sub(r"[^A-Z0-9_]+", "_", client_key.upper())
    return f"{normalized}__SECRETS"


@dataclass
class ClientConfig:
    """Keycloak 클라이언트 한 개에 대한 설정/상태 래퍼."""

    key: str
    raw: Dict[str, Any]

    base_url: str

    issuer: str = field(init=False)
    server_url: str = field(init=False)
    realm: str = field(init=False)
    client_id: str = field(init=False)
    client_secret: str = field(init=False)
    redirect_uri: str = field(init=False)

    extra: Dict[str, Any] = field(default_factory=dict)

    # Lazy 생성용 캐시
    kc: KeycloakOpenID | None = None
    kc_lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    def __post_init__(self) -> None:
        """초기화 후처리: raw 데이터를 기반으로 파생값 생성."""
        self._prepare_from_raw()

    def _prepare_from_raw(self) -> None:
        """clients.json 내용을 기반으로 전처리 + issuer 파생 + secret 주입."""
        prepared: Dict[str, Any] = {}

        for key, value in self.raw.items():
            if isinstance(value, str):
                prepared[key] = value.replace("{BASE_URL}", self.base_url)
            else:
                prepared[key] = value

        self.issuer = prepared.get("issuer", "")
        if not self.issuer:
            raise RuntimeError(f"[{self.key}] issuer is required")

        self.client_id = prepared.get("client_id", "")
        self.redirect_uri = prepared.get("redirect_uri", "")
        server_url = prepared.get("server_url", "")
        realm = prepared.get("realm", "")

        derived_server, derived_realm = _derive_from_issuer(self.issuer)

        self.server_url = server_url or derived_server
        self.realm = realm or derived_realm

        if not self.server_url or not self.realm:
            raise RuntimeError(
                f"[{self.key}] server_url/realm could not be derived from issuer={self.issuer}"
            )

        if not self.client_id or not self.redirect_uri:
            raise RuntimeError(f"[{self.key}] client_id/redirect_uri is required")

        # client_secret 주입
        self.client_secret = prepared.get("client_secret", "")
        if not self.client_secret:
            self._inject_client_secret()

        # 나머지 값은 extra에 보관
        for k, v in prepared.items():
            if k not in {
                "issuer",
                "client_id",
                "client_secret",
                "server_url",
                "realm",
                "redirect_uri",
            }:
                self.extra[k] = v

    def _inject_client_secret(self) -> None:
        candidates = [
            _secret_env_name(self.key),
            f"{self.key}__secrets",
        ]
        for env_key in candidates:
            secret = os.getenv(env_key)
            if secret:
                self.client_secret = secret
                logger.debug("client_secret hydrated from ENV: %s", env_key)
                return
        logger.info("client_secret missing for client '%s'", self.key)

    def build_kc(self) -> KeycloakOpenID:
        """Keycloak 클라이언트 lazy 생성 (이미 있으면 재사용)."""
        if self.kc is not None:
            return self.kc

        if not self.server_url or not self.realm or not self.client_id:
            raise RuntimeError(
                f"ClientConfig[{self.key}] is not fully configured: "
                f"server_url={self.server_url}, realm={self.realm}, client_id={self.client_id}"
            )

        with self.kc_lock:
            # 잠금 안에서 2차 확인 (double-checked locking)
            if self.kc is None:
                self.kc = KeycloakOpenID(
                    server_url=self.server_url,
                    realm_name=self.realm,
                    client_id=self.client_id,
                    client_secret_key=self.client_secret,
                    timeout=10,
                )
        return self.kc


class ClientRegistry:
    """clients.json 전체를 관리하는 레지스트리."""

    def __init__(self, base_url: str, clients: Dict[str, ClientConfig]):
        self.base_url = base_url
        self._clients = clients

    @classmethod
    def load(cls, base_url: str) -> "ClientRegistry":
        try:
            with open(Config.CLIENTS_FILE, encoding="utf-8") as fp:
                raw = json.load(fp)
        except FileNotFoundError:
            logger.warning("clients.json not found, ClientRegistry is empty")
            return cls(base_url, {})
        except json.JSONDecodeError as exc:
            logger.error("clients.json parsing failed: %s", exc)
            return cls(base_url, {})

        clients: Dict[str, ClientConfig] = {}
        for client_key, cfg in raw.items():
            if not isinstance(cfg, dict):
                logger.warning(
                    "clients.json entry '%s' ignored (expected object)", client_key
                )
                continue

            clients[client_key] = ClientConfig(
                key=client_key,
                raw=cfg,
                base_url=base_url,
            )

        return cls(base_url, clients)

    def validate(self) -> None:
        """모든 ClientConfig가 정상 구성되었는지 부팅 시점에서 검증."""
        errors = []

        for key, cfg in self._clients.items():
            if not cfg.server_url:
                errors.append(f"[{key}] server_url missing")
            if not cfg.realm:
                errors.append(f"[{key}] realm missing")
            if not cfg.client_id:
                errors.append(f"[{key}] client_id missing")
            if not cfg.client_secret:
                errors.append(f"[{key}] client_secret missing (ENV?)")
            if not cfg.redirect_uri:
                errors.append(f"[{key}] redirect_uri missing")

        if errors:
            msg = "ClientRegistry validation failed:\n" + "\n".join(errors)
            raise RuntimeError(msg)

    def require(self, key: str) -> ClientConfig:
        try:
            return self._clients[key]
        except KeyError:
            raise KeyError(f"Client '{key}' is not configured.") from None

    def __getitem__(self, key: str) -> ClientConfig:
        return self.require(key)

    def all(self) -> Dict[str, ClientConfig]:
        return dict(self._clients)


def client_registry_init() -> ClientRegistry:
    global client_registry
    client_registry = ClientRegistry.load(Config.BASE_URL)
    return client_registry


def get_client_registry() -> ClientRegistry:
    global client_registry
    if client_registry is None:
        raise RuntimeError(
            "ClientRegistry is not initialized. Call client_registry_init() first."
        )
    return client_registry
