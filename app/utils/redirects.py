from __future__ import annotations
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

from app.utils.clients import ClientConfig


def _is_safe_relative_path(path: str) -> bool:
    """상대 경로 기반 리다이렉트 경로의 안전성을 검증한다.

    Args:
        path (str): 검증 대상 경로.

    Returns:
        bool: 안전한 상대 경로면 True, 아니면 False.
    """
    if not path.startswith("/"):
        return False
    if path.startswith("//"):
        return False
    if "\\" in path:
        return False

    parsed = urlsplit(path)
    if parsed.scheme or parsed.netloc:
        return False
    return True


def redirect_allowed(
    cfg: ClientConfig,
    dest: Optional[str],
    policy_key: str = "redirect_after_allowlist",
) -> bool:
    """클라이언트별 allowlist 정책으로 최종 리다이렉트 목적지를 검증한다.

    Args:
        cfg (ClientConfig): 검증에 사용할 클라이언트 설정.
        dest (Optional[str]): 리다이렉트 대상 문자열.
        policy_key (str): 조회할 allowlist 정책 키.

    Returns:
        bool: 허용된 목적지면 True, 아니면 False.
    """
    if not dest:
        return False
    if not _is_safe_relative_path(dest):
        return False

    allowlist = cfg.extra.get(policy_key, [])
    if not isinstance(allowlist, list) or not allowlist:
        return False

    for prefix in allowlist:
        if not isinstance(prefix, str):
            continue
        if not _is_safe_relative_path(prefix):
            continue
        if dest.startswith(prefix):
            return True
    return False


def _normalize_absolute_url(url: str) -> str | None:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"}:
        return None
    if not parsed.netloc:
        return None
    if parsed.fragment:
        return None

    host = parsed.hostname.lower() if parsed.hostname else ""
    if not host:
        return None

    port = parsed.port
    if port is None:
        netloc = host
    else:
        default_http = parsed.scheme == "http" and port == 80
        default_https = parsed.scheme == "https" and port == 443
        netloc = host if (default_http or default_https) else f"{host}:{port}"

    path = parsed.path or "/"
    return urlunsplit((parsed.scheme, netloc, path, parsed.query, ""))


def callback_url_allowed(
    cfg: ClientConfig,
    callback_url: Optional[str],
    policy_key: str = "callback_url_allowlist",
) -> bool:
    if not callback_url:
        return False

    normalized_input = _normalize_absolute_url(callback_url)
    if not normalized_input:
        return False

    allowlist = cfg.extra.get(policy_key, [])
    if not isinstance(allowlist, list) or not allowlist:
        return False

    for allowed in allowlist:
        if not isinstance(allowed, str):
            continue
        normalized_allowed = _normalize_absolute_url(allowed)
        if not normalized_allowed:
            continue
        if normalized_input == normalized_allowed:
            return True
    return False
