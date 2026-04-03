"""Absolute URL validation helpers."""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit


DEFAULT_HTTP_PORT = 80
DEFAULT_HTTPS_PORT = 443


def normalize_absolute_url(url: str) -> str | None:
    """Return a canonical absolute URL string or None when invalid."""
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        return None

    if parsed.scheme not in {"http", "https"}:
        return None
    if not parsed.netloc:
        return None
    if parsed.fragment:
        return None

    host = parsed.hostname.lower() if parsed.hostname else ""
    if not host:
        return None

    if port is None:
        netloc = host
    else:
        default_http = parsed.scheme == "http" and port == DEFAULT_HTTP_PORT
        default_https = parsed.scheme == "https" and port == DEFAULT_HTTPS_PORT
        netloc = host if (default_http or default_https) else f"{host}:{port}"

    path = parsed.path or "/"
    return urlunsplit((parsed.scheme, netloc, path, parsed.query, ""))
