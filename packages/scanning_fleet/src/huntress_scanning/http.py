"""Small, bounded HTTP client used by reviewed builtin profiles.

The client never follows redirects automatically. Every request is authorized
individually through a callback supplied by the execution service, which
performs a fresh scope check against the sealed scope document.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable, Mapping
from typing import Any

import httpx
from huntress_contracts import HttpMethod

from .models import HttpResponse, ScanAuthorizationError, ScanRequestError, ScanTimeout

DEFAULT_USER_AGENT = "Huntress/0.1 (+authorized-security-testing)"


class BoundedHttpClient:
    """Synchronous, single-request client with hard byte and time caps."""

    def __init__(
        self,
        *,
        max_response_bytes: int = 1_048_576,
        timeout_seconds: float = 30.0,
        user_agent: str = DEFAULT_USER_AGENT,
        verify_tls: bool = True,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.max_response_bytes = max(1024, max_response_bytes)
        self.timeout_seconds = timeout_seconds
        self.user_agent = user_agent
        self._client = httpx.Client(
            follow_redirects=False,
            timeout=httpx.Timeout(timeout_seconds),
            headers={"User-Agent": user_agent, "Accept": "*/*"},
            verify=verify_tls,
            trust_env=False,
            transport=transport,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> BoundedHttpClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def request(
        self,
        method: HttpMethod,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        authorize: Callable[[str, HttpMethod], bool],
    ) -> HttpResponse:
        """Perform one authorized request.

        The authorization callback is called immediately before the request so
        redirects, path changes, or a scope version change cannot be bypassed by
        a handler's earlier check.
        """

        if not authorize(url, method):
            raise ScanAuthorizationError(f"scope check denied {method.value} {url}")
        started = time.perf_counter()
        request_headers = {"User-Agent": self.user_agent, "Accept": "*/*"}
        if headers:
            request_headers.update(headers)
        chunks: list[bytes] = []
        total = 0
        truncated = False
        try:
            with self._client.stream(
                method.value,
                url,
                headers=request_headers,
            ) as response:
                for chunk in response.iter_bytes():
                    if not chunk:
                        continue
                    remaining = self.max_response_bytes - total
                    if remaining <= 0:
                        truncated = True
                        break
                    if len(chunk) > remaining:
                        chunks.append(chunk[:remaining])
                        total += remaining
                        truncated = True
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                result_headers = tuple((key, value) for key, value in response.headers.multi_items())
                status_code = response.status_code
        except httpx.TimeoutException as exc:
            raise ScanTimeout(f"request timed out after {self.timeout_seconds:.1f}s: {url}") from exc
        except httpx.HTTPError as exc:
            raise ScanRequestError(f"request failed for {url}: {exc}") from exc
        elapsed_ms = max(0, int((time.perf_counter() - started) * 1000))
        return HttpResponse(
            url=str(url),
            method=method,
            status_code=status_code,
            headers=result_headers,
            body=b"".join(chunks),
            elapsed_ms=elapsed_ms,
            truncated=truncated,
            request_headers=tuple(request_headers.items()),
        )

    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        authorize: Callable[[str, HttpMethod], bool],
    ) -> HttpResponse:
        return self.request(HttpMethod.GET, url, headers=headers, authorize=authorize)


def safe_join(base_url: str, path: str) -> str:
    """Join a fixed reviewed path to a target base URL without path traversal."""

    if not path.startswith("/") or ".." in path or "\x00" in path or "\n" in path:
        raise ValueError(f"unsafe reviewed path: {path!r}")
    return f"{base_url.rstrip('/')}{path}"


def safe_query(url: str, params: Mapping[str, str]) -> str:
    """Append fixed query parameters while rejecting control characters."""

    from urllib.parse import urlencode, urlsplit, urlunsplit

    parts = urlsplit(url)
    for key, value in params.items():
        if any(ch in key or ch in value for ch in "\r\n\x00"):
            raise ValueError("query parameter contains control characters")
    existing = parts.query
    encoded = urlencode(dict(params))
    query = f"{existing}&{encoded}" if existing else encoded
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def response_to_json(response: HttpResponse) -> dict[str, Any]:
    """Compact, bounded representation for parser artifacts."""

    return {
        "url": response.url,
        "method": response.method.value,
        "status_code": response.status_code,
        "headers": dict(response.headers),
        "request_headers": dict(response.request_headers),
        "elapsed_ms": response.elapsed_ms,
        "truncated": response.truncated,
        "body_sha256": hashlib.sha256(response.body).hexdigest(),
        "body_size": len(response.body),
    }
