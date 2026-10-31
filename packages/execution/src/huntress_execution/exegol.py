"""Narrow Exegol MCP adapter.

Only one MCP tool is ever called: ``execute_command_in_container``. The command
is assembled from a reviewed profile template and an authoritative target; the
model cannot supply either. The adapter additionally refuses non-local MCP
endpoints unless explicitly configured otherwise.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import ipaddress
import json
import os
import threading
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx2
from huntress_contracts import ToolRunStatus

from .models import BackendContext, BackendOutput
from .profiles import build_command

DEFAULT_EXEGOL_URL = "http://127.0.0.1:2187/mcp"
EXECUTE_TOOL = "execute_command_in_container"


@dataclass(frozen=True, slots=True)
class ExegolProbe:
    """Result of a non-destructive MCP capability probe."""

    available: bool
    reason: str
    endpoint: str
    tools: tuple[str, ...] = ()


def _is_private_host(host: str) -> bool:
    normalized = host.lower().rstrip(".")
    if normalized == "localhost" or normalized.endswith(
        (".localhost", ".local", ".internal", ".test", ".example", ".invalid")
    ):
        return True
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return False
    return address.is_loopback or address.is_private or address.is_link_local


class _AsyncRunner:
    """A persistent event loop in a daemon thread for synchronous callers."""

    def __init__(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._loop.run_forever,
            name="huntress-exegol-mcp",
            daemon=True,
        )
        self._thread.start()
        self._closed = False
        self._lock = threading.Lock()

    def run(self, coroutine: Any, timeout: float) -> Any:
        with self._lock:
            if self._closed:
                raise RuntimeError("async runner is closed")
        future = asyncio.run_coroutine_threadsafe(coroutine, self._loop)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError as exc:
            future.cancel()
            raise TimeoutError(f"Exegol MCP call exceeded {timeout:.0f}s") from exc

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=2.0)
        if not self._loop.is_closed():
            self._loop.close()


class ExegolAdapter:
    """Fixed-profile executor backed by the Exegol MCP server."""

    name = "exegol"

    def __init__(
        self,
        *,
        url: str = DEFAULT_EXEGOL_URL,
        container: str = "pentest",
        token: str | None = None,
        timeout_seconds: float = 300.0,
        max_output_bytes: int = 1_048_576,
        allow_remote: bool = False,
        tool_name: str = EXECUTE_TOOL,
    ) -> None:
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ValueError("Exegol URL must be an absolute http(s) MCP endpoint")
        if not allow_remote and not _is_private_host(parts.hostname):
            raise ValueError(
                "Exegol endpoint must be loopback/private/local by default; "
                "set allow_remote=True only after an explicit network review"
            )
        if not container or any(char in container for char in "\n\r\0;|&$`"):
            raise ValueError("invalid Exegol container name")
        self._url = url
        self._container = container
        self._token = token or os.environ.get("EXEGOL_MCP_TOKEN") or os.environ.get("EXEGOL_TOKEN")
        self._timeout_seconds = max(1.0, float(timeout_seconds))
        self._max_output_bytes = max(1024, int(max_output_bytes))
        self._tool_name = tool_name
        self._runner = _AsyncRunner()

    @property
    def endpoint(self) -> str:
        return self._url

    def close(self) -> None:
        self._runner.close()

    def probe(self, timeout_seconds: float = 5.0) -> ExegolProbe:
        """Check that the endpoint exposes the one reviewed tool."""

        try:
            tools = self._runner.run(self._list_tools(float(timeout_seconds)), timeout_seconds + 1.0)
        except Exception as exc:
            return ExegolProbe(
                available=False,
                reason=self._safe_error(exc),
                endpoint=self._url,
            )
        names = tuple(sorted(tools))
        if self._tool_name not in names:
            return ExegolProbe(
                available=False,
                reason=f"MCP endpoint does not expose {self._tool_name!r}",
                endpoint=self._url,
                tools=names,
            )
        return ExegolProbe(
            available=True,
            reason="MCP endpoint exposes the reviewed execution tool",
            endpoint=self._url,
            tools=names,
        )

    def execute(self, context: BackendContext) -> BackendOutput:
        try:
            command = build_command(context.profile, context.target)
        except Exception as exc:
            return BackendOutput(
                status=ToolRunStatus.FAILED,
                error_code="profile_resolution_failed",
                error_message=self._safe_error(exc),
                backend=self.name,
            )

        timeout = min(self._timeout_seconds, float(context.profile.timeout_seconds))
        try:
            raw = self._runner.run(
                self._call_tool(
                    self._tool_name,
                    {"container_name": self._container, "command": command},
                    timeout,
                ),
                timeout + 5.0,
            )
        except TimeoutError as exc:
            return BackendOutput(
                status=ToolRunStatus.TIMEOUT,
                timed_out=True,
                error_code="exegol_timeout",
                error_message=self._safe_error(exc),
                request_count=1,
                backend=self.name,
            )
        except Exception as exc:
            return BackendOutput(
                status=ToolRunStatus.FAILED,
                error_code="exegol_error",
                error_message=self._safe_error(exc),
                request_count=1,
                backend=self.name,
            )

        is_error = bool(getattr(raw, "is_error", False))
        exit_code, output = self._parse_result(raw)
        output_bytes = output.encode("utf-8", errors="replace")
        truncated = len(output_bytes) > min(self._max_output_bytes, context.profile.max_output_bytes)
        if truncated:
            output_bytes = output_bytes[: min(self._max_output_bytes, context.profile.max_output_bytes)]
        if is_error:
            return BackendOutput(
                status=ToolRunStatus.FAILED,
                exit_code=exit_code,
                stdout=output_bytes,
                request_count=1,
                output_truncated=truncated,
                error_code="exegol_tool_error",
                error_message="Exegol reported a tool-level error; output preserved",
                backend=self.name,
            )
        if exit_code is None:
            return BackendOutput(
                status=ToolRunStatus.FAILED,
                stdout=output_bytes,
                request_count=1,
                output_truncated=truncated,
                error_code="exegol_unparsed_result",
                error_message="Exegol returned no parseable execution result",
                backend=self.name,
            )
        status = ToolRunStatus.SUCCEEDED if exit_code == 0 else ToolRunStatus.FAILED
        return BackendOutput(
            status=status,
            exit_code=exit_code,
            stdout=output_bytes,
            request_count=1,
            output_truncated=truncated,
            error_code=None if status is ToolRunStatus.SUCCEEDED else "exegol_nonzero_exit",
            error_message="" if status is ToolRunStatus.SUCCEEDED else f"command exited {exit_code}",
            backend=self.name,
        )

    async def _list_tools(self, timeout: float) -> tuple[str, ...]:
        from mcp import ClientSession
        from mcp.client.streamable_http import (  # type: ignore[attr-defined]
            create_mcp_http_client,
            streamable_http_client,
        )

        headers = self._headers()
        client = create_mcp_http_client(headers=headers, timeout=httpx2.Timeout(timeout))
        async with (
            client,
            streamable_http_client(self._url, http_client=client) as (read, write),
            ClientSession(read, write, read_timeout_seconds=timeout) as session,
        ):
            await session.initialize()
            result = await session.list_tools()
            return tuple(tool.name for tool in result.tools)

    async def _call_tool(self, name: str, arguments: dict[str, Any], timeout: float) -> Any:
        from mcp import ClientSession
        from mcp.client.streamable_http import (  # type: ignore[attr-defined]
            create_mcp_http_client,
            streamable_http_client,
        )

        headers = self._headers()
        client = create_mcp_http_client(headers=headers, timeout=httpx2.Timeout(timeout))
        async with (
            client,
            streamable_http_client(self._url, http_client=client) as (read, write),
            ClientSession(read, write, read_timeout_seconds=timeout) as session,
        ):
            await session.initialize()
            return await session.call_tool(
                name,
                arguments,
                read_timeout_seconds=timeout,
            )

    def _headers(self) -> dict[str, str]:
        if not self._token:
            return {}
        return {"Authorization": f"Bearer {self._token}"}

    @staticmethod
    def _parse_result(result: Any) -> tuple[int | None, str]:
        structured = getattr(result, "structured_content", None)
        if isinstance(structured, dict):
            exit_code = structured.get("exit_code")
            output = structured.get("output", "")
            if isinstance(exit_code, int):
                return exit_code, str(output)
        for item in getattr(result, "content", ()) or ():
            text = getattr(item, "text", None)
            if not isinstance(text, str):
                continue
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict) and isinstance(parsed.get("exit_code"), int):
                return parsed["exit_code"], str(parsed.get("output", ""))
        text_parts: list[str] = []
        for item in getattr(result, "content", ()) or ():
            text = getattr(item, "text", None)
            if isinstance(text, str):
                text_parts.append(text)
        if text_parts:
            return None, "\n".join(text_parts)
        return None, ""

    def _safe_error(self, exc: BaseException) -> str:
        message = f"{type(exc).__name__}: {exc}"
        if self._token:
            message = message.replace(self._token, "***")
        return message[:2000]


def detect_exegol(
    *,
    url: str = DEFAULT_EXEGOL_URL,
    container: str = "pentest",
    token: str | None = None,
    timeout_seconds: float = 5.0,
    allow_remote: bool = False,
) -> ExegolProbe:
    """Construct a short-lived adapter, probe it, and always close it."""

    adapter = ExegolAdapter(
        url=url,
        container=container,
        token=token,
        timeout_seconds=timeout_seconds,
        allow_remote=allow_remote,
    )
    try:
        return adapter.probe(timeout_seconds=timeout_seconds)
    finally:
        adapter.close()
