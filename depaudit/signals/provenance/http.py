"""Rate-limited async HTTP session with per-host semaphores and exponential backoff."""

from __future__ import annotations

import asyncio
import random
from collections import defaultdict
from typing import Any
from urllib.parse import urlparse

import aiohttp


_DEFAULT_PER_HOST = 10
_MAX_RETRIES = 4
_BASE_BACKOFF = 0.5  # seconds


class RateLimitedSession:
    def __init__(self, *, per_host: int = _DEFAULT_PER_HOST) -> None:
        self._per_host = per_host
        self._semaphores: dict[str, asyncio.Semaphore] = defaultdict(
            lambda: asyncio.Semaphore(self._per_host)
        )
        self._session: aiohttp.ClientSession | None = None

    async def __aenter__(self) -> "RateLimitedSession":
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={"User-Agent": "depaudit/0.1 (https://github.com/depaudit/depaudit)"},
        )
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._session:
            await self._session.close()
            self._session = None

    def _sem(self, url: str) -> asyncio.Semaphore:
        host = urlparse(url).netloc
        return self._semaphores[host]

    async def get_json(self, url: str) -> Any | None:
        return await self._get(url, as_json=True)

    async def get_text(self, url: str) -> str | None:
        return await self._get(url, as_json=False)

    async def _get(self, url: str, *, as_json: bool) -> Any | None:
        assert self._session is not None, "Use as async context manager"
        sem = self._sem(url)
        for attempt in range(_MAX_RETRIES):
            async with sem:
                try:
                    async with self._session.get(url) as resp:
                        if resp.status == 404:
                            return None
                        if resp.status == 429 or resp.status >= 500:
                            raise aiohttp.ClientResponseError(
                                resp.request_info,
                                resp.history,
                                status=resp.status,
                            )
                        resp.raise_for_status()
                        if as_json:
                            return await resp.json(content_type=None)
                        return await resp.text()
                except (aiohttp.ClientResponseError, aiohttp.ServerConnectionError) as exc:
                    status = getattr(exc, "status", 0)
                    if status == 404:
                        return None
                    if attempt == _MAX_RETRIES - 1:
                        return None
                    delay = _BASE_BACKOFF * (2 ** attempt) + random.uniform(0, 0.3)
                    await asyncio.sleep(delay)
                except asyncio.TimeoutError:
                    if attempt == _MAX_RETRIES - 1:
                        return None
                    delay = _BASE_BACKOFF * (2 ** attempt) + random.uniform(0, 0.3)
                    await asyncio.sleep(delay)
        return None
