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
        # L1 in-process cache (spec §7.2): a single run may have several
        # collectors fetch the same registry document for one dependency.
        # Memoising GET responses by URL collapses those into one real request.
        self._cache: dict[str, Any] = {}

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

    async def get_json(
        self, url: str, *, headers: dict[str, str] | None = None
    ) -> Any | None:
        return await self._get(url, as_json=True, headers=headers)

    async def get_text(
        self, url: str, *, headers: dict[str, str] | None = None
    ) -> str | None:
        return await self._get(url, as_json=False, headers=headers)

    async def post_json(self, url: str, payload: Any) -> Any | None:
        """POST *payload* as JSON and return the decoded JSON response.

        Returns None on 404 or after exhausting retries (network / 5xx / 429).
        """
        assert self._session is not None, "Use as async context manager"
        sem = self._sem(url)
        for attempt in range(_MAX_RETRIES):
            async with sem:
                try:
                    async with self._session.post(url, json=payload) as resp:
                        if resp.status == 404:
                            return None
                        if resp.status == 429 or resp.status >= 500:
                            raise aiohttp.ClientResponseError(
                                resp.request_info,
                                resp.history,
                                status=resp.status,
                            )
                        resp.raise_for_status()
                        return await resp.json(content_type=None)
                except (aiohttp.ClientResponseError, aiohttp.ServerConnectionError) as exc:
                    status = getattr(exc, "status", 0)
                    if status == 404:
                        return None
                    if attempt == _MAX_RETRIES - 1:
                        return None
                    await asyncio.sleep(_BASE_BACKOFF * (2 ** attempt) + random.uniform(0, 0.3))
                except asyncio.TimeoutError:
                    if attempt == _MAX_RETRIES - 1:
                        return None
                    await asyncio.sleep(_BASE_BACKOFF * (2 ** attempt) + random.uniform(0, 0.3))
        return None

    async def url_exists(self, url: str) -> bool | None:
        """Return whether *url* resolves.

        - ``True``  : the server returned a success / redirect status.
        - ``False`` : the resource is definitively absent (404 / 410).
        - ``None``  : indeterminate (timeout, DNS error, 5xx after retries).

        The tri-state return lets callers avoid false positives: only a
        definitive ``False`` should be treated as "the declared URL is dead".
        """
        assert self._session is not None, "Use as async context manager"
        sem = self._sem(url)
        for attempt in range(_MAX_RETRIES):
            async with sem:
                try:
                    async with self._session.get(url, allow_redirects=True) as resp:
                        if resp.status in (404, 410):
                            return False
                        if resp.status == 429 or resp.status >= 500:
                            raise aiohttp.ClientResponseError(
                                resp.request_info,
                                resp.history,
                                status=resp.status,
                            )
                        return True
                except aiohttp.ClientResponseError as exc:
                    status = getattr(exc, "status", 0)
                    if status in (404, 410):
                        return False
                    if attempt == _MAX_RETRIES - 1:
                        return None
                    await asyncio.sleep(_BASE_BACKOFF * (2 ** attempt) + random.uniform(0, 0.3))
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    if attempt == _MAX_RETRIES - 1:
                        return None
                    await asyncio.sleep(_BASE_BACKOFF * (2 ** attempt) + random.uniform(0, 0.3))
        return None

    async def _get(
        self, url: str, *, as_json: bool, headers: dict[str, str] | None = None
    ) -> Any | None:
        assert self._session is not None, "Use as async context manager"
        cache_key = f"{'json' if as_json else 'text'}:{url}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        result = await self._get_uncached(url, as_json=as_json, headers=headers)
        self._cache[cache_key] = result
        return result

    async def _get_uncached(
        self, url: str, *, as_json: bool, headers: dict[str, str] | None = None
    ) -> Any | None:
        assert self._session is not None, "Use as async context manager"
        sem = self._sem(url)
        for attempt in range(_MAX_RETRIES):
            async with sem:
                try:
                    async with self._session.get(url, headers=headers) as resp:
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
