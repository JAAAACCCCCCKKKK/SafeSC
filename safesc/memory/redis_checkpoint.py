"""memory/redis_checkpoint.py — `PlainRedisSaver`, the Redis fallback checkpointer (CLAUDE.md §3.1).

Split out of ``memory/checkpoint.py`` because it subclasses LangGraph's `BaseCheckpointSaver`
and so needs the optional ``agent`` extra at import time, whereas the Postgres helpers there
do not. ``langgraph-checkpoint-redis`` indexes checkpoints with RediSearch (``FT.*``), which
Upstash and most managed Redis do not ship, so ``--resume`` never worked there. This saver
uses only hash, sorted-set, set and list commands, which every Redis-compatible service
supports. Checkpoints hold `AuditState`, which by §3.5 never carries a credential.
"""

from __future__ import annotations

import asyncio
import json
import random
from collections.abc import AsyncIterator, Iterator, Sequence
from typing import Any, Optional
from urllib.parse import quote, unquote

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.base import (
    WRITES_IDX_MAP,
    BaseCheckpointSaver,
    ChannelVersions,
    Checkpoint,
    CheckpointMetadata,
    CheckpointTuple,
    SerializerProtocol,
    get_checkpoint_id,
    get_checkpoint_metadata,
)

from safesc.memory.checkpoint import DEFAULT_CHECKPOINT_TTL_S


def _key(*parts: object) -> str:
    # Percent-encode every part: checkpoint namespaces contain ':' and '|', and encoding
    # also removes glob metacharacters, so scan patterns built from these stay literal.
    return ":".join(quote(str(p), safe="") for p in parts)


def _text(value: Any) -> str:
    return value.decode() if isinstance(value, bytes) else value


def _field(mapping: dict, name: str) -> Any:
    return mapping.get(name.encode(), mapping.get(name))


class PlainRedisSaver(BaseCheckpointSaver[str]):
    """LangGraph checkpointer using only plain Redis commands (no RediSearch).

    Storage mirrors `InMemorySaver`'s model, one Redis structure per in-memory map. Every
    key is under `prefix` and percent-encoded:

    * ``ckpt:{thread}:{ns}:{id}``        hash   — checkpoint, metadata, parent id
    * ``idx:{thread}:{ns}``              zset   — checkpoint ids, all score 0, so members sort
                                                  lexicographically; ids are time-ordered UUIDs
    * ``ns:{thread}``                    set    — the thread's checkpoint namespaces
    * ``blob:{thread}:{ns}:{ch}:{ver}``  hash   — one channel value per version
    * ``writes:{thread}:{ns}:{id}``      hash   — pending writes by (task, index)
    * ``order:{thread}:{ns}:{id}``       list   — write insertion order (hash order is undefined)

    Each write refreshes `ttl_s` on the keys it touches, so a thread stays resumable for
    `ttl_s` after its last checkpoint and then ages out with no GC job.
    """

    def __init__(
        self,
        client: Any,
        *,
        ttl_s: int = DEFAULT_CHECKPOINT_TTL_S,
        prefix: str = "lgckpt:",
        serde: Optional[SerializerProtocol] = None,
    ) -> None:
        super().__init__(serde=serde)
        self.client = client  # must NOT decode responses: serialized values are bytes
        self.ttl_s = ttl_s
        self.prefix = prefix

    @classmethod
    def from_url(
        cls,
        url: str,
        *,
        ttl_s: int = DEFAULT_CHECKPOINT_TTL_S,
        socket_timeout_s: float = 5.0,
    ) -> "PlainRedisSaver":
        try:
            import redis  # lazy: optional dependency
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise RuntimeError(
                "redis is not installed; install the 'memory' extra to enable checkpointing"
            ) from exc
        client = redis.Redis.from_url(url, decode_responses=False, socket_timeout=socket_timeout_s)
        return cls(client, ttl_s=ttl_s)

    # ------------------------------------------------------------------ keys

    def _k(self, kind: str, *parts: object) -> str:
        return f"{self.prefix}{kind}:{_key(*parts)}"

    def _expire(self, target: Any, *keys: str) -> None:
        if self.ttl_s and self.ttl_s > 0:
            for key in keys:
                target.expire(key, self.ttl_s)

    # ------------------------------------------------------------------ reads

    def _load_blobs(self, thread_id: str, ns: str, versions: ChannelVersions) -> dict[str, Any]:
        items = list(versions.items())
        if not items:
            return {}
        pipe = self.client.pipeline(transaction=False)
        for channel, version in items:
            pipe.hgetall(self._k("blob", thread_id, ns, channel, version))
        values: dict[str, Any] = {}
        for (channel, _), blob in zip(items, pipe.execute()):
            if not blob:
                continue
            kind = _text(_field(blob, "type"))
            if kind == "empty":
                continue
            values[channel] = self.serde.loads_typed((kind, _field(blob, "data")))
        return values

    def _load_writes(self, thread_id: str, ns: str, checkpoint_id: str) -> list[tuple[str, str, Any]]:
        order = self.client.lrange(self._k("order", thread_id, ns, checkpoint_id), 0, -1)
        fields = list(dict.fromkeys(order))  # concurrent writers could append a field twice
        if not fields:
            return []
        raw = self.client.hmget(self._k("writes", thread_id, ns, checkpoint_id), fields)
        writes = []
        for value in raw:
            if value is None:
                continue
            header, _, data = value.partition(b"\n")
            meta = json.loads(header)
            writes.append(
                (meta["task_id"], meta["channel"], self.serde.loads_typed((meta["type"], data)))
            )
        return writes

    def _tuple(self, thread_id: str, ns: str, checkpoint_id: str) -> Optional[CheckpointTuple]:
        saved = self.client.hgetall(self._k("ckpt", thread_id, ns, checkpoint_id))
        if not saved:
            return None
        checkpoint: Checkpoint = self.serde.loads_typed(
            (_text(_field(saved, "type")), _field(saved, "checkpoint"))
        )
        metadata = self.serde.loads_typed(
            (_text(_field(saved, "metadata_type")), _field(saved, "metadata"))
        )
        parent = _text(_field(saved, "parent")) or None
        return CheckpointTuple(
            config={
                "configurable": {
                    "thread_id": thread_id,
                    "checkpoint_ns": ns,
                    "checkpoint_id": checkpoint_id,
                }
            },
            checkpoint={
                **checkpoint,
                "channel_values": self._load_blobs(thread_id, ns, checkpoint["channel_versions"]),
            },
            metadata=metadata,
            parent_config=(
                {"configurable": {"thread_id": thread_id, "checkpoint_ns": ns, "checkpoint_id": parent}}
                if parent
                else None
            ),
            pending_writes=self._load_writes(thread_id, ns, checkpoint_id),
        )

    def get_tuple(self, config: RunnableConfig) -> Optional[CheckpointTuple]:
        thread_id = config["configurable"]["thread_id"]
        ns = config["configurable"].get("checkpoint_ns", "")
        checkpoint_id = get_checkpoint_id(config)
        if not checkpoint_id:
            latest = self.client.zrevrange(self._k("idx", thread_id, ns), 0, 0)
            if not latest:
                return None
            checkpoint_id = _text(latest[0])
        return self._tuple(thread_id, ns, checkpoint_id)

    def _thread_ids(self) -> Iterator[str]:
        marker = f"{self.prefix}ns:"
        for key in self.client.scan_iter(match=f"{marker}*"):
            yield unquote(_text(key)[len(marker):])

    def list(
        self,
        config: Optional[RunnableConfig],
        *,
        filter: Optional[dict[str, Any]] = None,
        before: Optional[RunnableConfig] = None,
        limit: Optional[int] = None,
    ) -> Iterator[CheckpointTuple]:
        thread_ids = [config["configurable"]["thread_id"]] if config else list(self._thread_ids())
        config_ns = config["configurable"].get("checkpoint_ns") if config else None
        config_id = get_checkpoint_id(config) if config else None
        before_id = get_checkpoint_id(before) if before else None
        for thread_id in thread_ids:
            namespaces = sorted(_text(n) for n in self.client.smembers(self._k("ns", thread_id)))
            for ns in namespaces:
                if config_ns is not None and ns != config_ns:
                    continue
                ids = [_text(i) for i in self.client.zrevrange(self._k("idx", thread_id, ns), 0, -1)]
                for checkpoint_id in ids:
                    if config_id and checkpoint_id != config_id:
                        continue
                    if before_id and checkpoint_id >= before_id:
                        continue
                    tup = self._tuple(thread_id, ns, checkpoint_id)
                    if tup is None:  # expired between the index read and this one
                        continue
                    if filter and not all(tup.metadata.get(k) == v for k, v in filter.items()):
                        continue
                    if limit is not None and limit <= 0:
                        return
                    if limit is not None:
                        limit -= 1
                    yield tup

    # ------------------------------------------------------------------ writes

    def put(
        self,
        config: RunnableConfig,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        new_versions: ChannelVersions,
    ) -> RunnableConfig:
        thread_id = config["configurable"]["thread_id"]
        ns = config["configurable"].get("checkpoint_ns", "")
        stored = checkpoint.copy()
        values: dict[str, Any] = stored.pop("channel_values")  # type: ignore[misc]
        pipe = self.client.pipeline(transaction=False)

        for channel, version in new_versions.items():
            kind, data = (
                self.serde.dumps_typed(values[channel]) if channel in values else ("empty", b"")
            )
            blob_key = self._k("blob", thread_id, ns, channel, version)
            pipe.hset(blob_key, mapping={"type": kind, "data": data})
            self._expire(pipe, blob_key)

        kind, data = self.serde.dumps_typed(stored)
        meta_kind, meta_data = self.serde.dumps_typed(get_checkpoint_metadata(config, metadata))
        ckpt_key = self._k("ckpt", thread_id, ns, checkpoint["id"])
        pipe.hset(
            ckpt_key,
            mapping={
                "type": kind,
                "checkpoint": data,
                "metadata_type": meta_kind,
                "metadata": meta_data,
                "parent": config["configurable"].get("checkpoint_id") or "",
            },
        )
        idx_key, ns_key = self._k("idx", thread_id, ns), self._k("ns", thread_id)
        pipe.zadd(idx_key, {checkpoint["id"]: 0})
        pipe.sadd(ns_key, ns)
        self._expire(pipe, ckpt_key, idx_key, ns_key)
        pipe.execute()
        return {
            "configurable": {
                "thread_id": thread_id,
                "checkpoint_ns": ns,
                "checkpoint_id": checkpoint["id"],
            }
        }

    def put_writes(
        self,
        config: RunnableConfig,
        writes: Sequence[tuple[str, Any]],
        task_id: str,
        task_path: str = "",
    ) -> None:
        thread_id = config["configurable"]["thread_id"]
        ns = config["configurable"].get("checkpoint_ns", "")
        checkpoint_id = config["configurable"]["checkpoint_id"]
        writes_key = self._k("writes", thread_id, ns, checkpoint_id)
        order_key = self._k("order", thread_id, ns, checkpoint_id)
        for idx, (channel, value) in enumerate(writes):
            write_idx = WRITES_IDX_MAP.get(channel, idx)
            field = _key(task_id, write_idx)
            kind, data = self.serde.dumps_typed(value)
            header = json.dumps(
                {"task_id": task_id, "channel": channel, "type": kind, "task_path": task_path}
            )
            record = header.encode() + b"\n" + data
            # Same rule as InMemorySaver: a regular write is kept once (a retried task must
            # not duplicate it); a special write (negative index: error, interrupt) replaces.
            if write_idx >= 0:
                added = self.client.hsetnx(writes_key, field, record)
            else:
                added = self.client.hset(writes_key, field, record)
            if added:
                self.client.rpush(order_key, field)
        self._expire(self.client, writes_key, order_key)

    def delete_thread(self, thread_id: str) -> None:
        ns_key = self._k("ns", thread_id)
        doomed = [ns_key]
        for raw_ns in self.client.smembers(ns_key):
            ns = _text(raw_ns)
            idx_key = self._k("idx", thread_id, ns)
            doomed.append(idx_key)
            for raw_id in self.client.zrange(idx_key, 0, -1):
                checkpoint_id = _text(raw_id)
                doomed += [
                    self._k("ckpt", thread_id, ns, checkpoint_id),
                    self._k("writes", thread_id, ns, checkpoint_id),
                    self._k("order", thread_id, ns, checkpoint_id),
                ]
        doomed += [
            _text(k)
            for k in self.client.scan_iter(match=f"{self.prefix}blob:{quote(thread_id, safe='')}:*")
        ]
        self.client.delete(*doomed)

    def get_next_version(self, current: Optional[str], channel: None) -> str:
        # Same scheme as InMemorySaver / PostgresSaver: zero-padded counter, random suffix.
        if current is None:
            current_v = 0
        elif isinstance(current, int):
            current_v = current
        else:
            current_v = int(current.split(".")[0])
        return f"{current_v + 1:032}.{random.random():016}"

    # ------------------------------------------------------------------ async
    # Network I/O, so the sync methods run in a worker thread rather than on the loop.

    async def aget_tuple(self, config: RunnableConfig) -> Optional[CheckpointTuple]:
        return await asyncio.to_thread(self.get_tuple, config)

    async def alist(
        self,
        config: Optional[RunnableConfig],
        *,
        filter: Optional[dict[str, Any]] = None,
        before: Optional[RunnableConfig] = None,
        limit: Optional[int] = None,
    ) -> AsyncIterator[CheckpointTuple]:
        items = await asyncio.to_thread(
            lambda: list(self.list(config, filter=filter, before=before, limit=limit))
        )
        for item in items:
            yield item

    async def aput(
        self,
        config: RunnableConfig,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        new_versions: ChannelVersions,
    ) -> RunnableConfig:
        return await asyncio.to_thread(self.put, config, checkpoint, metadata, new_versions)

    async def aput_writes(
        self,
        config: RunnableConfig,
        writes: Sequence[tuple[str, Any]],
        task_id: str,
        task_path: str = "",
    ) -> None:
        await asyncio.to_thread(self.put_writes, config, writes, task_id, task_path)

    async def adelete_thread(self, thread_id: str) -> None:
        await asyncio.to_thread(self.delete_thread, thread_id)
