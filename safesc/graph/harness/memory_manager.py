"""graph/harness/memory_manager.py — the ONLY reader/writer of the §3 stores (§2.7.4).

Read: packages an exact-hash Redis record + top-k PGVector neighbours into an immutable
`MemoryContext`, injected as prompt-only prior findings — never merged into signals, so a
poisoned `clean` still can't buy a downgrade (§3.3). Write: one call at report_agent's tail,
keyed by `package@version+hash`, MAX-WINS on collision (decreases flagged), narrow scope.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Callable, Optional

from safesc.graph.state import AuditState, GateDecision, Severity, TrustDimension, dep_key

logger = logging.getLogger("safesc.memory")


def artifact_id(dep) -> str:
    """Immutable artifact identity used as the store key. Includes the hash when known —
    that's what makes recall 'exact-hash'."""
    h = getattr(dep, "hash", None)
    base = f"{dep.ecosystem}:{dep.name}@{dep.version}"
    return f"{base}+{h}" if h else base


def _query_text(task) -> str:
    """The similarity query for one fan-out task: what the deterministic signals actually
    observed, in the same register the fingerprint corpus is written in (§3.2). Bounded so
    one pathological evidence list can't dominate the embedding."""
    parts = [
        f"{getattr(getattr(task, 'dimension', None), 'value', '')} concern",
        " ".join(getattr(task, "trigger_sources", []) or []),
        " ".join(str(e) for e in (getattr(task, "trigger_evidence", []) or [])[:10]),
    ]
    return " ".join(p for p in parts if p.strip())[:600]


@dataclass(frozen=True)
class MemoryContext:
    """Immutable read snapshot handed to a specialist as prompt-only prior context."""

    artifact_id: str
    exact: Optional[dict] = None            # prior verdict for this exact hash (Redis)
    similar: tuple[dict, ...] = ()          # behaviourally-similar records (PGVector)

    def as_prior_findings(self) -> list[str]:
        """Render for the prompt. A curated known-attack fingerprint (§3.2) is labelled
        differently from a prior verdict: they warrant different reasoning — one says
        "this exact artifact was judged before", the other says "this resembles a
        documented attack pattern" — and a specialist that cannot tell them apart will
        cite the wrong thing. Both remain context only (§3.3)."""
        from safesc.memory.fingerprints import fingerprint_id, is_fingerprint

        out: list[str] = []
        if self.exact:
            out.append(f"[exact-hash prior] severity={self.exact.get('severity')} — {self.exact.get('summary','')}")
        for r in self.similar:
            if is_fingerprint(r):
                out.append(
                    f"[known-attack pattern {fingerprint_id(r)}] severity={r.get('severity')} "
                    f"— {r.get('summary','')}"
                )
            else:
                out.append(f"[similar {r.get('artifact_id','?')}] severity={r.get('severity')} — {r.get('summary','')}")
        return out


@dataclass
class MemoryConfig:
    top_k: int = 3
    escalate_floor: Severity = Severity.MEDIUM       # >= this counts as "ever escalated"
    hot_ttl_s: int = 7 * 24 * 3600                   # Redis hot-record TTL (§3.1)
    # Texts per embedding request on the write path. Providers cap batch size
    # (Voyage's limit is 128), so this chunks rather than sending one unbounded request.
    embed_batch_size: int = 128
    # override to plug a deployment's real popularity signal (§2.7.4 write scope (b))
    is_high_popularity: Callable[[str, AuditState], bool] = field(default=None)  # type: ignore


@dataclass
class PersistReport:
    written: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)  # attempted severity decreases


class MemoryManager:
    def __init__(self, *, redis=None, vector=None, embedder=None, config: Optional[MemoryConfig] = None):
        self.redis = redis
        self.vector = vector
        self.embedder = embedder
        self.config = config or MemoryConfig()

    # ------------------------------------------------------------------ read

    def read_context(self, artifact_key: str, query_text: str = "") -> MemoryContext:
        exact = self._redis_get(artifact_key)
        logger.debug(
            "memory read: exact %s for %s%s",
            "hit" if exact is not None else "miss",
            artifact_key,
            f" (severity={exact.get('severity')})" if exact is not None else "",
        )
        similar: tuple[dict, ...] = ()
        if self.vector is None or self.embedder is None or not query_text:
            logger.debug(
                "memory read: similarity skipped for %s (vector=%s embedder=%s query_text=%s)",
                artifact_key, self.vector is not None, self.embedder is not None, bool(query_text),
            )
        else:
            try:
                vec = self.embedder([query_text])[0]
                hits = self.vector.query_similar(vec, self.config.top_k) or []
                # never return the exact record twice
                similar = tuple(h for h in hits if h.get("artifact_id") != artifact_key)
                logger.debug(
                    "memory read: %d similar record(s) for %s (top_k=%d, %d raw hit(s))",
                    len(similar), artifact_key, self.config.top_k, len(hits),
                )
            except Exception as exc:
                logger.warning("similarity query failed for %s: %s", artifact_key, exc)
        return MemoryContext(artifact_id=artifact_key, exact=exact, similar=similar)

    def make_lookup(self, resolve: Callable[[str], tuple[str, str]]) -> Callable[[str], list[str]]:
        """Adapt to the specialists' `memory_lookup(dep_key) -> list[str]` seam.
        `resolve(dep_key) -> (artifact_key, query_text)` maps the graph's dep key to the
        store identity + a similarity query string (typically a static-signal summary)."""
        def _lookup(dk: str) -> list[str]:
            try:
                artifact_key, query_text = resolve(dk)
            except Exception:
                artifact_key, query_text = dk, ""
            return self.read_context(artifact_key, query_text).as_prior_findings()

        return _lookup

    def make_task_lookup(self) -> Callable[..., list[str]]:
        """The `memory_lookup` the graph actually wires (§2.7.4 read path).

        Signature is `(dep_key, *, task=None)`: the specialist offers the whole
        `SpecialistTask` as a keyword, and that is what makes recall work at all. A dep_key
        is `ecosystem:name@version`, but `persist` writes under `artifact_id(dep)` —
        `ecosystem:name@version+hash` — so a dep_key lookup misses the exact record for
        every dependency that has a hash, i.e. the entire point of exact-hash recall. The
        task carries `dependency` (hash included), so the read key can be derived the same
        way the write key was.

        It also supplies a *behavioural* similarity query (`_query_text`) instead of the
        package name. Embedding "npm:foo@1.0.0" retrieves packages with similar names,
        which is the identity dimension's job and is already deterministic (§4.4); what the
        vector store is for is finding artifacts that *behave* alike, including the curated
        attack fingerprints (§3.2), and that needs the signal text as the query.

        Without a task it degrades to the dep_key form rather than failing — a caller that
        cannot supply one still gets whatever exact record exists under that key.
        """
        def _lookup(dep_key_str: str, *, task=None) -> list[str]:
            dep = getattr(task, "dependency", None) if task is not None else None
            if dep is None:
                logger.debug(
                    "memory read: no task supplied for %s; falling back to dep_key lookup "
                    "(exact-hash recall degrades for hashed deps)", dep_key_str,
                )
                return self.read_context(str(dep_key_str), "").as_prior_findings()
            return self.read_context(artifact_id(dep), _query_text(task)).as_prior_findings()

        return _lookup

    # ------------------------------------------------------------------ write

    def persist(self, state: AuditState, gate: GateDecision) -> PersistReport:
        """Single write point, called at the tail of report_agent. Best-effort: a store
        failure is logged and skipped, never allowed to fail the gate.

        Two phases, because embedding is a *network* call and the rest is not. Phase 1
        resolves max-wins and writes every hot Redis record; phase 2 embeds all pending
        texts in batched calls and writes the vectors. Embedding per dependency issues one
        request per dep (76 on a mid-size repo), which providers rate-limit aggressively
        — a free-tier 3 RPM ceiling fails nearly all of them. ``Embedder`` is typed
        ``list[str] -> list[list[float]]`` precisely so this can be one call.
        """
        report = PersistReport()
        pending: list[tuple[str, dict, str]] = []  # (key, record, text-to-embed)
        for dep in state.dependencies:
            dk = dep_key(dep)
            severity = gate.per_dep.get(dk, Severity.CLEAN)
            key = artifact_id(dep)
            if not self._should_persist(dk, severity, state):
                logger.debug("memory write: skipping %s (severity=%s, below write scope)", key, severity)
                report.skipped.append(key)
                continue
            record = self._build_record(dk, key, severity, state)
            try:
                text = self._write_hot(key, record, report)
            except Exception as exc:
                logger.warning("persist failed for %s: %s", key, exc)
                report.skipped.append(key)
                continue
            report.written.append(key)
            logger.debug(
                "memory write: hot record %s severity=%s (vector pending=%s)",
                key, record["severity"], text is not None,
            )
            if text is not None:
                pending.append((key, record, text))
        self._write_vectors(pending)
        logger.info(
            "memory persist: %d written, %d skipped, %d anomaly(ies)",
            len(report.written), len(report.skipped), len(report.anomalies),
        )
        for anomaly in report.anomalies:
            logger.warning("memory anomaly: %s", anomaly)
        return report

    def _write_vectors(self, pending: "list[tuple[str, dict, str]]") -> None:
        """Embed the pending records in batches, then upsert each. Best-effort at batch
        granularity: if a batch's embedding call fails, the hot Redis records already
        written stand and only the vector half is lost — which costs grounding, never
        correctness (§3.3)."""
        if not pending or self.vector is None or self.embedder is None:
            logger.debug("memory write: no vectors to embed (%d record(s) pending)", len(pending))
            return
        size = max(1, self.config.embed_batch_size)
        batches = -(-len(pending) // size)  # ceil div, for the log line only
        for i, start in enumerate(range(0, len(pending), size), start=1):
            chunk = pending[start:start + size]
            try:
                vectors = self.embedder([text for _, _, text in chunk])
            except Exception as exc:
                logger.warning(
                    "embedding failed for %d record(s) starting at %s: %s",
                    len(chunk), chunk[0][0], exc,
                )
                continue
            if len(vectors) != len(chunk):
                logger.warning(
                    "embedder returned %d vector(s) for %d text(s); skipping vector upsert",
                    len(vectors), len(chunk),
                )
                continue
            upserted = 0
            for (key, record, _), vec in zip(chunk, vectors):
                try:
                    self.vector.upsert(key, vec, record)
                    upserted += 1
                except Exception as exc:
                    logger.warning("vector upsert failed for %s: %s", key, exc)
            logger.debug(
                "memory write: batch %d/%d embedded and upserted %d/%d record(s)",
                i, batches, upserted, len(chunk),
            )

    def _should_persist(self, dk: str, severity: Severity, state: AuditState) -> bool:
        if severity >= self.config.escalate_floor:
            return True  # (a) anything ever escalated
        if self._high_popularity(dk, state):
            return True  # (b) clean/benign confirmation for a high-popularity package
        return False     # long-tail first-seen benign → not cached

    def _high_popularity(self, dk: str, state: AuditState) -> bool:
        if self.config.is_high_popularity is not None:
            return bool(self.config.is_high_popularity(dk, state))
        # default proxy: the popularity dimension was checked and came back benign
        pop = [s for s in state.signals if s.dep_key == dk and s.dimension == TrustDimension.POPULARITY]
        return bool(pop) and all(s.severity <= Severity.LOW for s in pop)

    def _build_record(self, dk: str, key: str, severity: Severity, state: AuditState) -> dict:
        sigs = state.signals_for(dk)
        top = max(sigs, key=lambda s: s.severity, default=None)
        summary = (top.summary or top.source) if top else "clean"
        evidence = [e for s in sigs for e in s.evidence][:20]
        return {
            "artifact_id": key,
            "severity": int(severity),
            "summary": summary[:280],
            "evidence": evidence,
            "reasoning": (top.reasoning if top else "")[:1000],
        }

    def _write_hot(self, key: str, record: dict, report: PersistReport) -> "Optional[str]":
        """Resolve max-wins against any stored record and write the hot Redis entry.

        Returns the text to embed when a vector store is configured, else None. Severity
        is corrected on ``record`` in place, so the vector half persists the same severity
        the hot half did.
        """
        existing = self._get_any(key)
        if existing is not None:
            prev = int(existing.get("severity", 0))
            if record["severity"] < prev:
                # immutable hash ⇒ severity should only rise; a decrease is an anomaly
                report.anomalies.append(
                    f"{key}: attempted {prev}→{record['severity']} (kept {prev})"
                )
                record["severity"] = prev  # max-wins: keep the higher
        # hot exact record in Redis
        self._redis_set(key, record)
        # the long-term vector record is written later, in one batched pass
        if self.vector is None or self.embedder is None:
            return None
        return record["summary"] + "\n" + record.get("reasoning", "")

    # ------------------------------------------------------------------ maintenance

    def gc(self, **kwargs) -> dict:
        """Differentiated long-term retention (§3.4), invoked only by `safesc gc` — never
        by a graph node. Delegated to the vector store so store access stays centralised in
        this one component (§6.1.6). Redis short-term is TTL-only and needs no sweep."""
        if self.vector is None or not hasattr(self.vector, "gc"):
            return {"deleted": 0, "note": "no vector store / TTL-only retention"}
        return self.vector.gc(**kwargs)

    # ------------------------------------------------------------------ store shims

    def _redis_get(self, key: str) -> Optional[dict]:
        if self.redis is None:
            return None
        try:
            raw = self.redis.get(f"mem:{key}")
            return json.loads(raw) if raw else None
        except Exception:
            return None

    def _redis_set(self, key: str, record: dict) -> None:
        if self.redis is None:
            return
        try:
            self.redis.set(f"mem:{key}", json.dumps(record), ex=self.config.hot_ttl_s)
        except Exception as exc:
            logger.warning("redis set failed for %s: %s", key, exc)

    def _get_any(self, key: str) -> Optional[dict]:
        rec = self._redis_get(key)
        if rec is not None:
            return rec
        if self.vector is not None:
            try:
                return self.vector.get(key)
            except Exception:
                return None
        return None
