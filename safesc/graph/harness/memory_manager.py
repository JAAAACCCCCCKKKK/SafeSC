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


@dataclass(frozen=True)
class MemoryContext:
    """Immutable read snapshot handed to a specialist as prompt-only prior context."""

    artifact_id: str
    exact: Optional[dict] = None            # prior verdict for this exact hash (Redis)
    similar: tuple[dict, ...] = ()          # behaviourally-similar records (PGVector)

    def as_prior_findings(self) -> list[str]:
        out: list[str] = []
        if self.exact:
            out.append(f"[exact-hash prior] severity={self.exact.get('severity')} — {self.exact.get('summary','')}")
        for r in self.similar:
            out.append(f"[similar {r.get('artifact_id','?')}] severity={r.get('severity')} — {r.get('summary','')}")
        return out


@dataclass
class MemoryConfig:
    top_k: int = 3
    escalate_floor: Severity = Severity.MEDIUM       # >= this counts as "ever escalated"
    hot_ttl_s: int = 7 * 24 * 3600                   # Redis hot-record TTL (§3.1)
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
        similar: tuple[dict, ...] = ()
        if self.vector is not None and self.embedder is not None and query_text:
            try:
                vec = self.embedder([query_text])[0]
                hits = self.vector.query_similar(vec, self.config.top_k) or []
                # never return the exact record twice
                similar = tuple(h for h in hits if h.get("artifact_id") != artifact_key)
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

    # ------------------------------------------------------------------ write

    def persist(self, state: AuditState, gate: GateDecision) -> PersistReport:
        """Single write point, called at the tail of report_agent. Best-effort: a store
        failure is logged and skipped, never allowed to fail the gate."""
        report = PersistReport()
        for dep in state.dependencies:
            dk = dep_key(dep)
            severity = gate.per_dep.get(dk, Severity.CLEAN)
            key = artifact_id(dep)
            if not self._should_persist(dk, severity, state):
                report.skipped.append(key)
                continue
            record = self._build_record(dk, key, severity, state)
            try:
                self._upsert(key, record, report)
            except Exception as exc:
                logger.warning("persist failed for %s: %s", key, exc)
                report.skipped.append(key)
        return report

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

    def _upsert(self, key: str, record: dict, report: PersistReport) -> None:
        existing = self._get_any(key)
        if existing is not None:
            prev = int(existing.get("severity", 0))
            if record["severity"] < prev:
                # immutable hash ⇒ severity should only rise; a decrease is an anomaly
                report.anomalies.append(f"{key}: attempted {prev}→{record['severity']} (kept {prev})")
                record = {**record, "severity": prev}  # max-wins: keep the higher
        # hot exact record in Redis
        self._redis_set(key, record)
        # long-term vector record (needs an embedding)
        if self.vector is not None and self.embedder is not None:
            text = record["summary"] + "\n" + record.get("reasoning", "")
            try:
                vec = self.embedder([text])[0]
                self.vector.upsert(key, vec, record)
            except Exception as exc:
                logger.warning("vector upsert failed for %s: %s", key, exc)
        report.written.append(key)

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
