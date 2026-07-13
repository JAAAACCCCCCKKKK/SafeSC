"""entrypoints/api.py — the thin FastAPI surface (CLAUDE.md §1.3, §6.1.4).

Parses the request, assembles BYOK credentials from headers (§3.5), calls `graph.build.run`,
and shapes the HTTP response — no audit logic here. Routes: POST /audit (gated), POST /query
(evidence only, §1.3), POST /webhook (→ audit), GET /healthz. A missing LLM key is a 400;
keys are never logged or echoed.
"""

from __future__ import annotations

import logging
from typing import Optional

from credentials import MissingCredentialError, UserCredentials
from graph import build as graph_build
from graph.router import AuditRequest
from graph.state import RunMode, RunScope

logger = logging.getLogger("depaudit.api")

try:
    from fastapi import Depends, FastAPI, Header, HTTPException, Request
    from pydantic import BaseModel
except Exception:  # pragma: no cover - FastAPI optional at import time
    FastAPI = None  # type: ignore


# ---- request/response models (no secrets in either) -----------------------------


class AuditBody(BaseModel):
    target: str
    ecosystem: Optional[str] = None
    scope: Optional[RunScope] = None  # explicit override; never risk-derived (§2.2-A)
    include_report: bool = False      # embed the full canonical report (findings + evidence)


class QueryBody(BaseModel):
    target: str
    ecosystem: Optional[str] = None
    include_report: bool = False


class RunResponse(BaseModel):
    run_id: str
    passed: bool
    overall: str
    exit_code: int
    incomplete: bool
    summary: str
    per_dep: dict[str, str]
    report: Optional[dict] = None  # full AuditReport (§6) when include_report is set


# ---- credential intake from headers (BYOK) --------------------------------------


def credentials_from_headers(
    x_llm_api_key: Optional[str] = Header(default=None, alias="X-LLM-Api-Key"),
    x_llm_base_url: Optional[str] = Header(default=None, alias="X-LLM-Base-Url"),
    x_llm_model: Optional[str] = Header(default=None, alias="X-LLM-Model"),
    x_embedding_api_key: Optional[str] = Header(default=None, alias="X-Embedding-Api-Key"),
    x_embedding_base_url: Optional[str] = Header(default=None, alias="X-Embedding-Base-Url"),
    x_embedding_model: Optional[str] = Header(default=None, alias="X-Embedding-Model"),
) -> UserCredentials:
    try:
        return UserCredentials.from_request(
            llm_api_key=x_llm_api_key or "",
            llm_base_url=x_llm_base_url,
            llm_model=x_llm_model,
            embedding_api_key=x_embedding_api_key,
            embedding_base_url=x_embedding_base_url,
            embedding_model=x_embedding_model,
        )
    except MissingCredentialError as exc:
        # 400 with the *name* of the missing credential — never its value
        raise HTTPException(status_code=400, detail=str(exc))


def _to_response(result, *, include_report: bool = False) -> "RunResponse":
    gd = result.gate_decision
    report = None
    if include_report:
        # The reporter is a pure projection of the finished run (§6); building it here
        # never touches the gate outcome and holds no secrets (§3.5 invariant #3).
        from reporter import build_report

        report = build_report(result.final_state, run_id=result.run_id).model_dump()
    return RunResponse(
        run_id=result.run_id,
        passed=result.passed,
        overall=gd.overall.name,
        exit_code=result.exit_code,
        incomplete=result.incomplete,
        summary=gd.summary,
        per_dep={k: v.name for k, v in gd.per_dep.items()},
        report=report,
    )


def create_app(*, tools, session, memory=None, config=None, checkpointer=None) -> "FastAPI":
    """App factory. The audit machinery (tools/session/memory/checkpointer) is injected
    once at startup; per-request we only add the caller's BYOK credentials."""
    if FastAPI is None:  # pragma: no cover
        raise RuntimeError("fastapi is not installed")

    app = FastAPI(title="depaudit", version="2.5")

    def _run(req: AuditRequest, creds: UserCredentials):
        return graph_build.run(
            req, credentials=creds, tools=tools, session=session,
            memory=memory, config=config, checkpointer=checkpointer,
        )

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.post("/audit", response_model=RunResponse)
    def audit(body: AuditBody, creds: UserCredentials = Depends(credentials_from_headers)):
        req = AuditRequest(mode=RunMode.AUDIT, target=body.target, ecosystem=body.ecosystem, scope_override=body.scope)
        return _to_response(_run(req, creds), include_report=body.include_report)

    @app.post("/query", response_model=RunResponse)
    def query(body: QueryBody, creds: UserCredentials = Depends(credentials_from_headers)):
        req = AuditRequest(mode=RunMode.QUERY, target=body.target, ecosystem=body.ecosystem)
        return _to_response(_run(req, creds), include_report=body.include_report)

    @app.post("/webhook", response_model=RunResponse)
    async def webhook(request: Request, creds: UserCredentials = Depends(credentials_from_headers)):
        # Provider-specific signature verification belongs here (see §9 auth item).
        payload = await request.json()
        target = payload.get("repository", {}).get("clone_url") or payload.get("target") or "."
        req = AuditRequest(mode=RunMode.AUDIT, target=target)
        return _to_response(_run(req, creds))

    return app
