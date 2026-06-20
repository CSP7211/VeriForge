"""
Jarvis Web API Server — Lightweight FastAPI server for the web companion.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Dict

sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from jarvis import Jarvis

app = FastAPI(title="Jarvis API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Shared Jarvis instance
_jarvis: Jarvis | None = None

def get_jarvis() -> Jarvis:
    global _jarvis
    if _jarvis is None:
        _jarvis = Jarvis()
    return _jarvis


class ChatRequest(BaseModel):
    message: str
    code: str = ""
    project_id: int = 1


class CommandRequest(BaseModel):
    command: str  # scan, compliance, explain, spec, tests, audit, status, clear
    code: str = ""
    finding_id: str = ""
    standard: str = "SOC2"
    description: str = ""


@app.get("/api/health")
def health():
    return {"status": "ok", "name": "Jarvis", "version": "1.0.0", "time": time.time()}


@app.get("/api/status")
def status():
    return get_jarvis().get_status()


@app.post("/api/chat")
def chat(req: ChatRequest):
    j = get_jarvis()
    ctx = {}
    if req.code:
        ctx["code"] = req.code
    if req.project_id:
        ctx["project_id"] = req.project_id

    resp = j.process(req.message, **ctx)
    return {
        "text": resp.text,
        "intent": resp.intent,
        "confidence": resp.confidence,
        "action_taken": resp.action_taken,
        "data": _serialize(resp.data),
    }


@app.post("/api/command")
def command(req: CommandRequest):
    j = get_jarvis()
    message_map = {
        "scan": f"scan this code",
        "verify": "verify this code",
        "compliance": f"check compliance against {req.standard}",
        "explain": f"explain {req.finding_id}",
        "spec": f"generate spec for: {req.description}",
        "tests": f"generate tests for: {req.description or req.code}",
        "audit": f"create audit chain",
        "status": "system status",
        "help": "what can you do",
        "clear": "clear",
    }
    message = message_map.get(req.command, req.command)
    resp = j.process(message, code=req.code)
    return {
        "text": resp.text,
        "intent": resp.intent,
        "confidence": resp.confidence,
        "data": _serialize(resp.data),
    }


@app.get("/api/conversation")
def get_conversation():
    return {"conversation": get_jarvis().get_conversation()}


@app.post("/api/conversation/clear")
def clear_conversation():
    get_jarvis().clear_conversation()
    return {"status": "cleared"}


@app.get("/api/intents")
def get_intents():
    return {"intents": get_jarvis().router.get_intent_list()}


def _serialize(data: Dict[str, Any]) -> Dict[str, Any]:
    """Serialize data to JSON-safe dict."""
    try:
        return json.loads(json.dumps(data, default=str))
    except (TypeError, ValueError):
        return {"raw": str(data)[:500]}


def start_server(host: str = "0.0.0.0", port: int = 8765):
    import uvicorn
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    start_server()
