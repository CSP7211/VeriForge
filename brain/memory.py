"""
Jarvis Memory System — Short-term and long-term memory for conversations.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

MEMORY_DIR = Path(__file__).parent.parent / "memory"
MEMORY_DIR.mkdir(parents=True, exist_ok=True)

MEMORY_FILE = MEMORY_DIR / "jarvis_memory.json"


class ConversationTurn:
    """A single turn in the conversation."""

    def __init__(self, role: str, content: str, intent: str = "", entities: Optional[Dict] = None):
        self.role = role  # 'user' or 'jarvis'
        self.content = content
        self.intent = intent
        self.entities = entities or {}
        self.timestamp = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "role": self.role,
            "content": self.content,
            "intent": self.intent,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ConversationTurn":
        turn = cls(data["role"], data["content"], data.get("intent", ""))
        turn.timestamp = data.get("timestamp", time.time())
        return turn


class Memory:
    """
    Jarvis memory system:
    - Short-term: Last 20 conversation turns (in-memory)
    - Long-term: User preferences, facts (persisted to JSON)
    - Session: Current context, active project
    """

    SHORT_TERM_LIMIT = 20

    def __init__(self):
        self._short_term: List[ConversationTurn] = []
        self._session: Dict[str, Any] = {
            "active_project": None,
            "active_scanner": "veriforge_security_scan",
            "last_scan_id": None,
            "preferences": {},
        }
        self._long_term: Dict[str, Any] = self._load_long_term()

    # ─── Short-term memory ─────────────────────────────────────────
    def add_turn(self, role: str, content: str, intent: str = "", entities: Optional[Dict] = None) -> None:
        """Add a conversation turn to short-term memory."""
        turn = ConversationTurn(role, content, intent, entities)
        self._short_term.append(turn)
        if len(self._short_term) > self.SHORT_TERM_LIMIT:
            self._short_term = self._short_term[-self.SHORT_TERM_LIMIT:]

    def get_recent_context(self, n: int = 5) -> List[Dict[str, str]]:
        """Get the last N turns as context for response generation."""
        return [{"role": t.role, "content": t.content} for t in self._short_term[-n:]]

    def get_conversation_history(self) -> List[Dict[str, Any]]:
        """Get full conversation history."""
        return [t.to_dict() for t in self._short_term]

    def clear_short_term(self) -> None:
        """Clear short-term memory (new conversation)."""
        self._short_term = []

    # ─── Session state ─────────────────────────────────────────────
    def get_session(self) -> Dict[str, Any]:
        return self._session.copy()

    def set_session(self, key: str, value: Any) -> None:
        self._session[key] = value

    def get_active_project(self) -> Optional[int]:
        return self._session.get("active_project")

    def set_active_project(self, project_id: int) -> None:
        self._session["active_project"] = project_id

    # ─── Long-term memory ──────────────────────────────────────────
    def _load_long_term(self) -> Dict[str, Any]:
        """Load long-term memory from disk."""
        if MEMORY_FILE.exists():
            try:
                with open(MEMORY_FILE) as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return {
            "user_name": None,
            "preferences": {},
            "learned_facts": {},
            "scan_count": 0,
            "created_at": time.time(),
        }

    def _save_long_term(self) -> None:
        """Persist long-term memory to disk."""
        try:
            with open(MEMORY_FILE, 'w') as f:
                json.dump(self._long_term, f, indent=2)
        except IOError:
            pass

    def get_preference(self, key: str, default: Any = None) -> Any:
        return self._long_term.get("preferences", {}).get(key, default)

    def set_preference(self, key: str, value: Any) -> None:
        if "preferences" not in self._long_term:
            self._long_term["preferences"] = {}
        self._long_term["preferences"][key] = value
        self._save_long_term()

    def set_user_name(self, name: str) -> None:
        self._long_term["user_name"] = name
        self._save_long_term()

    def get_user_name(self) -> Optional[str]:
        return self._long_term.get("user_name")

    def increment_scan_count(self) -> int:
        self._long_term["scan_count"] = self._long_term.get("scan_count", 0) + 1
        self._save_long_term()
        return self._long_term["scan_count"]

    def get_scan_count(self) -> int:
        return self._long_term.get("scan_count", 0)

    def learn_fact(self, key: str, value: Any) -> None:
        """Store a learned fact about the user or environment."""
        if "learned_facts" not in self._long_term:
            self._long_term["learned_facts"] = {}
        self._long_term["learned_facts"][key] = {
            "value": value,
            "learned_at": time.time(),
        }
        self._save_long_term()

    # ─── Memory summary ────────────────────────────────────────────
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of current memory state."""
        return {
            "short_term_turns": len(self._short_term),
            "user_name": self.get_user_name(),
            "scan_count": self.get_scan_count(),
            "active_project": self.get_active_project(),
            "session_keys": list(self._session.keys()),
            "preferences": self._long_term.get("preferences", {}),
            "learned_facts_count": len(self._long_term.get("learned_facts", {})),
        }


# Singleton
_memory: Optional[Memory] = None

def get_memory() -> Memory:
    global _memory
    if _memory is None:
        _memory = Memory()
    return _memory
