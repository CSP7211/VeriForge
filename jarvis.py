#!/usr/bin/env python3
"""
VeriForge Jarvis — Personal AI Assistant
The brain: intent routing, personality, memory, tool execution.

Usage:
    from jarvis import Jarvis
    j = Jarvis()
    response = j.process("scan this code for vulnerabilities", code="import os\nAPI_KEY='secret'")
    print(response.text)

    # Voice mode
    j.speak(response.text)

    # CLI mode
    python jarvis.py --cli
    python jarvis.py --voice
    python jarvis.py --web
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Add brain module to path
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent))

from brain.intent import get_router
from brain.personality import get_personality
from brain.memory import get_memory
from brain.handlers import get_executor


@dataclass
class JarvisResponse:
    """Structured response from Jarvis."""
    text: str
    intent: str = ""
    confidence: float = 0.0
    data: Dict[str, Any] = field(default_factory=dict)
    action_taken: bool = False


class Jarvis:
    """
    VeriForge Jarvis — Personal AI Security Assistant.

    Core loop: INPUT → Intent Classification → Tool Execution →
               Personality Formatting → Memory Storage → OUTPUT
    """

    VERSION = "1.0.0"

    def __init__(self):
        self.router = get_router()
        self.personality = get_personality()
        self.memory = get_memory()
        self.executor = get_executor()
        self._voice_available = False
        self._voice_engine = None
        self._detect_voice()

    def _detect_voice(self) -> None:
        """Detect if voice synthesis is available."""
        try:
            import pyttsx3
            self._voice_engine = pyttsx3.init()
            self._voice_engine.setProperty('rate', 175)
            self._voice_engine.setProperty('volume', 0.9)
            self._voice_available = True
        except ImportError:
            pass

    # ─── MAIN PROCESSING ───────────────────────────────────────────
    def process(self, message: str, **context) -> JarvisResponse:
        """
        Process a user message and return a structured response.

        Args:
            message: The user's text input
            **context: Additional context (code, project_id, etc.)

        Returns:
            JarvisResponse with text, intent, data
        """
        if not message or not message.strip():
            return JarvisResponse(
                text="I'm listening, sir. Please say something.",
                intent="conversation",
                confidence=1.0,
            )

        message = message.strip()

        # Store user turn in memory
        self.memory.add_turn("user", message)

        # Step 1: Intent classification
        intent, confidence, entities = self.router.classify(message)

        # Merge explicit context into entities
        if "code" in context and context["code"]:
            entities["code"] = context["code"]
        if "project_id" in context:
            entities["project_id"] = context["project_id"]

        # Step 2: Execute action based on intent
        result_data: Dict[str, Any] = {}
        action_taken = False

        try:
            if intent == "security_scan":
                result_data = self._handle_security_scan(entities)
                action_taken = True

            elif intent == "verify_code":
                result_data = self._handle_verify_code(entities)
                action_taken = True

            elif intent == "check_compliance":
                result_data = self._handle_check_compliance(entities)
                action_taken = True

            elif intent == "explain_finding":
                result_data = self._handle_explain_finding(entities)
                action_taken = True

            elif intent == "generate_spec":
                result_data = self._handle_generate_spec(entities)
                action_taken = True

            elif intent == "generate_tests":
                result_data = self._handle_generate_tests(entities)
                action_taken = True

            elif intent == "audit_chain":
                result_data = self._handle_audit_chain(entities)
                action_taken = True

            elif intent == "system_status":
                result_data = self.executor.get_status()
                action_taken = True

            elif intent == "help":
                result_data = {"intents": self.router.get_intent_list()}

            elif intent == "conversation":
                result_data = {"text": message}

            else:
                # Fallback: try to scan if it looks like code
                if len(message) > 20 and any(kw in message for kw in ('def ', 'import ', 'class ', '=', ';')):
                    result_data = self._handle_security_scan({"code": message})
                    intent = "security_scan"
                    action_taken = True
                else:
                    result_data = {"text": message}

        except Exception as exc:
            traceback.print_exc()
            response_text = self.personality.format_error(str(exc))
            self.memory.add_turn("jarvis", response_text, intent)
            return JarvisResponse(
                text=response_text,
                intent=intent,
                confidence=confidence,
                data={"error": str(exc)},
            )

        # Step 3: Format response with personality
        response_text = self.personality.format_tool_result(intent, result_data)

        # Step 4: Store assistant turn in memory
        self.memory.add_turn("jarvis", response_text, intent)

        return JarvisResponse(
            text=response_text,
            intent=intent,
            confidence=confidence,
            data=result_data,
            action_taken=action_taken,
        )

    # ─── HANDLERS ──────────────────────────────────────────────────
    def _handle_security_scan(self, entities: Dict[str, Any]) -> Dict[str, Any]:
        code = entities.get("code", "")
        if not code:
            return {"status": "error", "message": "No code provided. Please paste the code you'd like me to scan."}
        standard = entities.get("standard", "SOC2")
        result = self.executor.security_scan(code, standard)
        self.memory.increment_scan_count()
        return result

    def _handle_verify_code(self, entities: Dict[str, Any]) -> Dict[str, Any]:
        code = entities.get("code", "")
        if not code:
            return {"status": "error", "message": "No code provided for verification."}
        return self.executor.verify_code(code)

    def _handle_check_compliance(self, entities: Dict[str, Any]) -> Dict[str, Any]:
        code = entities.get("code", "")
        if not code:
            return {"status": "error", "message": "No code provided for compliance check."}
        standard = entities.get("standard", "SOC2")
        return self.executor.check_compliance(code, standard)

    def _handle_explain_finding(self, entities: Dict[str, Any]) -> Dict[str, Any]:
        finding_id = entities.get("finding_id", "")
        audience = entities.get("audience", "developer")
        if not finding_id:
            return {"status": "error", "message": "Please specify a CVE ID or finding to explain. For example: 'explain CVE-2024-002'"}
        return self.executor.explain_finding(finding_id, audience)

    def _handle_generate_spec(self, entities: Dict[str, Any]) -> Dict[str, Any]:
        description = entities.get("description", "")
        if not description:
            return {"status": "error", "message": "Please describe what you'd like a specification for."}
        language = entities.get("language", "python")
        return self.executor.generate_spec(description, language)

    def _handle_generate_tests(self, entities: Dict[str, Any]) -> Dict[str, Any]:
        spec = entities.get("spec", "")
        if not spec:
            return {"status": "error", "message": "Please provide a function or specification to generate tests for."}
        return self.executor.generate_tests(spec)

    def _handle_audit_chain(self, entities: Dict[str, Any]) -> Dict[str, Any]:
        entries = entities.get("entries", [])
        if not entries:
            return {"status": "error", "message": "Please provide audit entries as a comma-separated list."}
        return self.executor.audit_chain(entries)

    # ─── VOICE ─────────────────────────────────────────────────────
    def speak(self, text: str) -> bool:
        """Speak text using TTS. Returns True if spoken."""
        if not self._voice_available or not self._voice_engine:
            return False
        try:
            self._voice_engine.say(text)
            self._voice_engine.runAndWait()
            return True
        except Exception:
            return False

    def is_voice_available(self) -> bool:
        return self._voice_available

    # ─── MEMORY ACCESS ─────────────────────────────────────────────
    def get_memory_summary(self) -> Dict[str, Any]:
        return self.memory.get_summary()

    def get_conversation(self) -> List[Dict[str, Any]]:
        return self.memory.get_conversation_history()

    def clear_conversation(self) -> None:
        self.memory.clear_short_term()

    def set_user_name(self, name: str) -> None:
        self.memory.set_user_name(name)

    # ─── STATUS ────────────────────────────────────────────────────
    def get_status(self) -> Dict[str, Any]:
        return {
            "name": "VeriForge Jarvis",
            "version": self.VERSION,
            "voice": self._voice_available,
            "tools": self.executor.get_status(),
            "memory": self.get_memory_summary(),
        }


# ─── CLI MODE ──────────────────────────────────────────────────────
def run_cli():
    """Run Jarvis in interactive CLI mode."""
    jarvis = Jarvis()
    print("=" * 60)
    print("  VERIFORGE JARVIS v" + Jarvis.VERSION)
    print("  Personal AI Security Assistant")
    print("=" * 60)
    print()
    print(jarvis.personality.greet())
    print()
    print("Type 'help' for capabilities, 'quit' to exit.")
    print("-" * 60)

    while True:
        try:
            user_input = input("\n[You] ").strip()
            if not user_input:
                continue
            if user_input.lower() in ("quit", "exit", "bye"):
                print("\n[Jarvis] " + random.choice([
                    "Shutting down. Until next time, sir.",
                    "Powering off. Stay secure.",
                    "Goodbye. The perimeter remains guarded.",
                ]))
                break
            if user_input.lower() == "clear":
                jarvis.clear_conversation()
                print("[Jarvis] Conversation history cleared.")
                continue
            if user_input.lower() == "status":
                status = jarvis.get_status()
                print(f"[Jarvis] Voice: {'available' if status['voice'] else 'unavailable'}")
                print(f"         Tools: {status['tools']['mcp_tools']} MCP tools")
                print(f"         Scans run: {status['memory']['scan_count']}")
                continue

            resp = jarvis.process(user_input)
            print(f"\n[Jarvis] {resp.text}")

            if jarvis.is_voice_available():
                jarvis.speak(resp.text[:300])  # Limit TTS length

        except KeyboardInterrupt:
            print("\n\n[Jarvis] Interrupted. Goodbye.")
            break
        except EOFError:
            break


def run_voice_mode():
    """Run Jarvis in voice-only interactive mode."""
    jarvis = Jarvis()
    print("Voice mode activated. Speak your commands.")
    print("(Voice input requires additional setup - using text fallback)")
    run_cli()


def run_web_server():
    """Run Jarvis web API server."""
    try:
        from web.server import start_server
        start_server()
    except ImportError:
        print("Web server not available. Install fastapi and uvicorn.")
        sys.exit(1)


# ─── MAIN ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    import random

    parser = argparse.ArgumentParser(description="VeriForge Jarvis — Personal AI Assistant")
    parser.add_argument("--cli", action="store_true", help="Interactive CLI mode (default)")
    parser.add_argument("--voice", action="store_true", help="Voice interactive mode")
    parser.add_argument("--web", action="store_true", help="Web API server mode")
    parser.add_argument("--command", "-c", type=str, help="Single command mode")
    parser.add_argument("--code", type=str, help="Code to analyze (with --command)")
    parser.add_argument("--speak", action="store_true", help="Speak responses")
    args = parser.parse_args()

    if args.web:
        run_web_server()
    elif args.voice:
        run_voice_mode()
    elif args.command:
        j = Jarvis()
        ctx = {}
        if args.code:
            ctx["code"] = args.code
        resp = j.process(args.command, **ctx)
        print(resp.text)
        if args.speak:
            j.speak(resp.text[:300])
    else:
        run_cli()
