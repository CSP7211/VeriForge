from .engine import VeriForgeEngine

class AgentVerifier:
    def __init__(self, config):
        self.config = config
        self.engine = VeriForgeEngine(config)

    def verify_agent_task(self, task_id: str, task_data: dict) -> dict:
        code = task_data.get("code", "")
        result = self.engine.verify_code(code)
        return {"task_id": task_id, "verified": result.verified, "findings": result.findings, "signature": result.signature, "code_hash": result.code_hash}
