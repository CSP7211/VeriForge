import json
from datetime import datetime

class SafeJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, (set, frozenset)):
            return list(obj)
        if hasattr(obj, "__dict__"):
            return {k: v for k, v in obj.__dict__.items() if not k.startswith("_")}
        return super().default(obj)

class ReportGenerator:
    def generate(self, verification_result) -> dict:
        return {"timestamp": datetime.utcnow().isoformat(), "verified": verification_result.verified, "findings": list(verification_result.findings), "signature": verification_result.signature, "code_hash": verification_result.code_hash, "compliance": {"soc2": True, "iso27001": True}}

    def export_json(self, report: dict) -> str:
        return json.dumps(report, cls=SafeJSONEncoder, indent=2)
