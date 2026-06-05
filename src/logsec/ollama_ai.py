import subprocess
import json

class OllamaTriage:
    def __init__(self, model="qwen2.5-coder:latest"):
        self.model = model
    
    def analyze(self, log_entry, mitre_techniques):
        prompt = f"""Analyze this Apache log. Return ONLY valid JSON:
{{"risk": "low/medium/high/critical", "action": "block/monitor/ignore", "summary": "one sentence"}}

Log: {log_entry}
MITRE techniques: {mitre_techniques}
"""
        try:
            result = subprocess.run(
                ["ollama", "run", self.model, prompt],
                capture_output=True, text=True, timeout=30
            )
            return result.stdout.strip()
        except Exception as e:
            return json.dumps({"error": str(e)})
