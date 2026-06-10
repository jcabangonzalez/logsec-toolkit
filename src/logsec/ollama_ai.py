import json
import subprocess

import requests

_OLLAMA_BASE = "http://localhost:11434"


class OllamaTriage:
    def __init__(self, model: str = "qwen2.5-coder:latest"):
        self.model = model

    def analyze(self, log_entry: str, mitre_techniques: list) -> str:
        """Per-entry triage — returns a raw JSON string."""
        prompt = (
            "Analyze this Apache log entry and return ONLY valid JSON, no other text:\n"
            '{"risk": "low|medium|high|critical", "action": "block|monitor|ignore", "summary": "one sentence"}\n\n'
            f"Log: {log_entry}\n"
            f"MITRE techniques: {mitre_techniques}\n"
        )
        return _call_ollama(self.model, prompt, system="Return only valid JSON, no markdown.")

    def triage_batch(self, entries: list, prompt: str) -> list:
        """Batch triage using the shared build_prompt format. Returns a parsed list."""
        system = (
            "You are a Senior Cybersecurity Analyst. "
            "Respond ONLY with a valid JSON array, no markdown, no explanation."
        )
        raw = _call_ollama(self.model, prompt, system=system)
        text = raw.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return parsed
        return [parsed]


def _call_ollama(model: str, prompt: str, system: str = "") -> str:
    """Call Ollama REST API; fall back to subprocess if the server is unreachable."""
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    try:
        resp = requests.post(
            f"{_OLLAMA_BASE}/api/chat",
            json={"model": model, "messages": messages, "stream": False, "format": "json"},
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json()["message"]["content"]
    except requests.exceptions.ConnectionError:
        pass  # fall through to subprocess
    except Exception as exc:
        return json.dumps({"error": str(exc)})

    # Subprocess fallback (Ollama server not running but CLI is available)
    try:
        full_prompt = f"{system}\n\n{prompt}" if system else prompt
        result = subprocess.run(
            ["ollama", "run", model, full_prompt],
            capture_output=True, text=True, timeout=60,
        )
        return result.stdout.strip()
    except Exception as exc:
        return json.dumps({"error": str(exc)})
