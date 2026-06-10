"""Gercek LLM adapter (Anthropic Claude). Kalkanin ARKASINDAKI model.

claude_llm(prompt) -> str   (ANTHROPIC_API_KEY .env'den)
"""
from __future__ import annotations

import os

from reasongate import embeddings  # noqa: F401  (.env yuklenmesini tetikler)

_client = None


def claude_llm(prompt: str, model: str = None, max_tokens: int = 600,
               system: str = None) -> str:
    global _client
    if _client is None:
        import anthropic
        key = os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise RuntimeError("ANTHROPIC_API_KEY yok (.env).")
        _client = anthropic.Anthropic(api_key=key)
    model = model or os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-6")
    kwargs = dict(model=model, max_tokens=max_tokens,
                  messages=[{"role": "user", "content": prompt}])
    if system:
        kwargs["system"] = system
    resp = _client.messages.create(**kwargs)
    return "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
