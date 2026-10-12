"""
claude_client.py — Shared wrapper around the Anthropic (Claude) API.

Why a wrapper?
* One place for retries, timeouts and logging.
* No sampling parameters are passed (current SDK/models don't accept them);
  consistency comes from the forced JSON schema below and from the rule-based
  floor in risk_classifier.py, not from temperature.
* Forces STRUCTURED output: every call defines a JSON schema as a "tool" and
  forces Claude to call it (tool_choice). The pipeline therefore always gets
  machine-validated JSON instead of free text it has to parse — critical in a
  compliance workflow where a malformed answer must never slip through.
"""

from __future__ import annotations

import base64
import time
from pathlib import Path
from typing import Any

import config

logger = config.get_logger("claude_client")


class ClaudeError(RuntimeError):
    """Raised when the Claude API cannot produce a valid structured answer."""


_client = None


def _get_client():
    global _client
    if _client is None:
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover
            raise ClaudeError("anthropic package not installed: pip install anthropic") from exc
        if not config.ANTHROPIC_API_KEY:
            raise ClaudeError("ANTHROPIC_API_KEY is not set")
        _client = anthropic.Anthropic(
            api_key=config.ANTHROPIC_API_KEY,
            timeout=config.CLAUDE_TIMEOUT_SECONDS,
            max_retries=config.CLAUDE_MAX_RETRIES,  # SDK retries 429/5xx with backoff
        )
    return _client


MEDIA_TYPES = {
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".gif": "image/gif",
}


def file_to_content_block(path: str | Path) -> dict:
    """Turn a PDF or image into a Claude content block (base64)."""
    path = Path(path)
    media_type = MEDIA_TYPES.get(path.suffix.lower())
    if media_type is None:
        raise ClaudeError(f"Unsupported file type: {path.suffix}")
    data = base64.standard_b64encode(path.read_bytes()).decode("ascii")
    block_type = "document" if media_type == "application/pdf" else "image"
    return {"type": block_type,
            "source": {"type": "base64", "media_type": media_type, "data": data}}


def call_structured(system: str, content: list[dict], tool_name: str,
                    tool_description: str, input_schema: dict,
                    max_tokens: int | None = None) -> dict[str, Any]:
    """Call Claude and force a JSON answer that matches `input_schema`.

    Returns {"result": <dict>, "model": str, "usage": {...}, "latency_ms": int}.
    """
    client = _get_client()
    started = time.perf_counter()
    try:
        response = client.messages.create(
            model=config.CLAUDE_MODEL,
            max_tokens=max_tokens or config.CLAUDE_MAX_TOKENS,
            system=system,
            tools=[{"name": tool_name, "description": tool_description,
                    "input_schema": input_schema}],
            tool_choice={"type": "tool", "name": tool_name},
            messages=[{"role": "user", "content": content}],
        )
    except Exception as exc:
        logger.error("Claude API call failed: %s", exc)
        raise ClaudeError(f"Claude API call failed: {exc}") from exc

    latency_ms = int((time.perf_counter() - started) * 1000)
    for block in response.content:
        if getattr(block, "type", None) == "tool_use" and block.name == tool_name:
            usage = getattr(response, "usage", None)
            logger.info("Claude %s ok in %d ms", tool_name, latency_ms)
            return {
                "result": dict(block.input),
                "model": response.model,
                "usage": {
                    "input_tokens": getattr(usage, "input_tokens", None),
                    "output_tokens": getattr(usage, "output_tokens", None),
                },
                "latency_ms": latency_ms,
            }
    raise ClaudeError(f"Claude did not return a {tool_name} tool call "
                      f"(stop_reason={response.stop_reason})")
