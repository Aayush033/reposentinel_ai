"""Gemini provider: synthesis and reasoning model using official google-genai SDK."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env", override=False)

_PRIMARY_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
_FALLBACK_MODEL = os.getenv("GEMINI_FALLBACK_MODEL", "gemini-3.5-flash-lite")
_MAX_RETRIES = 3
_BASE_BACKOFF = 2.0


async def gemini_synthesize(
    prompt: str,
    context: str | None = None,
    max_output_tokens: int = 8192,
) -> dict[str, Any]:
    """Use Gemini to synthesize and reason over gathered tool data into a coherent security report."""
    primary = os.getenv("GEMINI_MODEL", _PRIMARY_MODEL)
    fallback = os.getenv("GEMINI_FALLBACK_MODEL", _FALLBACK_MODEL)

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return {
            "success": False,
            "error": "GEMINI_API_KEY not configured. Falling back to Groq for synthesis.",
            "model": primary,
        }

    try:
        from google import genai
        from google.genai import types as genai_types
    except ImportError:
        return {
            "success": False,
            "error": "google-genai package not available.",
            "model": primary,
        }

    client = genai.Client(api_key=api_key)
    full_prompt = prompt if not context else f"{context}\n\n{prompt}"

    candidates = [primary] if fallback == primary else [primary, fallback]
    last_error = "Gemini synthesis failed."

    for model_id in candidates:
        for attempt in range(_MAX_RETRIES):
            try:
                response = await asyncio.to_thread(
                    client.models.generate_content,
                    model=model_id,
                    contents=full_prompt,
                    config=genai_types.GenerateContentConfig(
                        max_output_tokens=max_output_tokens,
                        temperature=0.1,
                    ),
                )
                text = (
                    response.text
                    if hasattr(response, "text") and response.text
                    else str(response)
                )
                return {
                    "success": True,
                    "model": model_id,
                    "text": text,
                }
            except Exception as exc:  # noqa: BLE001
                err_str = str(exc)
                last_error = (
                    f"Gemini {model_id} failed: {type(exc).__name__}: {err_str}"
                )
                is_transient = any(
                    kw in err_str.lower()
                    for kw in (
                        "429",
                        "quota",
                        "rate limit",
                        "resource_exhausted",
                        "503",
                        "502",
                        "unavailable",
                    )
                )
                if is_transient and attempt < _MAX_RETRIES - 1:
                    await asyncio.sleep(_BASE_BACKOFF ** (attempt + 1))
                    continue
                break

    return {
        "success": False,
        "error": f"{last_error}. Synthesis fell back to Groq.",
        "model": primary,
    }


def is_gemini_available() -> bool:
    return bool(os.getenv("GEMINI_API_KEY"))
