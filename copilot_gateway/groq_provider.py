"""Groq provider: primary tool-selection and orchestration model."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from groq import APIConnectionError, APIStatusError, AsyncGroq, RateLimitError

load_dotenv(Path(__file__).resolve().parent.parent / ".env", override=False)

_PRIMARY_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
_FALLBACK_MODEL = os.getenv("GROQ_FALLBACK_MODEL", "openai/gpt-oss-20b")
_MAX_RETRIES = 3
_BASE_BACKOFF = 2.0


def _get_client() -> AsyncGroq:
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError(
            "GROQ_API_KEY is not set. Set it in your .env file. Groq is required as the primary orchestration model."
        )
    return AsyncGroq(api_key=api_key, max_retries=0)


async def _call_with_retry(
    client: AsyncGroq,
    model: str,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None = None,
    tool_choice: str | dict | None = None,
    max_tokens: int = 4096,
) -> dict[str, Any]:
    """Call Groq chat completions with exponential backoff on 429/503."""
    for attempt in range(_MAX_RETRIES):
        try:
            kwargs: dict[str, Any] = {
                "model": model,
                "messages": messages,
                "max_tokens": max_tokens,
                "timeout": 60.0,
            }
            if tools:
                kwargs["tools"] = tools
            if tool_choice is not None:
                kwargs["tool_choice"] = tool_choice

            response = await client.chat.completions.create(**kwargs)
            return {
                "success": True,
                "model": model,
                "message": response.choices[0].message,
                "usage": {
                    "prompt_tokens": response.usage.prompt_tokens
                    if response.usage
                    else None,
                    "completion_tokens": response.usage.completion_tokens
                    if response.usage
                    else None,
                },
                "finish_reason": response.choices[0].finish_reason,
            }
        except RateLimitError:
            if attempt < _MAX_RETRIES - 1:
                wait = _BASE_BACKOFF ** (attempt + 1)
                await asyncio.sleep(wait)
                continue
            return {
                "success": False,
                "error": "Groq rate limit exceeded after retries",
                "model": model,
                "retryable": True,
            }
        except APIStatusError as exc:
            if exc.status_code in (503, 502, 504) and attempt < _MAX_RETRIES - 1:
                await asyncio.sleep(_BASE_BACKOFF ** (attempt + 1))
                continue
            return {
                "success": False,
                "error": f"Groq API error {exc.status_code}: {exc.message}",
                "model": model,
                "retryable": False,
            }
        except APIConnectionError as exc:
            return {
                "success": False,
                "error": f"Groq connection error: {exc}",
                "model": model,
                "retryable": False,
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "success": False,
                "error": f"Groq unexpected error: {type(exc).__name__}: {exc}",
                "model": model,
                "retryable": False,
            }
    return {"success": False, "error": "Max retries exceeded", "model": model}


async def groq_chat_with_tools(
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None = None,
    tool_choice: str | dict | None = None,
    max_tokens: int = 4096,
) -> dict[str, Any]:
    """Submit a chat completion request to Groq with tool-calling support and model fallback."""
    if not os.getenv("GROQ_API_KEY"):
        return {
            "success": False,
            "error": "GROQ_API_KEY not configured. Cannot proceed — Groq is the required orchestration model.",
            "model": _PRIMARY_MODEL,
        }

    client = _get_client()

    # Try primary model first
    result = await _call_with_retry(
        client, _PRIMARY_MODEL, messages, tools, tool_choice, max_tokens
    )
    if result["success"]:
        return result

    # Fall back to smaller model
    if result.get("retryable", True):
        fallback_result = await _call_with_retry(
            client, _FALLBACK_MODEL, messages, tools, tool_choice, max_tokens
        )
        if fallback_result["success"]:
            fallback_result["fallback_from"] = _PRIMARY_MODEL
            return fallback_result

    return result


def is_groq_available() -> bool:
    return bool(os.getenv("GROQ_API_KEY"))
