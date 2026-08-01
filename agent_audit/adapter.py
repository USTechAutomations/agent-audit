"""Target-agent adapters.

A *target* is the agent under audit. v1 supports OpenAI-compatible chat endpoints
(vLLM, Ollama, LM Studio, TGI, a gateway, or a hosted provider — what most deployed
agents already sit behind).

The adapter contract is deliberately tiny — one method, `run_case` — so that future
adapter types (webhook, CLI subprocess, MCP) can be added without touching the battery
or the evidence store. Adapter transport failures are surfaced as AdapterError, which
the runner records as an `error` outcome; they are never silently swallowed and never
invisibly retried (the runner does exactly one recorded retry on timeout).
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Protocol


class AdapterError(RuntimeError):
    """Transport/protocol failure talking to a target. Recorded, never hidden."""


@dataclass(frozen=True)
class TargetConfig:
    """Immutable description of an agent under audit."""

    target_id: str
    base_url: str
    model: str
    system_prompt: str
    temperature: float = 0.0
    max_tokens: int = 1024
    seed: int | None = None
    api_key_env: str | None = None
    timeout_s: float = 120.0

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "TargetConfig":
        required = ("target_id", "base_url", "model", "system_prompt")
        missing = [k for k in required if k not in d or d[k] in (None, "")]
        if missing:
            raise ValueError(f"target config missing required fields: {missing}")
        s = d.get("sampling", {})
        return TargetConfig(
            target_id=str(d["target_id"]),
            base_url=str(d["base_url"]).rstrip("/"),
            model=str(d["model"]),
            system_prompt=str(d["system_prompt"]),
            temperature=float(s.get("temperature", d.get("temperature", 0.0))),
            max_tokens=int(s.get("max_tokens", d.get("max_tokens", 1024))),
            seed=s.get("seed", d.get("seed")),
            api_key_env=d.get("api_key_env"),
            timeout_s=float(d.get("timeout_s", 120.0)),
        )

    def fingerprint(self) -> dict[str, Any]:
        """Identity of the target for sealing — excludes any secret material.

        The api_key VALUE is never included (only the env var name), and base_url is
        kept because it is part of what was audited. system_prompt is hashed, not
        stored verbatim in the fingerprint, so planted canaries do not leak into the
        manifest; the full prompt still lives in the sealed per-case blob.
        """
        import hashlib

        return {
            "target_id": self.target_id,
            "base_url": self.base_url,
            "model": self.model,
            "system_prompt_sha256": hashlib.sha256(
                self.system_prompt.encode("utf-8")
            ).hexdigest(),
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "seed": self.seed,
        }


@dataclass
class AdapterResponse:
    """What the target said, plus the raw exchange for sealing."""

    content: str
    reasoning: str = ""
    raw_request: dict[str, Any] = field(default_factory=dict)
    raw_response: dict[str, Any] = field(default_factory=dict)
    latency_ms: int = 0

    def visible_text(self) -> str:
        """Everything a consumer of the API can read: answer + exposed reasoning.

        A canary leaking into the reasoning channel is still a leak — the endpoint
        returns it — so checkers scan this combined text.
        """
        if self.reasoning:
            return f"{self.content}\n\n[reasoning]\n{self.reasoning}"
        return self.content


class AgentAdapter(Protocol):
    """The one-method contract every target type implements."""

    def run_case(self, messages: list[dict[str, str]]) -> AdapterResponse: ...


class OpenAICompatAdapter:
    """Calls an OpenAI-compatible /v1/chat/completions endpoint via urllib (stdlib)."""

    def __init__(self, config: TargetConfig) -> None:
        self.config = config

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.config.api_key_env:
            key = os.environ.get(self.config.api_key_env, "")
            if key:
                headers["Authorization"] = f"Bearer {key}"
        return headers

    def run_case(self, messages: list[dict[str, str]]) -> AdapterResponse:
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }
        if self.config.seed is not None:
            payload["seed"] = self.config.seed

        url = f"{self.config.base_url}/v1/chat/completions"
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=body, headers=self._headers(), method="POST"
        )
        started = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout_s) as resp:
                raw = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:500]
            raise AdapterError(f"HTTP {exc.code} from target: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise AdapterError(f"transport error to target: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise AdapterError(f"target returned non-JSON: {exc}") from exc

        latency_ms = int((time.monotonic() - started) * 1000)
        try:
            message = raw["choices"][0]["message"]
            content = message.get("content") or ""
            reasoning = message.get("reasoning") or ""
        except (KeyError, IndexError, TypeError) as exc:
            raise AdapterError(f"unexpected response shape: {exc}") from exc

        return AdapterResponse(
            content=content,
            reasoning=reasoning,
            raw_request=payload,
            raw_response=raw,
            latency_ms=latency_ms,
        )
