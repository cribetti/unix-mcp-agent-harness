"""Model-agnostic LLM provider configuration and OpenAI-compatible client factory.

Supports seamless switching between local Ollama, self-hosted vLLM/TGI, and enterprise
OpenAI-compatible gateways (AWS Bedrock, GCP Vertex AI, Azure OpenAI, OpenRouter, or
custom VPC proxies) via environment variables, YAML config files, or CLI flags.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import os
import re
from typing import Any, Iterable, Mapping
from urllib.parse import urlparse

from openai import OpenAI

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover - stdlib fallback handles minimal containers
    yaml = None


class ProviderAPIError(RuntimeError):
    """Sanitized LLM provider/HTTP error that never exposes API keys or credentials."""


@dataclass(frozen=True)
class ProviderPreset:
    name: str
    default_base_url: str
    default_model: str
    default_api_key: str
    requires_api_key: bool
    supports_reasoning_effort: bool = False
    extra_headers: dict[str, str] = field(default_factory=dict)


PROVIDER_PRESETS: dict[str, ProviderPreset] = {
    "ollama": ProviderPreset(
        name="ollama",
        default_base_url="http://localhost:11434/v1",
        default_model="qwen3:8b",
        default_api_key="ollama",
        requires_api_key=False,
        supports_reasoning_effort=True,
    ),
    "vllm": ProviderPreset(
        name="vllm",
        default_base_url="http://localhost:8000/v1",
        default_model="Qwen/Qwen2.5-Coder-7B-Instruct",
        default_api_key="EMPTY",
        requires_api_key=False,
        supports_reasoning_effort=False,
    ),
    "openai": ProviderPreset(
        name="openai",
        default_base_url="https://api.openai.com/v1",
        default_model="gpt-4o-mini",
        default_api_key="",
        requires_api_key=True,
        supports_reasoning_effort=False,
    ),
    "openai_compatible": ProviderPreset(
        name="openai_compatible",
        default_base_url="",
        default_model="",
        default_api_key="",
        requires_api_key=True,
        supports_reasoning_effort=False,
    ),
    "openrouter": ProviderPreset(
        name="openrouter",
        default_base_url="https://openrouter.ai/api/v1",
        default_model="qwen/qwen-2.5-coder-32b-instruct",
        default_api_key="",
        requires_api_key=True,
        supports_reasoning_effort=False,
        extra_headers={"X-Title": "unix-mcp-agent-harness"},
    ),
    "bedrock": ProviderPreset(
        name="bedrock",
        default_base_url="",
        default_model="anthropic.claude-3-5-sonnet-20241022-v2:0",
        default_api_key="",
        requires_api_key=True,
        supports_reasoning_effort=False,
    ),
    "vertex": ProviderPreset(
        name="vertex",
        default_base_url="",
        default_model="google/gemini-2.5-pro",
        default_api_key="",
        requires_api_key=True,
        supports_reasoning_effort=False,
    ),
    "azure": ProviderPreset(
        name="azure",
        default_base_url="",
        default_model="gpt-4o",
        default_api_key="",
        requires_api_key=True,
        supports_reasoning_effort=False,
    ),
}

PROVIDER_ALIASES: dict[str, str] = {
    "local": "ollama",
    "tgi": "vllm",
    "custom": "openai_compatible",
    "openai-compatible": "openai_compatible",
    "aws_bedrock": "bedrock",
    "aws-bedrock": "bedrock",
    "gcp_vertex": "vertex",
    "gcp-vertex": "vertex",
    "vertex_ai": "vertex",
    "vertex-ai": "vertex",
    "azure_openai": "azure",
    "azure-openai": "azure",
}

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "host.docker.internal", "ollama", "vllm"}
_ENV_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")
_NON_SECRET_PLACEHOLDERS = {"", "ollama", "EMPTY", "[REDACTED]", "***REDACTED***"}
_SECRET_PATTERNS = (
    re.compile(r"(Bearer\s+)[A-Za-z0-9._\-+/=]{6,}", re.IGNORECASE),
    re.compile(r"\bsk-[A-Za-z0-9_\-]{8,}"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{12,}"),
    re.compile(r"((?:api[-_]?key|authorization|x-api-key|token|secret)\s*[:=]\s*['\"]?)([^\s'\",;}{]+)", re.IGNORECASE),
)


def sanitize_error_message(message: str, secrets: Iterable[str] = ()) -> str:
    """Scrub explicit secrets and common credential patterns from error/log strings."""
    cleaned = str(message or "")
    for secret in secrets:
        if secret and secret not in _NON_SECRET_PLACEHOLDERS and len(secret) >= 4:
            cleaned = cleaned.replace(secret, "[REDACTED]")
    for idx, pat in enumerate(_SECRET_PATTERNS):
        if idx in (0, 3):
            cleaned = pat.sub(r"\1[REDACTED]", cleaned)
        else:
            cleaned = pat.sub("[REDACTED]", cleaned)
    return cleaned


def normalize_provider_name(name: str | None) -> str:
    raw = (name or "ollama").strip().lower()
    canonical = PROVIDER_ALIASES.get(raw, raw)
    if canonical not in PROVIDER_PRESETS:
        supported = ", ".join(sorted(PROVIDER_PRESETS.keys()))
        raise ValueError(f"Unsupported LLM provider '{name}'. Supported providers: {supported}")
    return canonical


def _expand_env_placeholders(value: Any, env: Mapping[str, str]) -> Any:
    if isinstance(value, str):
        def _repl(match: re.Match[str]) -> str:
            var_name = match.group(1)
            default_val = match.group(2) if match.group(2) is not None else ""
            return env.get(var_name, default_val)

        return _ENV_VAR_RE.sub(_repl, value)
    if isinstance(value, dict):
        return {k: _expand_env_placeholders(v, env) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env_placeholders(item, env) for item in value]
    return value


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    """Minimal zero-dependency YAML subset parser (nested mappings + scalar values)."""
    root: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(-1, root)]
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        in_quote = None
        cleaned_chars = []
        for ch in stripped:
            if ch in ("'", '"') and in_quote is None:
                in_quote = ch
            elif ch == in_quote:
                in_quote = None
            elif ch == "#" and in_quote is None:
                break
            cleaned_chars.append(ch)
        line = "".join(cleaned_chars).strip()
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        key = key.strip()
        val = val.strip()

        while len(stack) > 1 and indent <= stack[-1][0]:
            stack.pop()
        current = stack[-1][1]

        if not val:
            child: dict[str, Any] = {}
            current[key] = child
            stack.append((indent, child))
        else:
            if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                parsed: Any = val[1:-1]
            elif val.lower() in ("true", "false"):
                parsed = val.lower() == "true"
            elif val.lower() in ("null", "~"):
                parsed = None
            else:
                try:
                    parsed = int(val)
                except ValueError:
                    try:
                        parsed = float(val)
                    except ValueError:
                        parsed = val
            current[key] = parsed
    return root


def load_provider_yaml(config_path: str, env: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Load and expand a YAML config file (supporting PyYAML or zero-dependency fallback)."""
    env_map = env if env is not None else os.environ
    with open(config_path, "r", encoding="utf-8") as f:
        raw_text = f.read()
    if yaml is not None:
        loaded = yaml.safe_load(raw_text) or {}
    else:
        loaded = _parse_simple_yaml(raw_text)
    if not isinstance(loaded, dict):
        raise ValueError(f"Config file '{config_path}' must contain a YAML mapping at top level.")
    return _expand_env_placeholders(loaded, env_map)


@dataclass(frozen=True)
class ProviderConfig:
    """Resolved runtime configuration for an OpenAI-compatible LLM endpoint."""

    provider: str
    base_url: str
    api_key: str = field(repr=False)
    model: str
    timeout: float = 300.0
    max_retries: int = 2
    extra_headers: dict[str, str] = field(default_factory=dict)
    supports_reasoning_effort: bool = False

    def redacted_api_key(self) -> str:
        if not self.api_key:
            return ""
        if self.api_key in ("ollama", "EMPTY"):
            return self.api_key
        return "***REDACTED***"

    def redacted_headers(self) -> dict[str, str]:
        return {
            k: ("***REDACTED***" if any(m in k.lower() for m in ("key", "auth", "token", "secret")) else v)
            for k, v in self.extra_headers.items()
        }

    def secret_values(self) -> tuple[str, ...]:
        vals = [self.api_key] if self.api_key not in _NON_SECRET_PLACEHOLDERS else []
        for k, v in self.extra_headers.items():
            if v and any(m in k.lower() for m in ("key", "auth", "token", "secret")):
                vals.append(v)
        return tuple(vals)

    def to_safe_dict(self) -> dict[str, Any]:
        """Return a log/audit-safe representation with secrets redacted."""
        return {
            "provider": self.provider,
            "base_url": self.base_url,
            "model": self.model,
            "api_key": self.redacted_api_key(),
            "timeout": self.timeout,
            "max_retries": self.max_retries,
            "supports_reasoning_effort": self.supports_reasoning_effort,
        }

    def __repr__(self) -> str:
        return (
            f"ProviderConfig(provider={self.provider!r}, base_url={self.base_url!r}, "
            f"model={self.model!r}, api_key={self.redacted_api_key()!r}, "
            f"timeout={self.timeout!r}, max_retries={self.max_retries!r})"
        )


def _validate_base_url(base_url: str, provider: str) -> str:
    cleaned = (base_url or "").strip()
    if not cleaned:
        raise ValueError(
            f"Provider '{provider}' requires a base URL. Set LLM_BASE_URL, --base-url, or llm.base_url in config."
        )
    parsed = urlparse(cleaned)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"Invalid LLM base URL '{cleaned}': expected http:// or https:// URL with host.")
    if parsed.username or parsed.password:
        raise ValueError("LLM base URL must not contain embedded userinfo credentials; pass credentials via LLM_API_KEY.")
    return cleaned.rstrip("/")


def _is_local_url(base_url: str) -> bool:
    host = (urlparse(base_url).hostname or "").lower()
    return host in _LOCAL_HOSTS


def resolve_provider_config(
    *,
    provider: str | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
    model: str | None = None,
    timeout: float | None = None,
    max_retries: int | None = None,
    config_path: str | None = None,
    env: Mapping[str, str] | None = None,
) -> ProviderConfig:
    """Resolve provider settings with precedence: CLI args > env vars > YAML config > preset defaults."""
    env_map = env if env is not None else os.environ

    cfg_file = config_path or env_map.get("LLM_CONFIG") or None
    yaml_llm: dict[str, Any] = {}
    if cfg_file:
        full_cfg = load_provider_yaml(cfg_file, env=env_map)
        section = full_cfg.get("llm", full_cfg)
        if isinstance(section, dict):
            yaml_llm = section

    resolved_provider = normalize_provider_name(
        provider or env_map.get("LLM_PROVIDER") or yaml_llm.get("provider") or "ollama"
    )
    preset = PROVIDER_PRESETS[resolved_provider]

    profile_cfg: dict[str, Any] = {}
    profiles = yaml_llm.get("profiles")
    if isinstance(profiles, dict) and isinstance(profiles.get(resolved_provider), dict):
        profile_cfg = profiles[resolved_provider]

    resolved_base_url = _validate_base_url(
        base_url
        or env_map.get("LLM_BASE_URL")
        or profile_cfg.get("base_url")
        or yaml_llm.get("base_url")
        or preset.default_base_url,
        resolved_provider,
    )

    resolved_model = (
        model
        or env_map.get("LLM_MODEL")
        or profile_cfg.get("model")
        or yaml_llm.get("model")
        or preset.default_model
        or ""
    ).strip()
    if not resolved_model:
        raise ValueError(
            f"Provider '{resolved_provider}' requires a model name. Set LLM_MODEL, --model, or llm.model in config."
        )

    resolved_api_key = (
        api_key
        or env_map.get("LLM_API_KEY")
        or profile_cfg.get("api_key")
        or yaml_llm.get("api_key")
        or preset.default_api_key
        or ""
    ).strip()

    if not resolved_api_key:
        if preset.requires_api_key and not (resolved_provider == "openai_compatible" and _is_local_url(resolved_base_url)):
            raise ValueError(
                f"Provider '{resolved_provider}' requires an API key. Set LLM_API_KEY or pass --api-key."
            )
        resolved_api_key = "EMPTY"

    raw_timeout = (
        timeout
        if timeout is not None
        else env_map.get("LLM_TIMEOUT")
        or profile_cfg.get("timeout")
        or yaml_llm.get("timeout")
        or 300.0
    )
    try:
        resolved_timeout = float(raw_timeout)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid LLM timeout '{raw_timeout}': must be a number in [1, 3600].") from exc
    if not (1.0 <= resolved_timeout <= 3600.0):
        raise ValueError(f"LLM timeout must be between 1 and 3600 seconds, got {resolved_timeout}")

    raw_retries = (
        max_retries
        if max_retries is not None
        else env_map.get("LLM_MAX_RETRIES")
        or profile_cfg.get("max_retries")
        or yaml_llm.get("max_retries")
        or 2
    )
    try:
        resolved_retries = int(raw_retries)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid LLM max_retries '{raw_retries}': must be an integer in [0, 10].") from exc
    if not (0 <= resolved_retries <= 10):
        raise ValueError(f"LLM max_retries must be between 0 and 10, got {resolved_retries}")

    headers: dict[str, str] = dict(preset.extra_headers)
    for src in (yaml_llm.get("extra_headers"), profile_cfg.get("extra_headers")):
        if isinstance(src, dict):
            headers.update({str(k): str(v) for k, v in src.items() if v})

    if resolved_provider == "azure" and resolved_api_key and "api-key" not in {k.lower() for k in headers}:
        headers["api-key"] = resolved_api_key

    supports_reasoning = preset.supports_reasoning_effort
    if "supports_reasoning_effort" in profile_cfg:
        supports_reasoning = bool(profile_cfg["supports_reasoning_effort"])
    elif "supports_reasoning_effort" in yaml_llm:
        supports_reasoning = bool(yaml_llm["supports_reasoning_effort"])

    return ProviderConfig(
        provider=resolved_provider,
        base_url=resolved_base_url,
        api_key=resolved_api_key,
        model=resolved_model,
        timeout=resolved_timeout,
        max_retries=resolved_retries,
        extra_headers=headers,
        supports_reasoning_effort=supports_reasoning,
    )


def create_openai_client(config: ProviderConfig) -> OpenAI:
    """Instantiate an OpenAI SDK client bound to the resolved ProviderConfig."""
    kwargs: dict[str, Any] = {
        "base_url": config.base_url,
        "api_key": config.api_key,
        "timeout": config.timeout,
        "max_retries": config.max_retries,
    }
    if config.extra_headers:
        kwargs["default_headers"] = dict(config.extra_headers)
    return OpenAI(**kwargs)
