from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import tomllib

from .models import Severity


DEFAULT_EXCLUDES = (
    ".git/**",
    ".venv/**",
    "venv/**",
    "node_modules/**",
    "dist/**",
    "build/**",
)


@dataclass(slots=True)
class Config:
    context_lines: int = 3
    fail_on: Severity | None = Severity.WARNING
    exclude: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    disabled_rules: set[str] = field(default_factory=set)
    extra_evidence_terms: list[str] = field(default_factory=list)


def load_config(path: Path | None) -> Config:
    config = Config()
    if path is None:
        candidate = Path(".claimfence.toml")
        if not candidate.exists():
            return config
        path = candidate
    if not path.exists():
        raise FileNotFoundError(f"configuration file not found: {path}")

    with path.open("rb") as stream:
        raw = tomllib.load(stream)
    section = raw.get("claimfence", raw)

    context_lines = section.get("context_lines", config.context_lines)
    if not isinstance(context_lines, int) or not 0 <= context_lines <= 20:
        raise ValueError("context_lines must be an integer from 0 to 20")
    config.context_lines = context_lines

    fail_on = section.get("fail_on", "warning")
    if fail_on is None or str(fail_on).lower() == "none":
        config.fail_on = None
    else:
        config.fail_on = Severity.parse(str(fail_on))

    config.exclude.extend(_string_list(section.get("exclude", []), "exclude"))
    config.disabled_rules = {
        value.upper() for value in _string_list(section.get("disabled_rules", []), "disabled_rules")
    }
    config.extra_evidence_terms = _string_list(
        section.get("extra_evidence_terms", []), "extra_evidence_terms"
    )
    return config


def _string_list(value: object, name: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{name} must be a list of strings")
    return list(value)
