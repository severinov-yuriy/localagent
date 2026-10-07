"""Application-level security boundary: decisions, secret scanning and redaction."""
from __future__ import annotations

import base64
import math
import re
from dataclasses import dataclass
from typing import Any, ClassVar, Mapping


@dataclass(frozen=True)
class SecurityDecision:
    """Immutable result of one security policy decision."""

    allowed: bool
    policy: str
    operation: str
    reason: str


class SecretScanner:
    """Conservative detector and redactor for credentials and token-like values.

    ``scan`` is the only authoritative secret-detection primitive used by the
    runtime. ``redact`` is the corresponding presentation primitive for durable
    or user-visible sinks.
    """

    _patterns: ClassVar[tuple[tuple[str, re.Pattern[str]], ...]] = (
        ("private_key", re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")),
        ("bearer", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}")),
        ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
        ("api_key", re.compile(r"(?i)\b(?:api[_-]?key|access[_-]?key|client[_-]?secret|secret[_-]?key)\s*[:=]\s*['\"]?[A-Za-z0-9_./+=:-]{12,}")),
        ("password", re.compile(r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'\";,]{8,}")),
        ("credential", re.compile(r"(?i)\b(?:credential|token|access[_-]?token|refresh[_-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9_./+=:-]{12,}")),
        ("aws", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
        ("google_key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")),
        ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
        ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
        ("connection_string", re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^ \t\r\n/]+:[^ \t\r\n@]+@")),
        ("ssh_key", re.compile(r"(?i)\b(?:ssh-rsa|ssh-ed25519)\s+[A-Za-z0-9+/=]{80,}")),
        ("env_secret", re.compile(r"(?im)^\s*[A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)[A-Z0-9_]*\s*=\s*\S+")),
    )
    filename_patterns: ClassVar[tuple[re.Pattern[str], ...]] = (
        re.compile(r"^\.env(?:\..*)?$", re.I),
        re.compile(r".*\.(?:pem|key)$", re.I),
        re.compile(r"^id_(?:rsa|ed25519|ecdsa)$", re.I),
        re.compile(r"^credentials(?:\..*)?$", re.I),
        re.compile(r"^secrets(?:\..*)?$", re.I),
    )
    _data_url_re: ClassVar[re.Pattern[str]] = re.compile(
        r"^data:[^;,\s]+;base64,(?P<payload>[A-Za-z0-9+/=\r\n]+)$", re.I | re.S
    )
    REDACTED: ClassVar[str] = "[REDACTED]"

    @classmethod
    def filename_blocked(cls, name: str) -> bool:
        """Return whether a filename matches the built-in secret-name deny list."""
        return any(pattern.fullmatch(str(name)) for pattern in cls.filename_patterns)

    @classmethod
    def scan(cls, value: Any) -> str | None:
        """Return a sensitivity category when ``value`` contains secret material."""
        if isinstance(value, bytes):
            return cls._scan_bytes(value)
        if isinstance(value, Mapping):
            for key, item in value.items():
                if cls.scan(key) or cls.scan(item):
                    return "secret"
            return None
        if isinstance(value, (list, tuple, set)):
            for item in value:
                if cls.scan(item):
                    return "secret"
            return None
        if not isinstance(value, str):
            return None

        data_url = cls._data_url_re.fullmatch(value.strip())
        if data_url:
            try:
                payload = base64.b64decode(data_url.group("payload"), validate=True)
            except (ValueError, UnicodeEncodeError):
                return "binary_sensitive_data"
            return cls._scan_bytes(payload)

        return cls._scan_text(value)

    @classmethod
    def redact(cls, value: Any, keys: list[str] | tuple[str, ...] | None = None) -> Any:
        """Recursively redact sensitive values while preserving safe structure."""
        keyset = tuple(str(key).lower() for key in (keys or ()))
        if isinstance(value, Mapping):
            return {
                key: cls.REDACTED if cls._key_requires_redaction(key, keyset) else cls.redact(item, list(keyset))
                for key, item in value.items()
            }
        if isinstance(value, (list, tuple)):
            return [cls.redact(item, list(keyset)) for item in value]
        if isinstance(value, bytes):
            return cls.REDACTED if cls.scan(value) else f"<binary:{len(value)} bytes>"
        if isinstance(value, str):
            if cls._data_url_re.fullmatch(value.strip()):
                return cls.REDACTED
            if cls.scan(value):
                return cls.REDACTED
            return value
        return value

    @classmethod
    def _key_requires_redaction(cls, key: Any, keyset: tuple[str, ...]) -> bool:
        text = str(key).lower()
        return any(secret in text for secret in keyset)

    @classmethod
    def _scan_bytes(cls, value: bytes) -> str | None:
        # Secrets embedded as ASCII/UTF-8 metadata remain detectable inside common
        # binary payloads. Uninspectable binary without a known textual secret is
        # allowed; the image/file transport itself is still passed through DLP.
        return cls._scan_text(value.decode("utf-8", "ignore"))

    @classmethod
    def _scan_text(cls, value: str) -> str | None:
        for category, pattern in cls._patterns:
            if pattern.search(value):
                return category
        for token in re.findall(r"\b[A-Za-z0-9_-]{32,}\b", value):
            if len(set(token)) >= 10:
                entropy = _entropy(token)
                if entropy >= 4.0:
                    return "high_entropy_token"
        return None


def _entropy(value: str) -> float:
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    n = len(value)
    return -sum((count / n) * math.log2(count / n) for count in counts.values())


class DLPPolicy:
    """Default-deny data boundary for model context and tool arguments/results."""

    def __init__(self, scanner: type[SecretScanner] | None = None):
        self.scanner = scanner or SecretScanner

    def check(self, operation: str, value: Any) -> SecurityDecision:
        """Return an allow/block decision without returning sensitive content."""
        reason = self.scanner.scan(value)
        if reason:
            return SecurityDecision(False, "DLPPolicy", operation, "content blocked by security policy")
        return SecurityDecision(True, "DLPPolicy", operation, "allowed")
