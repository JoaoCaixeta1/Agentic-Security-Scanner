"""Validated JSON, redaction, deterministic deduplication and atomic output."""

import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional
from urllib.parse import parse_qsl, quote, quote_plus, urlencode, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field

CPF_PATTERN = re.compile(r"(?<![0-9])(?:[0-9]{3}\.[0-9]{3}\.[0-9]{3}-[0-9]{2}|[0-9]{11})(?![0-9])")


def now():
    return datetime.now(timezone.utc).isoformat()


class Redactor:
    def __init__(self, secrets=()):
        self.secrets = set(s for s in secrets if s)

    def add(self, value):
        if value:
            self.secrets.add(str(value))

    def text(self, value: str) -> str:
        variants = self.secrets | {quote(s, safe="") for s in self.secrets} | {quote_plus(s) for s in self.secrets}
        for secret in sorted(variants, key=len, reverse=True):
            value = value.replace(secret, "[REDACTED]") if len(secret) >= 4 else re.sub(r"(?<!\w)" + re.escape(secret) + r"(?!\w)", "[REDACTED]", value)
        value = CPF_PATTERN.sub("[CPF REDACTED]", value)
        value = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/-]+=*", r"\1[REDACTED]", value)
        return value

    def url(self, value):
        try:
            u = urlsplit(value)
            query = urlencode([(k, "[REDACTED]") for k, _ in parse_qsl(u.query, keep_blank_values=True)])
            # The validated target origin is structural metadata: a short cookie
            # such as "0" must not redact digits from 127.0.0.1 or the port.
            return urlunsplit((u.scheme, u.netloc.rsplit("@", 1)[-1],
                               self.text(u.path), self.text(query), ""))
        except ValueError:
            return "[INVALID URL]"

    def clean(self, value):
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.clean(v) for v in value]
        if isinstance(value, dict):
            return {str(k): self.url(v) if str(k) in ("url", "target") and isinstance(v, str)
                    else self.clean(v) for k, v in value.items()}
        return value


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    type: str
    title: str
    severity: Literal["info", "low", "medium", "high"]
    confidence: Literal["medium", "high"]
    url: str
    method: str
    cwe: str
    owasp: str
    evidence: Dict[str, Any]
    impact: str
    remediation: str
    limitations: List[str] = Field(default_factory=list)


class Report(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: str = "1.0"
    scanner: Dict[str, str] = Field(default_factory=lambda: {"name": "Agentic Security Scanner", "version": "1.0.0"})
    target: Optional[str] = None
    status: Literal["running", "completed", "partial", "error"] = "running"
    started_at: str = Field(default_factory=now)
    finished_at: Optional[str] = None
    authentication: str = "not_attempted"
    coverage: Dict[str, Any] = Field(default_factory=dict)
    ai: Dict[str, Any] = Field(default_factory=dict)
    checks: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    findings: List[Finding] = Field(default_factory=list)
    errors: List[Dict[str, str]] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    decisions: List[Dict[str, Any]] = Field(default_factory=list)


class Results:
    def __init__(self, report, redactor):
        self.report, self.redactor = report, redactor
        self.keys = set()

    def warning(self, message):
        if message not in self.report.warnings:
            self.report.warnings.append(message)

    def error(self, code, message):
        item = {"code": code, "message": message}
        if item not in self.report.errors:
            self.report.errors.append(item)

    def add(self, kind, url, method, evidence, *, title, severity, cwe, owasp, impact, remediation, confidence="high", limitations=(), discriminator=""):
        key = (kind, url, method, discriminator)
        if kind == "open_redirect" and discriminator:
            parts = urlsplit(url)
            # Group only variations of the proven destination parameter. Keep
            # other query values: they may select a different resource or flow.
            parameters = tuple((name, None if name == discriminator else value)
                               for name, value in parse_qsl(parts.query, keep_blank_values=True))
            key = (kind, urlunsplit(parts._replace(query="", fragment="")),
                   method, discriminator, parameters)
        if key in self.keys:
            return
        self.keys.add(key)
        identifier = hashlib.sha256(repr(key).encode()).hexdigest()[:16]
        self.report.findings.append(Finding(
            id=identifier, type=kind, url=self.redactor.url(url), method=method,
            title=title, severity=severity, confidence=confidence, cwe=cwe, owasp=owasp,
            evidence=self.redactor.clean(evidence), impact=impact, remediation=remediation,
            limitations=list(limitations),
        ))


def write_report(report: Report, path: Path, redactor: Redactor):
    # Mask secrets again at the final boundary, including cookies discovered late.
    data = report.model_dump(mode="json")
    # Redact untrusted/free text without corrupting enum values or schema keys.
    if data["target"] is not None:
        data["target"] = redactor.url(data["target"])
    for key in ("errors", "warnings", "decisions", "checks"):
        data[key] = redactor.clean(data[key])
    for finding in data["findings"]:
        finding["url"] = redactor.url(finding["url"])
        for key in ("evidence", "title", "impact", "remediation", "limitations"):
            finding[key] = redactor.clean(finding[key])
    validated = Report.model_validate(data)
    payload = json.dumps(validated.model_dump(mode="json"), ensure_ascii=False, indent=2) + "\n"
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix=".findings-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
