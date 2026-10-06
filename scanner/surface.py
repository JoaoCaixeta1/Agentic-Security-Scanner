"""Discover forms and explicit references, never a dictionary of target paths."""

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Dict, List
from urllib.parse import unquote, urlsplit

from bs4 import BeautifulSoup

from discovery import extract_links
from .config import ScopeError

MUTATING = re.compile(r"(?i)(?:^|[/_?&=.;\-])(delete|remove|destroy|logout|signout|sair|excluir|comprar|purchase|checkout|transfer|reset)(?:$|[/_?&=.;\-])")
LOGOUT = re.compile(r"(?i)\b(log\s*out|sign\s*out|sair|desconectar|encerrar\s+sess[aã]o)\b")


def safe_to_visit(url):
    # Inspect the path/query, including common encoding layers and script suffixes.
    # This is a conservative name heuristic, not proof that a GET is side-effect free.
    parsed = urlsplit(url)
    candidate = parsed.path + "?" + parsed.query
    for _ in range(3):
        if MUTATING.search(candidate):
            return False
        decoded = unquote(candidate)
        if decoded == candidate:
            return True
        candidate = decoded
    return not MUTATING.search(candidate)


@dataclass
class Form:
    id: str
    page_url: str
    action: str
    method: str
    fields: List[Dict[str, str]] = field(repr=False)
    label: str = ""
    enctype: str = "application/x-www-form-urlencoded"

    @property
    def login(self):
        passwords = [f for f in self.fields if f["type"] == "password"]
        if len(passwords) != 1 or passwords[0].get("autocomplete") == "new-password":
            return False
        submit = " ".join(f["name"] + " " + f["value"] for f in self.fields
                          if f["type"] in ("submit", "image"))
        if re.search(r"(?i)(register|sign.?up|cadastro|criar conta|reset password)", submit):
            return False
        if re.search(r"(?i)(log.?in|sign.?in|entrar|acessar)", submit):
            return True
        return not re.search(r"(?i)(register|sign.?up|cadastro|criar conta|reset password)",
                             self.label + " " + self.action)

    @property
    def logout(self):
        return not self.login and bool(LOGOUT.search(self.label) or LOGOUT.search(self.action))

    def public(self):
        # Field values (including CSRF and secrets) never go to the model.
        return {"id": self.id, "method": self.method, "fields": [{"name": f["name"][:80], "type": f["type"]} for f in self.fields[:20]], "login_candidate": self.login}


@dataclass
class Surface:
    links: List[str] = field(default_factory=list)
    forms: List[Form] = field(default_factory=list)
    logout_links: List[str] = field(default_factory=list)
    endpoints: List[Dict[str, str]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


def inspect(obs, scope):
    out = Surface()

    def add(reference, method="GET", source="link"):
        try:
            url = scope.require(reference, obs.url)
        except (ScopeError, ValueError):
            return None
        if len(out.endpoints) < 100 and not any(e["url"] == url and e["method"] == method for e in out.endpoints):
            out.endpoints.append({"url": url, "method": method, "source": source})
        if method == "GET" and safe_to_visit(url) and url not in out.links and len(out.links) < 100:
            out.links.append(url)
        return url

    if obs.content_type in ("text/html", "application/xhtml+xml"):
        found = extract_links(obs.body, obs.url, obs.content_type)
        if found.limit_reached:
            out.warnings.append("Limite de links por página atingido.")
        if found.skipped_reason:
            out.warnings.append(found.skipped_reason)
        soup = BeautifulSoup(obs.text, "html.parser")
        if (not found.links and not soup.find("form") and soup.find("script", src=True)
                and any("-" in tag.name for tag in soup.find_all(True))):
            out.warnings.append("Interface dinâmica sem links ou formulários HTML: a descoberta sem JavaScript pode estar incompleta.")
        for anchor in soup.find_all("a", href=True):
            if LOGOUT.search(anchor.get_text(" ", strip=True)) or LOGOUT.search(anchor["href"]):
                try:
                    out.logout_links.append(scope.require(anchor["href"], obs.url))
                except ScopeError:
                    pass
        for url in found.links:
            if url not in out.logout_links:
                add(url)
        html_base = soup.find("base", href=True)
        parent = obs.url
        if html_base:
            try:
                parent = scope.require(html_base["href"], obs.url)
            except ScopeError:
                # External base cannot authorize form submissions or script fetches.
                out.warnings.append("Base HTML fora do escopo; formulários relativos não foram usados.")
                parent = None
        for index, element in enumerate(soup.find_all("form", limit=20)):
            action = element.get("action") or obs.url
            if parent is None and not action.startswith(("http://", "https://")):
                continue
            try:
                action = scope.require(action, parent or obs.url)
            except ScopeError:
                continue
            fields = []
            for item in element.find_all(["input", "button", "select", "textarea"], limit=50):
                name = item.get("name")
                if not name or item.has_attr("disabled"):
                    continue
                kind = item.get("type", "submit" if item.name == "button" else "text").lower()
                if kind in ("checkbox", "radio") and not item.has_attr("checked"):
                    continue
                value = item.get("value", "")
                if item.name == "select":
                    selected = item.find("option", selected=True) or item.find("option")
                    value = selected.get("value", selected.get_text()) if selected else ""
                fields.append({"name": str(name), "type": kind, "value": str(value), "autocomplete": item.get("autocomplete", "")})
            method = element.get("method", "GET").upper()
            if method not in ("GET", "POST"):
                continue
            label = element.get_text(" ", strip=True)[:300]
            identity = hashlib.sha256(f"{obs.url}|{action}|{method}|{index}".encode()).hexdigest()[:12]
            form = Form("form-" + identity, obs.url, action, method, fields, label, element.get("enctype", "application/x-www-form-urlencoded"))
            out.forms.append(form)
            if form.login:
                out.forms.extend(json_login_forms(element, scripts="\n".join(s.get_text() for s in soup.find_all("script", src=False)), obs=obs, scope=scope))
            if not form.login and not form.logout:
                add(action, method, "form")
        if parent:
            for script in soup.find_all("script", src=True, limit=20):
                try:
                    add(scope.require(script["src"], parent), source="script")
                except ScopeError:
                    pass
        scripts = "\n".join(s.get_text() for s in soup.find_all("script", src=False))
        discover_script(scripts, add)
    elif obs.content_type in ("application/javascript", "text/javascript"):
        discover_script(obs.text, add)
    elif obs.content_type in ("application/json", "text/json") or obs.content_type.endswith("+json"):
        try:
            data = json.loads(obs.text)
        except (ValueError, RecursionError):
            return out
        count = [0]

        def walk(value, depth=0):
            if depth > 8 or count[0] > 1000:
                return
            count[0] += 1
            if isinstance(value, dict):
                for key, item in list(value.items())[:100]:
                    if key.lower() in ("href", "url", "next", "self", "link") and isinstance(item, str) and item.startswith(("/", "http://", "https://")):
                        add(item, source="json_reference")
                    walk(item, depth + 1)
            elif isinstance(value, list):
                for item in value[:100]:
                    walk(item, depth + 1)

        walk(data)
        if isinstance(data, dict) and ("openapi" in data or "swagger" in data):
            paths = data.get("paths", {})
            if isinstance(paths, dict):
                for path, methods in list(paths.items())[:100]:
                    if "{" in path or not isinstance(methods, dict):
                        continue
                    for method in methods:
                        if method.upper() in ("GET", "POST", "HEAD", "OPTIONS"):
                            add(path, method.upper(), "openapi")
    return out


def discover_script(text, add):
    pattern = r"(?:\bfetch|\baxios\.(get|post))\s*\(\s*['\"]([^'\"\r\n]+)['\"]"
    for match in list(re.finditer(pattern, text[:200000]))[:100]:
        method = (match.group(1) or "GET").upper()
        options = text[match.end():match.end() + 200]
        explicit = re.search(r"\bmethod\s*:\s*['\"]([A-Za-z]+)['\"]", options)
        if explicit and not match.group(1):
            method = explicit.group(1).upper()
        if method in ("GET", "POST", "HEAD", "OPTIONS"):
            add(match.group(2), method, "script_reference")


def json_login_forms(element, scripts, obs, scope):
    """Only literal POST + JSON.stringify keys associated with a password form."""
    forms = []
    for match in re.finditer(r"fetch\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*\{([^;]{1,1500})", scripts[:200000]):
        block = match.group(2)
        if not re.search(r"method\s*:\s*['\"]POST['\"]", block, re.I):
            continue
        body = re.search(r"JSON\.stringify\s*\(\s*\{([^}]+)\}", block)
        if not body:
            continue
        names = re.findall(r"(?:^|,)\s*['\"]?([A-Za-z_][A-Za-z_0-9]*)['\"]?\s*(?=:|,|$)", body.group(1))
        password = [n for n in names if n.lower() in ("password", "passwd", "senha")]
        username = [n for n in names if n.lower() in ("username", "email", "user", "login", "usuario")]
        if len(password) != 1 or len(username) != 1 or len(names) != 2:
            continue  # Additional dynamic fields/CSRF cannot be reconstructed safely.
        try:
            action = scope.require(match.group(1), obs.url)
        except ScopeError:
            continue
        identity = hashlib.sha256((action + "|json").encode()).hexdigest()[:12]
        fields = [{"name": username[0], "type": "text", "value": ""}, {"name": password[0], "type": "password", "value": ""}]
        forms.append(Form("form-" + identity, obs.url, action, "POST", fields, "Login JSON discovered in script", "application/json"))
    return forms
