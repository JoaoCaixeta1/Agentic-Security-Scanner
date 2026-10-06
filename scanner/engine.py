"""Bounded discovery, local planning, authentication and evidence collection."""

import hashlib
import json
import time
from collections import deque

import httpx

from .agent import Planner
from .detectors import Detectors, denied, meaningful, same_content
from .network import Budget, Network
from .surface import inspect, safe_to_visit


class Engine:
    def __init__(self, settings, results, target_transport=None, ai_transport=None):
        self.settings, self.results = settings, results
        self.report = results.report
        self.budget = Budget(settings.max_requests, time.monotonic() + settings.max_seconds)
        self.net = Network(settings, self.budget, results, transport=target_transport)
        self.planner = Planner(settings, self.budget, results, transport=ai_transport)
        self.detectors = Detectors(self.net, results)
        self.queue = deque([(settings.base_url, 0)])
        self.visited = set()
        self.known = {settings.base_url}
        self.forms, self.logout_links, self.observations = {}, [], []
        self.login_attempts = set()
        self.logged_in = False
        self.pages = 0
        self.depth_skipped = 0
        self.references = []
        self.basic_attempted = False
        self.progress = lambda message: None

    def close(self):
        self.net.close()
        self.planner.close()

    def summarize(self):
        self.report.ai = self.planner.summary()
        self.report.coverage = {"pages": self.pages, "discovered_urls": len(self.known), "remaining_queue": len(self.queue), "target_requests": self.budget.count, "target_bytes": self.budget.bytes_read, "depth_skipped": self.depth_skipped, "protected_references": len(self.references), "limits": {"pages": self.settings.max_pages, "requests": self.settings.max_requests, "depth": self.settings.max_depth, "seconds": self.settings.max_seconds, "bytes_per_response": self.settings.max_body}, "javascript_executed": False}

    def record(self, obs):
        if obs is not None:
            if obs.status >= 500:
                self.results.warning("O alvo retornou erro HTTP 5xx durante descoberta ou login; a cobertura pode estar incompleta.")
            self.observations.append(obs)
            self.detectors.cpf(obs)

    def enqueue(self, url, depth):
        self.known.add(url)
        if depth > self.settings.max_depth:
            self.depth_skipped += 1
            return
        if len(self.queue) >= self.settings.max_pages * 4:
            self.results.warning("Fila de descoberta atingiu o limite; cobertura parcial.")
            return
        if safe_to_visit(url) and (url, self.logged_in) not in self.visited and not any(u == url for u, _ in self.queue):
            self.queue.append((url, depth))

    def plan(self, forms):
        if self.planner.available and self.planner.calls < self.settings.max_ai_calls:
            self.progress(f"Planejamento local: chamada {self.planner.calls + 1}/{self.settings.max_ai_calls}.")
        candidates = [{"id": "url-" + hashlib.sha256(url.encode()).hexdigest()[:12], "url": url, "source": "discovery"} for url, _ in list(self.queue)[:12]]
        plan = self.planner.choose(candidates, forms)
        if plan:
            priorities = {item: index for index, item in enumerate(plan.priority_ids)}
            ordered = sorted(self.queue, key=lambda item: priorities.get("url-" + hashlib.sha256(item[0].encode()).hexdigest()[:12], 999))
            self.queue = deque(ordered)
        return plan

    def login(self, forms, plan):
        if self.logged_in or not self.settings.username or len(self.login_attempts) >= 2:
            return
        candidates = [f for f in forms if f.login and f.action not in self.login_attempts]
        if not candidates:
            return
        candidates = sorted(candidates, key=lambda f: f.method != "POST")
        form = next((f for f in candidates if plan and f.id == plan.login_form_id), next((f for f in candidates if f.enctype == "application/json"), candidates[0]))
        if form.method != "POST" or form.enctype not in ("application/x-www-form-urlencoded", "application/json"):
            self.results.warning("Login descoberto exige fluxo não suportado; credenciais não foram enviadas na URL.")
            return
        text_fields = [f for f in form.fields if f["type"] in ("text", "email")]
        passwords = [f for f in form.fields if f["type"] == "password"]
        if not text_fields or len(passwords) != 1:
            return
        if plan and plan.login_form_id == form.id:
            username_field, password_field = plan.username_field, plan.password_field
        else:
            preferred = [f for f in text_fields if f["name"].lower() in ("username", "email", "login", "user", "usuario")]
            if len(text_fields) != 1 and len(preferred) != 1:
                self.results.warning("Campos de login ambíguos; envio de credenciais não realizado.")
                return
            username_field, password_field = (preferred or text_fields)[0]["name"], passwords[0]["name"]
        fields = {f["name"]: f["value"] for f in form.fields if f["type"] not in ("file", "reset", "button")}
        fields[username_field], fields[password_field] = self.settings.username, self.settings.password
        for value in fields.values():
            self.results.redactor.add(value)
        self.login_attempts.add(form.action)
        if form.enctype == "application/json":
            response = self.net.request("POST", form.action, json=fields, follow=True)
        else:
            response = self.net.request("POST", form.action, data=fields, follow=True)
        token = None
        if response and 200 <= response.status < 300 and "json" in response.content_type:
            try:
                payload = json.loads(response.text)
                if isinstance(payload, dict):
                    token = payload.get("access_token") or payload.get("token")
                if not isinstance(token, str) or not 8 <= len(token) <= 8192 or any(ord(c) < 33 or ord(c) > 126 for c in token):
                    token = None
                if token:
                    self.results.redactor.add(token)
                    self.net.client.headers["Authorization"] = "Bearer " + token
            except (ValueError, RecursionError):
                pass
        self.report.authentication = "attempted_unverified"
        if response and response.status < 400 and (self.net.snapshot() or token) and not any(f.login for f in inspect(response, self.net.scope).forms):
            self.logged_in = True
            self.net.authenticated = True
            self.report.authentication = "session_observed_unverified"
            self.enqueue(self.settings.base_url, 0)
            self.enqueue(response.url, 0)
            # Revisit discovered pages with the new session; no path is invented.
            for url in sorted(self.known):
                self.enqueue(url, 0)
        self.record(response)

    def run(self):
        self.progress("Verificando Ollama local e iniciando descoberta.")
        self.planner.preflight()
        while self.queue and self.pages < self.settings.max_pages:
            self.budget.check()
            url, depth = self.queue.popleft()
            key = (url, self.logged_in)
            if key in self.visited:
                continue
            self.visited.add(key)
            obs = self.net.request("GET", url, follow=True)
            self.pages += 1
            if obs is None:
                continue
            if obs.status == 401 and "basic" in obs.headers.get("www-authenticate", "").lower() and self.settings.username and not self.basic_attempted:
                self.basic_attempted = True
                self.net.client.auth = httpx.BasicAuth(self.settings.username, self.settings.password)
                retry = self.net.request("GET", url, follow=True)
                if meaningful(retry):
                    self.logged_in = True
                    self.net.authenticated = True
                    retry.authenticated = True
                    self.report.authentication = "basic_observed_unverified"
                    obs = retry
                else:
                    self.net.client.auth = None
                    self.report.authentication = "failed"
            self.record(obs)
            surface = inspect(obs, self.net.scope)
            for warning in surface.warnings:
                self.results.warning(warning)
            self.forms.update({f.id: f for f in surface.forms})
            self.logout_links = list(dict.fromkeys(self.logout_links + surface.logout_links))[:20]
            for link in surface.links:
                self.enqueue(link, depth + 1)
            login_candidates = [f for f in surface.forms if f.login]
            plan = None
            if (self.planner.calls == 0 or (login_candidates and not self.logged_in)
                    or (self.pages % 5 == 0 and self.queue
                        and self.planner.calls < self.settings.max_ai_calls - 1)):
                plan = self.plan(login_candidates)
            self.login(login_candidates, plan)
        if self.planner.calls == 0 and self.planner.available:
            self.plan([])
        if self.queue:
            self.results.warning("Limite de páginas atingido; há URLs não visitadas.")
        if self.depth_skipped:
            self.results.warning("Limite de profundidade restringiu a descoberta.")
        self.progress(f"Descoberta: {self.pages} páginas; iniciando verificações e controles.")
        if self.logged_in:
            self.protected_checks()
        else:
            for kind in ("http_method_tampering", "session_cookie_flags", "session_after_logout"):
                self.detectors.outcome(kind, "skipped", "no_authenticated_session")
            if not self.settings.username and any(f.login for f in self.forms.values()):
                self.report.authentication = "credentials_missing"
                self.results.warning("Login descoberto sem credenciais; cobertura autenticada não foi executada.")
            if self.settings.username:
                self.results.warning("Não foi possível verificar uma sessão autenticada; testes dependentes de login foram limitados.")
        # Redirect probes run before logout because a return flow may need the session.
        self.detectors.redirects(sorted(self.known))
        if self.references and self.net.client.auth is None and "Authorization" not in self.net.client.headers:
            self.detectors.logout(self.references[0], list(self.forms.values()), self.logout_links)
        elif self.references:
            self.detectors.outcome("session_after_logout", "skipped", "non_cookie_authentication")
        self.summarize()

    def protected_checks(self):
        anonymous = self.net.fork()
        try:
            candidates = [o for o in self.observations if o.authenticated and meaningful(o) and o.method == "GET" and o.content_type in ("text/html", "application/json", "text/json", "application/xhtml+xml")]
            seen = set()
            for reference in candidates:
                if reference.url in seen or not safe_to_visit(reference.url):
                    continue
                seen.add(reference.url)
                anonymous.client.cookies.clear()
                baseline = anonymous.request("GET", reference.url, follow=True)
                fresh = self.net.request("GET", reference.url, follow=True)
                if denied(baseline, self.net.scope) and not same_content(reference, baseline) and same_content(reference, fresh):
                    self.references.append(fresh)
                    self.report.authentication = "verified"
                    # Confirm mandatory method checks immediately, preserving findings
                    # even if the global budget ends before later resources or extras.
                    anonymous.client.cookies.clear()
                    self.detectors.method_tampering(fresh, anonymous)
            if self.references:
                self.detectors.cookie_flags(self.references[0])
            else:
                self.results.warning("Sessão sem recurso protegido estável: controles de autenticação inconclusivos.")
                for kind in ("http_method_tampering", "session_cookie_flags", "session_after_logout"):
                    self.detectors.outcome(kind, "skipped", "no_stable_protected_reference")
        finally:
            anonymous.close()
