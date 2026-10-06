"""Reproducible checks. The LLM cannot create or confirm findings."""

import re
import json

from bs4 import BeautifulSoup
import secrets
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .report import CPF_PATTERN
from .surface import inspect, safe_to_visit

KINDS = ("cpf_exposure", "http_method_tampering", "session_cookie_flags", "session_after_logout", "open_redirect")


def valid_cpf(value):
    digits = re.sub(r"[^0-9]", "", value)
    if len(digits) != 11 or len(set(digits)) == 1:
        return False
    for size in (9, 10):
        check = (sum(int(digits[i]) * (size + 1 - i) for i in range(size)) * 10) % 11
        if int(digits[size]) != (0 if check == 10 else check):
            return False
    return True


def meaningful(obs):
    return obs is not None and 200 <= obs.status < 300 and not obs.truncated and len(obs.body.strip()) >= 24


def same_content(left, right):
    # Exact content is intentionally conservative: dynamic pages may be inconclusive.
    return meaningful(left) and meaningful(right) and left.content_type == right.content_type and left.body.strip() == right.body.strip()


def denied(obs, scope):
    if obs is None:
        return False
    if obs.status in (401, 403):
        return True
    return obs.content_type in ("text/html", "application/xhtml+xml") and any(f.login for f in inspect(obs, scope).forms)


class Detectors:
    def __init__(self, network, results):
        self.net, self.results = network, results
        self.report = results.report
        for kind in KINDS:
            self.report.checks[kind] = {"tested": 0, "confirmed": 0, "negative": 0, "inconclusive": 0, "skipped": 0, "reasons": {}, "details": []}

    def count(self, kind, key="tested"):
        self.report.checks[kind][key] += 1

    def outcome(self, kind, state, reason, obs=None, **evidence):
        self.count(kind, state)
        check = self.report.checks[kind]
        check["reasons"][reason] = check["reasons"].get(reason, 0) + 1
        if len(check["details"]) < 100:
            detail = {"outcome": state, "reason": reason}
            if obs:
                detail.update(url=self.results.redactor.url(obs.url), request_id=obs.id, status=obs.status)
            detail.update(self.results.redactor.clean(evidence))
            check["details"].append(detail)

    def add(self, kind, obs, evidence, method_override=None, **kwargs):
        before = len(self.report.findings)
        self.results.add(kind, obs.url, method_override or obs.method, evidence, **kwargs)
        self.report.checks[kind]["confirmed"] += len(self.report.findings) - before

    def cpf(self, obs):
        kind = "cpf_exposure"
        if obs is None or not (obs.content_type.startswith("text/") or "json" in obs.content_type):
            return
        self.count(kind)
        matches = []
        contexts = []
        traversal_limited = False
        if "json" in obs.content_type:
            try:
                document = json.loads(obs.text)
            except (ValueError, RecursionError):
                self.outcome(kind, "inconclusive", "invalid_json", obs)
                return
            pending = [(document, 0)]
            examined = 0
            while pending and examined < 2000:
                item, depth = pending.pop()
                examined += 1
                if depth > 12:
                    traversal_limited = True
                    continue
                if isinstance(item, dict):
                    traversal_limited |= len(item) > 200
                    for key, value in list(item.items())[:200]:
                        if re.fullmatch(r"(?i)(?:customer[_-]?|client[_-]?|document[_-]?)?cpf", key) and isinstance(value, (str, int)):
                            contexts.append("cpf: " + str(value))
                        elif isinstance(value, (dict, list)):
                            pending.append((value, depth + 1))
                elif isinstance(item, list):
                    traversal_limited |= len(item) > 200
                    pending.extend((v, depth + 1) for v in item[:200])
            traversal_limited |= bool(pending)
        else:
            soup = BeautifulSoup(obs.text, "html.parser") if "html" in obs.content_type else None
            contexts = [soup.get_text(" ") if soup else obs.text]
            if soup:
                contexts.extend("cpf: " + field.get("value", "") for field in soup.find_all("input", attrs={"name": re.compile(r"(?i)^cpf$")}))
        text = "\n".join(contexts)
        for match in CPF_PATTERN.finditer(text):
            if not valid_cpf(match.group()):
                continue
            context = text[max(0, match.start() - 60):match.end() + 60]
            if not re.search(r"(?i)\bcpf\b", context):
                continue
            if re.search(r"(?i)\b(exemplo|example|dummy|fixture|fict[ií]cio|sample|test[e]?)\b", context):
                continue
            # No raw person data or deterministic CPF hashes are emitted.
            matches.append(re.sub(r"[^0-9]", "", match.group()))
        if not matches:
            reason = "body_truncated" if obs.truncated else "json_traversal_limit" if traversal_limited else "no_contextual_valid_cpf"
            self.outcome(kind, "inconclusive" if obs.truncated or traversal_limited else "negative", reason, obs)
            return
        self.add(kind, obs, {"request_id": obs.id, "status": obs.status, "valid_distinct_cpfs": len(set(matches)), "context": "CPF field/label near checksum-valid value", "access": "authenticated_session" if obs.authenticated else "public_session", "raw_values": "omitted"},
                 title="CPF com dígitos verificadores válidos exposto na resposta", severity="medium" if not obs.authenticated else "low", cwe="CWE-200", owasp="A01:2025", confidence="medium",
                 impact="A resposta contém identificadores pessoais completos e legíveis.",
                 remediation="Minimizar e mascarar CPF; verificar autorização e necessidade de exposição.",
                 limitations=["Checksum e contexto não comprovam pessoa real nem acesso indevido. Revisão de regra de negócio é necessária."])

    def method_tampering(self, reference, anonymous):
        kind = "http_method_tampering"
        if not safe_to_visit(reference.url):
            self.outcome(kind, "skipped", "unsafe_resource", reference)
            return
        self.count(kind)
        baseline = anonymous.request("GET", reference.url, follow=True)
        if not denied(baseline, self.net.scope):
            self.outcome(kind, "inconclusive", "anonymous_denial_not_reproduced", baseline)
            return
        attempts = []
        for _ in range(2):
            anonymous.client.cookies.clear()
            attempts.append(anonymous.request("POST", reference.url, data={}, follow=True))
        anonymous.client.cookies.clear()
        final = anonymous.request("GET", reference.url, follow=True)
        if all(same_content(reference, probe) for probe in attempts) and denied(final, self.net.scope):
            self.add(kind, reference, {"authenticated_reference": reference.id, "anonymous_get": [baseline.id, final.id], "anonymous_get_status": [baseline.status, final.status], "anonymous_post": [p.id for p in attempts], "anonymous_post_status": [p.status for p in attempts], "comparison": "exact protected response body and content type; reproduced twice"},
                     method_override="POST", title="Troca de GET por POST contorna controle de acesso", severity="high", cwe="CWE-650", owasp="A01:2025",
                     impact="Cliente sem sessão obtém a mesma resposta protegida ao alterar o método HTTP.", remediation="Aplicar autorização antes do despacho por método e negar métodos não previstos.")
        elif denied(final, self.net.scope) and all(p is not None and (denied(p, self.net.scope) or p.status == 405) for p in attempts):
            self.outcome(kind, "negative", "post_did_not_bypass_access_control", reference,
                         probe_ids=[p.id for p in attempts], terminal_statuses=[p.status for p in attempts], final_control=final.id)
        else:
            self.outcome(kind, "inconclusive", "post_response_not_comparable_or_control_failed", reference,
                         terminal_statuses=[p.status if p else None for p in attempts])

    def cookie_flags(self, reference):
        kind = "session_cookie_flags"
        cookies = self.net.snapshot()
        if not cookies:
            self.outcome(kind, "skipped", "no_cookies", reference)
        if len(cookies) > 5:
            self.outcome(kind, "skipped", "cookie_limit", omitted=len(cookies) - 5)
        for cookie in cookies[:5]:
            self.count(kind)
            rest = {k.lower(): v for k, v in cookie._rest.items()}
            missing = ([] if "httponly" in rest else ["HttpOnly"])
            if reference.url.startswith("https://") and not cookie.secure:
                missing.append("Secure")
            if not missing:
                self.outcome(kind, "negative", "applicable_cookie_flags_present", reference, cookie_name=cookie.name, secure_required=reference.url.startswith("https://"))
                continue
            reduced = [c for c in cookies if (c.name, c.domain, c.path) != (cookie.name, cookie.domain, cookie.path)]
            probe = self.net.fork(reduced)
            control = self.net.fork(cookies)
            isolated = self.net.fork([cookie])
            try:
                without = probe.request("GET", reference.url, follow=True)
                restored = control.request("GET", reference.url, follow=True)
                alone = isolated.request("GET", reference.url, follow=True)
            finally:
                probe.close()
                control.close()
                isolated.close()
            if denied(without, self.net.scope) and same_content(reference, restored) and same_content(reference, alone):
                self.add(kind, reference, {"cookie_name": cookie.name, "cookie_path": cookie.path, "missing_flags": missing, "without_cookie_request": without.id, "without_cookie_status": without.status, "restored_request": restored.id, "cookie_alone_request": alone.id, "cookie_value": "omitted"},
                         title="Cookie necessário à sessão sem flag de segurança", severity="medium", cwe="CWE-1004" if "HttpOnly" in missing else "CWE-614", owasp="A02:2025", discriminator=cookie.name + cookie.path,
                         impact="A proteção do cookie de autenticação está incompleta.", remediation="Definir HttpOnly e, em HTTPS, Secure no cookie de sessão; avaliar SameSite conforme o fluxo.",
                         limitations=["Ausência de HttpOnly não comprova XSS; Secure não é exigido neste teste sobre HTTP local."])
            else:
                self.outcome(kind, "inconclusive", "cookie_authentication_role_not_proven", reference, cookie_name=cookie.name)

    def redirects(self, urls):
        kind = "open_redirect"
        tested = 0
        for url in dict.fromkeys(urls):
            if tested >= 8:
                self.results.warning("Limite de candidatos a redirect atingido.")
                break
            parts = urlsplit(url)
            parameters = parse_qsl(parts.query, keep_blank_values=True)
            for index, (name, value) in enumerate(parameters):
                # Only an existing internal destination is a candidate, never guessed parameters.
                if not value.startswith(("/", "http://", "https://", "./", "../")) and not re.match(r"^[A-Za-z0-9_-]+(?:/[A-Za-z0-9_.-]+|\.[A-Za-z0-9]+)(?:[/?#].*)?$", value):
                    continue
                try:
                    self.net.scope.require(value, url)
                except ValueError:
                    continue
                if tested >= 8:
                    break
                tested += 1
                self.count(kind)
                baseline = self.net.request("GET", url)
                if baseline is None or baseline.status not in (301, 302, 303, 307, 308) or not baseline.headers.get("location"):
                    self.outcome(kind, "inconclusive", "baseline_not_http_redirect", baseline)
                    continue
                try:
                    self.net.scope.require(baseline.headers.get("location", ""), url)
                except ValueError:
                    self.outcome(kind, "inconclusive", "baseline_destination_outside_scope", baseline)
                    continue
                # An arbitrary public redirector may intentionally accept external URLs.
                # Require evidence that this is a protected return flow.
                anonymous = self.net.fork()
                try:
                    control = anonymous.request("GET", url, follow=True)
                finally:
                    anonymous.close()
                if not denied(control, self.net.scope):
                    self.outcome(kind, "inconclusive", "public_redirector_intent_unknown", baseline)
                    continue
                observations = []
                for _ in range(2):
                    external = "https://" + secrets.token_hex(8) + ".scanner.invalid/redirect-proof"
                    changed = list(parameters)
                    changed[index] = (name, external)
                    candidate = urlunsplit(parts._replace(query=urlencode(changed)))
                    response = self.net.request("GET", candidate)  # Never follows Location.
                    if response and response.status in (301, 302, 303, 307, 308) and response.headers.get("location") == external:
                        observations.append(response)
                if len(observations) == 2:
                    self.add(kind, baseline, {"parameter": name, "baseline_request": baseline.id, "probe_requests": [o.id for o in observations], "external_location_controlled": True, "external_destination_contacted": False},
                             title="Parâmetro controla redirecionamento para origem externa", severity="low", confidence="medium", cwe="CWE-601", owasp="A01:2025", discriminator=name,
                             impact="O endpoint pode encaminhar o navegador para um destino externo escolhido pelo cliente.", remediation="Permitir apenas destinos internos ou uma lista explícita de destinos confiáveis.",
                             limitations=["Pode ser um redirecionador externo intencional. A política de destinos exige revisão humana; exploração não foi alegada."])
                else:
                    self.outcome(kind, "inconclusive", "external_redirect_not_reproduced", baseline)
        if tested == 0:
            self.outcome(kind, "skipped", "no_supported_destination_parameter",
                         explanation="No same-origin URL/path parameter discovered; numeric IDs and JavaScript redirects are not probed.")

    def logout(self, reference, forms, links):
        kind = "session_after_logout"
        logout_forms = [f for f in forms if f.logout and f.method == "POST" and f.enctype == "application/x-www-form-urlencoded"]
        if not logout_forms and not links:
            self.outcome(kind, "skipped", "no_supported_logout_discovered")
            return
        old_cookies = self.net.snapshot()
        if not old_cookies:
            self.outcome(kind, "skipped", "no_cookies")
            return
        self.count(kind)
        if logout_forms:
            form = logout_forms[0]
            response = self.net.request("POST", form.action, data={f["name"]: f["value"] for f in form.fields}, follow=True)
        else:
            response = self.net.request("GET", links[0], follow=True)
        current = self.net.request("GET", reference.url, follow=True)
        if response is None or response.status >= 400 or not denied(current, self.net.scope):
            self.outcome(kind, "inconclusive", "logout_effect_not_verified", current)
            return
        stale = self.net.fork(old_cookies)
        anon = self.net.fork()
        try:
            control = anon.request("GET", reference.url, follow=True)
            probes = []
            for _ in range(2):
                stale.restore(old_cookies)
                probes.append(stale.request("GET", reference.url, follow=True))
        finally:
            stale.close()
            anon.close()
        if denied(control, self.net.scope) and all(same_content(reference, p) for p in probes):
            self.add(kind, reference, {"logout_request": response.id, "current_session_denied": current.id, "anonymous_denied": control.id, "old_cookie_requests": [p.id for p in probes], "old_cookie_status": [p.status for p in probes], "comparison": "exact protected response body after logout; reproduced twice", "cache_control": "no-cache"},
                     title="Sessão anterior continua válida após logout verificado", severity="high", cwe="CWE-613", owasp="A07:2025", impact="Uma cópia anterior do cookie permite reutilizar a sessão após a saída do usuário.", remediation="Invalidar a sessão no servidor durante logout; revogar tokens ou limitar sua validade conforme o risco.")
        elif denied(control, self.net.scope) and all(denied(p, self.net.scope) for p in probes):
            self.outcome(kind, "negative", "old_session_rejected_after_logout", reference,
                         logout_request=response.id, probe_ids=[p.id for p in probes], terminal_statuses=[p.status for p in probes])
        else:
            self.outcome(kind, "inconclusive", "old_session_response_not_comparable_or_control_failed", reference)
