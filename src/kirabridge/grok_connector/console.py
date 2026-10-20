"""One-time Grok connector consent inside the existing local operator console."""

# ruff: noqa: E501 -- Embedded browser assets keep ordinary HTML/JavaScript layout.

from __future__ import annotations

import json
import re
from collections.abc import Callable

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route

from kirabridge.bridge_core.models import BridgeError

MAX_DECISION_BYTES = 1024


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


class GrokConnectorConsole:
    """Routes inherit the parent console's local Host/Origin/session/CSP checks."""

    def __init__(self, administration, authorize_operator, authenticate: Callable[[Request], None]):
        self.administration, self.authorize_operator = administration, authorize_operator
        self.authenticate = authenticate
        self.routes = [
            Route("/grok-connector", self.index),
            Route("/grok-connector.js", self.javascript),
            Route("/grok-connector.css", self.stylesheet),
            Route("/api/grok-connector", self.status),
            Route("/api/grok-connector/{request_id}/decision", self.decide, methods=["POST"]),
        ]

    def _operator(self, request: Request):
        self.authenticate(request)
        self.authorize_operator()

    async def index(self, request: Request):
        return HTMLResponse(HTML)

    async def javascript(self, request: Request):
        return Response(JAVASCRIPT, media_type="application/javascript")

    async def stylesheet(self, request: Request):
        return Response(CSS, media_type="text/css")

    async def status(self, request: Request):
        self._operator(request)
        return JSONResponse(self.administration.status())

    async def decide(self, request: Request):
        self._operator(request)
        if request.headers.get("content-type", "").split(";")[0] != "application/json":
            raise BridgeError("invalid_request", "A JSON decision is required")
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > MAX_DECISION_BYTES:
                raise BridgeError("payload_limit", "Decision exceeds limit")
            body.extend(chunk)
        try:
            payload = json.loads(body, object_pairs_hook=_unique_object)
        except (ValueError, UnicodeDecodeError, RecursionError):
            raise BridgeError("invalid_request", "Invalid connector decision") from None
        if (
            not isinstance(payload, dict)
            or set(payload) != {"allow"}
            or type(payload["allow"]) is not bool
        ):
            raise BridgeError("invalid_request", "Choose approval or denial for this request")
        request_id = request.path_params["request_id"]
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", request_id):
            raise BridgeError("invalid_request", "Invalid authorization request ID")
        decision = self.administration.decide(request_id, payload["allow"])
        status = decision.get("status") if isinstance(decision, dict) else None
        if status not in {"pending", "approved", "denied", "expired"}:
            raise BridgeError("connector_state_unknown", "Authorization outcome is unknown")
        # Do not return poll data, redirect URLs, codes, state or credentials.
        return JSONResponse({"request_id": request_id, "status": status})


HTML = r"""<!doctype html>
<html lang="de"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>KiraBridge · Grok App</title>
<link rel="stylesheet" href="/networkpunkt.css"><link rel="stylesheet" href="/style.css">
<link rel="stylesheet" href="/grok-connector.css">
<script src="/grok-connector.js" defer></script>
</head><body class="np-ui np-scroll"><main class="console">
<header class="console-header"><div><p class="np-meta" data-t="local">Auf diesem Mac · lokaler Zugang</p>
<h1>KiraBridge · Grok App</h1><p data-t="intro">Die Grok-App einmalig verbinden und ihren Zugang prüfen.</p></div>
<nav class="np-actions"><a class="np-button" href="/" data-t="tasks">Aufträge</a>
<a class="np-button" href="/team">Team</a>
<button class="np-button" type="button" data-language="de">DE</button>
<button class="np-button" type="button" data-language="en">EN</button>
<button class="np-button" type="button" id="refresh" data-t="refresh">Aktualisieren</button></nav></header>
<p id="notice" class="np-notice" role="status" aria-live="polite"></p>
<section class="mode-panel"><h2 data-t="urlTitle">1 · Verbindung in Grok eintragen</h2>
<label for="connector-url" data-t="url">Öffentliche MCP-Adresse</label>
<input id="connector-url" readonly autocomplete="off">
<button class="np-button" id="copy-url" type="button" data-t="copy">Adresse kopieren</button>
<p class="meta" data-t="connect">In Grok: Connectors → New Connector → Custom. Diese Adresse verwenden und die Anmeldung starten.</p>
<p id="enabled-state"></p><p id="identity-state"></p><p id="approval-mode"></p>
<details class="np-disclosure"><summary data-t="scope">Eingerichtete Fähigkeiten des App-Zugangs</summary>
<pre id="capabilities" class="np-scroll" tabindex="0"></pre></details></section>
<section><h2 data-t="approvalTitle">2 · Einmalige Anmeldung auf diesem Mac prüfen</h2>
<p data-t="oneTime">Diese Entscheidung verknüpft den App-Zugang. Sie ist keine zusätzliche Freigabe für jeden Auftrag und ändert keine bestehende Aufgabenberechtigung.</p>
<p class="meta" data-t="untrustedName">Der Clientname stammt aus der Anfrage. Vor dem Bestätigen die Verbindungskennung mit dem ursprünglichen Grok-Anmeldefenster vergleichen und den registrierten Rücksprung prüfen.</p>
<div id="pending"></div></section>
<section><h2 data-t="proofTitle">3 · Tatsächlichen Aufruf prüfen</h2>
<p data-t="proofBoundary">Eine lokale Anmeldung oder ein erreichbarer Tunnel beweist noch keinen Aufruf aus der Handy-App. Werkzeugzugriff aus Eve oder dem Sprachmodus ist noch nicht nachgewiesen.</p>
<p id="last-use"></p><details class="np-disclosure"><summary data-t="evidence">Lokaler Authentifizierungsnachweis</summary>
<pre id="evidence" class="np-scroll" tabindex="0"></pre></details></section>
<footer class="np-meta"><p data-t="identityBoundary">grok_app ist die Grok-App. grok bleibt der getrennte CLI-Arbeitsagent. Es wird keine vorhandene Grok-Sitzung übernommen.</p>
<p data-t="tokens">Hier werden keine Grok-Passwörter, Anbieter-API-Schlüssel oder OAuth-Tokens verlangt oder angezeigt.</p>
<p data-t="tunnelBoundary">Eine neue temporäre Tunneladresse erfordert eine neue Verknüpfung. Der lokale Freigabebereich wird nicht durch den Tunnel veröffentlicht.</p></footer>
</main></body></html>"""


JAVASCRIPT = r""""use strict";
const words = {
 de: {
  local: "Auf diesem Mac · lokaler Zugang", intro: "Die Grok-App einmalig verbinden und ihren Zugang prüfen.",
  tasks: "Aufträge", refresh: "Aktualisieren", urlTitle: "1 · Verbindung in Grok eintragen",
  url: "Öffentliche MCP-Adresse", copy: "Adresse kopieren",
  connect: "In Grok: Connectors → New Connector → Custom. Diese Adresse verwenden und die Anmeldung starten.",
  scope: "Eingerichtete Fähigkeiten des App-Zugangs",
  approvalTitle: "2 · Einmalige Anmeldung auf diesem Mac prüfen",
  oneTime: "Diese Entscheidung verknüpft den App-Zugang. Sie ist keine zusätzliche Freigabe für jeden Auftrag und ändert keine bestehende Aufgabenberechtigung.",
  untrustedName: "Der Clientname stammt aus der Anfrage. Vor dem Bestätigen die Verbindungskennung mit dem ursprünglichen Grok-Anmeldefenster vergleichen und den registrierten Rücksprung prüfen.",
  connectionReference: "Verbindungskennung",
  proofTitle: "3 · Tatsächlichen Aufruf prüfen",
  proofBoundary: "Eine lokale Anmeldung oder ein erreichbarer Tunnel beweist noch keinen Aufruf aus der Handy-App. Werkzeugzugriff aus Eve oder dem Sprachmodus ist noch nicht nachgewiesen.",
  evidence: "Lokaler Authentifizierungsnachweis",
  identityBoundary: "grok_app ist die Grok-App. grok bleibt der getrennte CLI-Arbeitsagent. Es wird keine vorhandene Grok-Sitzung übernommen.",
  tokens: "Hier werden keine Grok-Passwörter, Anbieter-API-Schlüssel oder OAuth-Tokens verlangt oder angezeigt.",
  tunnelBoundary: "Eine neue temporäre Tunneladresse erfordert eine neue Verknüpfung. Der lokale Freigabebereich wird nicht durch den Tunnel veröffentlicht.",
  enabled: "Connector konfiguriert; die öffentliche Erreichbarkeit ist damit noch nicht belegt.",
  disabled: "App-Connector noch nicht aktiviert. Zuerst kirabridge grok-connector setup und start verwenden.",
  identity: "OAuth-Identität: grok_app · CLI-Identität: grok",
  automatic: "App-Aufträge verwenden die bestehenden automatischen Freigaben innerhalb ihrer eingerichteten Rechte.",
  manual: "Für den App-Zugang ist Einzelauftragsfreigabe eingerichtet.",
  unknownMode: "Auftragsberechtigung des App-Zugangs noch nicht bestätigt.",
  noPending: "Keine offene Anmeldeanfrage. Die Anmeldung in Grok starten; diese Seite liest dann ihren aktuellen Stand.",
  redirect: "Registrierter Rücksprung nach der Anmeldung", scopes: "Angefragter Umfang",
  created: "Erstellt", expires: "Gültig bis", unnamed: "Unbenannter Client",
  allow: "Diese Verknüpfung erlauben", deny: "Diese Verknüpfung ablehnen",
  approved: "Verknüpfung bestätigt. Im Grok-Anmeldefenster fortfahren.",
  denied: "Verknüpfung abgelehnt.", expired: "Die Anmeldeanfrage ist abgelaufen. In Grok neu anmelden.",
  pending: "Die Anmeldeanfrage wartet weiterhin auf eine Entscheidung.",
  noUse: "Noch kein authentifizierter MCP-Aufruf in diesem Connector belegt.",
  lastUse: "Letzter protokollierter authentifizierter MCP-Aufruf: ",
  lastBoundary: " Dieser lokale Beleg bestätigt allein weder ein bestimmtes Handy noch Eve.",
  connected: "Lokalen Freigabestand gelesen.", copied: "Öffentliche MCP-Adresse kopiert.",
  selectCopy: "Adresse markieren und manuell kopieren.", unknownTime: "Zeitpunkt unbekannt",
  errors: {
   unauthorized: "Den lokalen KiraBridge-Freigabestarter erneut öffnen.",
   csrf: "Diese Seite direkt über den lokalen KiraBridge-Starter öffnen.",
   network: "Verbindung nicht bestätigt. Aktualisieren liest den bestehenden Zustand.",
   uncertain: "Die Antwort fehlt. Zuerst aktualisieren und den bestehenden Zustand prüfen; es wird nicht automatisch erneut freigegeben.",
   storage: "Lokale Browserdaten sind gesperrt. Den lokalen Starter erneut öffnen.",
   not_found: "Anmeldeanfrage nicht mehr vorhanden. Den aktuellen Stand neu laden.",
   connector_disabled: "Der App-Connector ist nicht aktiviert.",
   connector_profile_conflict: "Das lokale Connectorprofil passt nicht. Den aktuellen Tunnelstatus prüfen; die alte Adresse wird nicht weiterverwendet.",
   generic: "Die Anfrage konnte nicht abgeschlossen werden."
  }
 },
 en: {
  local: "On this Mac · local principal", intro: "Link the Grok app once and inspect its access.",
  tasks: "Tasks", refresh: "Refresh", urlTitle: "1 · Add the connection in Grok",
  url: "Public MCP address", copy: "Copy address",
  connect: "In Grok: Connectors → New Connector → Custom. Use this address and start authentication.",
  scope: "Configured capabilities of the app principal",
  approvalTitle: "2 · Review the initial sign-in on this Mac",
  oneTime: "This decision links the app principal. It adds no per-task approval and changes no existing task permissions.",
  untrustedName: "The client supplied its own name. Compare the connection reference with the original Grok sign-in window and review the registered callback before approval.",
  connectionReference: "Connection reference",
  proofTitle: "3 · Verify an actual call",
  proofBoundary: "Local authorization or a reachable tunnel does not establish a mobile-app call. Tool access from Eve or voice mode has not been verified.",
  evidence: "Local authentication evidence",
  identityBoundary: "grok_app identifies the Grok app. grok remains the separate CLI worker. No existing Grok session is attached.",
  tokens: "No Grok passwords, provider API keys or OAuth tokens are requested or displayed here.",
  tunnelBoundary: "A changed temporary tunnel address needs a new connection. The local operator console is never exposed through this tunnel.",
  enabled: "Connector configured; this does not establish public reachability.",
  disabled: "App connector not enabled yet. First use kirabridge grok-connector setup and start.",
  identity: "OAuth identity: grok_app · CLI identity: grok",
  automatic: "App tasks use existing automatic approval within their configured permissions.",
  manual: "The app principal currently requires per-task approval.",
  unknownMode: "The app principal's task permissions have not been confirmed.",
  noPending: "No sign-in request pending. Start authentication in Grok; this page reads its current state.",
  redirect: "Registered callback after sign-in", scopes: "Requested scope",
  created: "Created", expires: "Expires", unnamed: "Unnamed client",
  allow: "Allow this connection", deny: "Deny this connection",
  approved: "Connection approved. Continue in the Grok authentication window.",
  denied: "Connection denied.", expired: "The sign-in request expired. Start a new sign-in in Grok.",
  pending: "The sign-in request is still awaiting a decision.",
  noUse: "No authenticated MCP call has been recorded for this connector yet.",
  lastUse: "Last recorded authenticated MCP call: ",
  lastBoundary: " This local evidence alone establishes neither a particular phone nor Eve.",
  connected: "Local authorization state read.", copied: "Public MCP address copied.",
  selectCopy: "Select the address and copy it manually.", unknownTime: "Time unknown",
  errors: {
   unauthorized: "Reopen the local KiraBridge approval launcher.",
   csrf: "Open this page through the local KiraBridge launcher.",
   network: "Connection not confirmed. Refresh reads the existing state.",
   uncertain: "The response is missing. Refresh and inspect existing state first; approval is never retried automatically.",
   storage: "Local browser storage is blocked. Reopen the local launcher.",
   not_found: "Sign-in request no longer present. Refresh the current state.",
   connector_disabled: "The app connector is not enabled.",
   connector_profile_conflict: "The local connector profile does not match. Inspect the current tunnel status; the previous address is not reused.",
   generic: "The request could not be completed."
  }
 }
};
const $ = id => document.getElementById(id);
let language = "de", snapshot = null, busy = false;
try { language = localStorage.getItem("kirabridge.locale") || "de"; } catch (_) {}
if (!words[language]) language = "de";
const t = key => words[language][key] || key;
function node(tag, value, cls) {
 const item = document.createElement(tag);
 if (value !== undefined) item.textContent = value;
 if (cls) item.className = cls;
 return item;
}
function notice(value, error = false) {
 $("notice").textContent = value; $("notice").dataset.state = error ? "error" : "normal";
}
function failure(code, serverCode) { return Object.assign(new Error(code), {code, serverCode}); }
function showError(error) {
 snapshot = null;
 $("connector-url").value = ""; $("copy-url").disabled = true;
 for (const button of $("pending").querySelectorAll("button")) button.disabled = true;
 notice((words[language].errors[error.code] || words[language].errors.generic) +
  (error.serverCode ? " (" + error.serverCode + ")" : ""), true);
}
async function api(path, payload) {
 let token;
 try { token = localStorage.getItem("kirabridge.session") || ""; }
 catch (_) { throw failure("storage"); }
 const options = {cache: "no-store", credentials: "omit",
  headers: {Authorization: "Bearer " + token, "Content-Type": "application/json"}};
 if (payload !== undefined) { options.method = "POST"; options.body = JSON.stringify(payload); }
 let response, value;
 try { response = await fetch(path, options); }
 catch (_) { throw failure(payload === undefined ? "network" : "uncertain"); }
 try { value = await response.json(); }
 catch (_) { throw failure(payload === undefined ? "generic" : "uncertain"); }
 if (!response.ok) {
  if (payload !== undefined && response.status >= 500) throw failure("uncertain");
  const code = typeof value.error === "string" ? value.error : "generic";
  throw failure(words[language].errors[code] ? code : "generic", code);
 }
 return value;
}
function time(value) {
 const date = new Date(value * 1000);
 return value && !Number.isNaN(date.getTime()) ? new Intl.DateTimeFormat(
  language === "de" ? "de-DE" : "en-GB", {dateStyle: "short", timeStyle: "medium"}
 ).format(date) : t("unknownTime");
}
function render(data) {
 $("connector-url").value = data.connector_url || "";
 $("copy-url").disabled = !data.connector_url;
 $("enabled-state").textContent = t(data.enabled ? "enabled" : "disabled");
 $("identity-state").textContent = t("identity");
 $("approval-mode").textContent = t(data.task_approval_mode === "automatic" ? "automatic" :
  data.task_approval_mode === "manual" ? "manual" : "unknownMode");
 $("capabilities").textContent = JSON.stringify(data.capabilities, null, 2);
 const container = $("pending"); container.replaceChildren();
 for (const pending of data.pending) {
  const card = node("article", undefined, "card");
  card.append(node("h3", pending.client_name || t("unnamed")), node("p", pending.id, "identifier"),
   node("p", t("connectionReference") + ": " + pending.id.slice(-12).toUpperCase(), "connection-reference"),
   node("p", t("redirect"), "field-label"), node("pre", pending.redirect_uri, "np-scroll"),
   node("p", t("scopes") + ": " + (pending.scopes || []).join(", "), "meta"),
   node("p", t("created") + ": " + time(pending.created) + " · " +
    t("expires") + ": " + time(pending.expires_at), "meta"));
  const actions = node("div", undefined, "np-actions");
  for (const allow of [true, false]) {
   const button = node("button", t(allow ? "allow" : "deny"), "np-button");
   button.type = "button";
   if (allow) button.dataset.variant = "primary";
   button.addEventListener("click", async () => {
    if (busy) return;
    busy = true;
    for (const control of container.querySelectorAll("button")) control.disabled = true;
    try {
     const decision = await api("/api/grok-connector/" + encodeURIComponent(pending.id) + "/decision", {allow});
     snapshot = await api("/api/grok-connector"); render(snapshot); notice(t(decision.status));
    } catch (error) { showError(error); }
    finally { busy = false; }
   });
   actions.append(button);
  }
  card.append(actions); container.append(card);
 }
 if (!data.pending.length) container.append(node("p", t("noPending"), "empty"));
 const use = data.authorization && data.authorization.last_use;
 $("last-use").textContent = use ? t("lastUse") + time(use.at) +
  (use.tool ? " · " + use.tool : "") + t("lastBoundary") : t("noUse");
 $("evidence").textContent = JSON.stringify(data.authorization, null, 2);
}
async function refresh() {
 if (busy) return;
 busy = true;
 try { snapshot = await api("/api/grok-connector"); render(snapshot); notice(t("connected")); }
 catch (error) { showError(error); }
 finally { busy = false; }
}
function translate() {
 document.documentElement.lang = language;
 document.querySelectorAll("[data-t]").forEach(item => { item.textContent = t(item.dataset.t); });
 document.querySelectorAll("[data-language]").forEach(item => {
  item.setAttribute("aria-pressed", String(item.dataset.language === language));
 });
 if (snapshot) render(snapshot);
}
$("copy-url").addEventListener("click", async () => {
 try { await navigator.clipboard.writeText($("connector-url").value); notice(t("copied")); }
 catch (_) { $("connector-url").focus(); $("connector-url").select(); notice(t("selectCopy")); }
});
$("refresh").addEventListener("click", refresh);
document.querySelectorAll("[data-language]").forEach(button => button.addEventListener("click", () => {
 language = button.dataset.language;
 try { localStorage.setItem("kirabridge.locale", language); } catch (_) {}
 translate();
}));
setInterval(() => { if (!document.hidden && !busy) refresh(); }, 5000);
translate(); refresh();
"""


CSS = r"""#connector-url { display: block; box-sizing: border-box; width: 100%;
 margin: var(--np-space-2) 0; padding: var(--np-space-2); color: var(--np-text);
 background: var(--np-canvas); border: 1px solid var(--np-control-border);
 font: inherit; font-family: ui-monospace, monospace; }
.mode-panel > p { margin-top: var(--np-space-3); }
.mode-panel > details { margin-top: var(--np-space-3); }
.card > .np-actions { margin-top: var(--np-space-4); }
.connection-reference { font-family: ui-monospace, monospace; font-weight: 700;
 letter-spacing: .06em; margin-top: var(--np-space-3); }
#notice[data-state="error"] { color: var(--np-danger); }
button:disabled { opacity: .6; }
"""
