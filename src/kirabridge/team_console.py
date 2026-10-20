"""Team UI mounted inside the authenticated, loopback-only approval console.

The browser is always the configured ``local`` principal. It cannot choose an
actor, impersonate a member or mark another member's work as its own result.
"""

# ruff: noqa: E501 -- Browser assets retain their ordinary HTML/JavaScript layout.

from __future__ import annotations

import json
from collections.abc import Callable

from pydantic import ValidationError
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route

from kirabridge.bridge_core.models import BridgeError
from kirabridge.team_manager.models import (
    TeamCreate,
    TeamMessageSend,
    TeamRoleSet,
    TeamWorkClaim,
    TeamWorkComplete,
    TeamWorkCreate,
)

MAX_REQUEST_BYTES = 524288


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


class TeamConsole:
    """Supply routes; the parent console retains Host, Origin and CSP guards."""

    def __init__(self, ports, authenticate: Callable[[Request], None]):
        self.config, self.security, self.teams = ports.config, ports.security, ports.teams
        self.authenticate = authenticate
        self.routes = [
            Route("/team", self.index),
            Route("/team.js", self.javascript),
            Route("/team.css", self.stylesheet),
            Route("/api/team", self.list_teams, methods=["GET"]),
            Route("/api/team", self.create, methods=["POST"]),
            Route("/api/team/{team_id}", self.get),
            Route("/api/team/{team_id}/roles", self.set_role, methods=["POST"]),
            Route("/api/team/{team_id}/messages", self.messages, methods=["GET"]),
            Route("/api/team/{team_id}/messages", self.send, methods=["POST"]),
            Route("/api/team/{team_id}/messages/{message_id}/ack", self.ack, methods=["POST"]),
            Route("/api/team/{team_id}/work", self.work_list, methods=["GET"]),
            Route("/api/team/{team_id}/work", self.delegate, methods=["POST"]),
            Route("/api/team/{team_id}/work/{work_id}", self.work_get),
            Route("/api/team/{team_id}/work/{work_id}/claim", self.claim, methods=["POST"]),
            Route("/api/team/{team_id}/work/{work_id}/complete", self.complete, methods=["POST"]),
            Route("/api/team/{team_id}/events", self.events),
        ]

    def _principal(self, request: Request) -> str:
        self.authenticate(request)
        self.security.principal("local")
        return "local"

    @staticmethod
    async def _payload(request: Request) -> dict:
        if request.headers.get("content-type", "").split(";")[0] != "application/json":
            raise BridgeError("invalid_request", "A JSON team request is required")
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > MAX_REQUEST_BYTES:
                raise BridgeError("payload_limit", "Team request exceeds browser limit")
            body.extend(chunk)
        try:
            value = json.loads(body, object_pairs_hook=_unique_object)
        except (ValueError, UnicodeDecodeError):
            raise BridgeError("invalid_request", "Invalid JSON team request") from None
        if not isinstance(value, dict):
            raise BridgeError("invalid_request", "A JSON object is required")
        return value

    async def _model(self, request: Request, model, *, scoped: bool = True):
        payload = await self._payload(request)
        if scoped:
            for name in ("team_id", "work_id"):
                if name in request.path_params:
                    if name in payload:
                        raise BridgeError("invalid_request", "Identifiers belong in the route")
                    payload[name] = request.path_params[name]
        try:
            return model.model_validate(payload)
        except ValidationError:
            raise BridgeError("invalid_request", "Invalid team fields") from None

    @staticmethod
    def _page(request: Request) -> tuple[int, int]:
        if set(request.query_params) - {"after", "limit"}:
            raise BridgeError("invalid_request", "Unknown team page parameter")
        try:
            after = int(request.query_params.get("after", "0"))
            limit = int(request.query_params.get("limit", "50"))
        except ValueError:
            raise BridgeError("invalid_request", "Invalid team page") from None
        if not 0 <= after < 2**63 or not 1 <= limit <= 50:
            raise BridgeError("invalid_request", "Team page limit is 1..50")
        if any(len(request.query_params.getlist(key)) != 1 for key in request.query_params):
            raise BridgeError("invalid_request", "Repeated team page parameter")
        return after, limit

    async def index(self, request: Request):
        return HTMLResponse(HTML)

    async def javascript(self, request: Request):
        return Response(JAVASCRIPT, media_type="application/javascript")

    async def stylesheet(self, request: Request):
        return Response(CSS, media_type="text/css")

    async def list_teams(self, request: Request):
        principal = self._principal(request)
        self.security.principal(principal, "team.read")
        result = self.teams.list(principal) if self.config.team.enabled else {"teams": []}
        roster = []
        for name, worker in self.config.team.workers.items():
            policy = self.config.principals.get(name)
            adapter = self.config.agents.get(worker.agent) if worker.agent else None
            automatic = bool(
                worker.agent
                and worker.cwd
                and policy
                and policy.approval_mode == "automatic"
                and "agent.execute" in policy.capabilities
                and worker.agent in policy.agents
                and adapter
            )
            roster.append(
                {
                    "principal": name,
                    "agent": worker.agent,
                    "adapter": adapter.kind if adapter else None,
                    "execution": "automatic"
                    if automatic
                    else "blocked"
                    if worker.agent
                    else "external",
                    "authentication_status": "unknown" if worker.agent else "external",
                }
            )
        policy = self.security.principal(principal)
        return JSONResponse(
            {
                **result,
                "principal": principal,
                "enabled": self.config.team.enabled,
                "can_create": "team.manage" in policy.capabilities,
                "roster": roster,
            }
        )

    async def get(self, request: Request):
        principal = self._principal(request)
        return JSONResponse(self.teams.get(principal, request.path_params["team_id"]))

    async def create(self, request: Request):
        principal = self._principal(request)
        value = await self._model(request, TeamCreate, scoped=False)
        return JSONResponse(self.teams.create(principal, value))

    async def set_role(self, request: Request):
        principal = self._principal(request)
        value = await self._model(request, TeamRoleSet)
        return JSONResponse(self.teams.set_role(principal, value))

    async def messages(self, request: Request):
        principal = self._principal(request)
        after, limit = self._page(request)
        return JSONResponse(
            self.teams.messages(principal, request.path_params["team_id"], after, limit)
        )

    async def send(self, request: Request):
        principal = self._principal(request)
        value = await self._model(request, TeamMessageSend)
        return JSONResponse(self.teams.send(principal, value))

    async def ack(self, request: Request):
        principal = self._principal(request)
        if await self._payload(request):
            raise BridgeError("invalid_request", "Acknowledgement body must be empty")
        return JSONResponse(
            self.teams.ack(
                principal, request.path_params["team_id"], request.path_params["message_id"]
            )
        )

    async def work_list(self, request: Request):
        principal = self._principal(request)
        after, limit = self._page(request)
        return JSONResponse(
            self.teams.work_list(principal, request.path_params["team_id"], after, limit)
        )

    async def delegate(self, request: Request):
        principal = self._principal(request)
        value = await self._model(request, TeamWorkCreate)
        return JSONResponse(self.teams.delegate(principal, value))

    async def work_get(self, request: Request):
        principal = self._principal(request)
        return JSONResponse(
            self.teams.work_get(
                principal, request.path_params["team_id"], request.path_params["work_id"]
            )
        )

    async def claim(self, request: Request):
        principal = self._principal(request)
        value = await self._model(request, TeamWorkClaim)
        return JSONResponse(self.teams.work_claim(principal, value))

    async def complete(self, request: Request):
        principal = self._principal(request)
        value = await self._model(request, TeamWorkComplete)
        return JSONResponse(self.teams.work_complete(principal, value))

    async def events(self, request: Request):
        principal = self._principal(request)
        after, limit = self._page(request)
        return JSONResponse(
            self.teams.events(principal, request.path_params["team_id"], after, limit)
        )


HTML = r"""<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>KiraBridge · Team</title>
  <link rel="stylesheet" href="/networkpunkt.css">
  <link rel="stylesheet" href="/style.css">
  <link rel="stylesheet" href="/team.css">
  <script src="/team.js" defer></script>
</head>
<body class="np-ui np-scroll">
<main class="console">
  <header class="console-header">
    <div><p class="np-meta" data-t="local">Auf diesem Gerät · lokaler Zugang</p>
      <h1>KiraBridge · Team</h1><p data-t="intro">Zusammenarbeiten, delegieren und Ergebnisse prüfen.</p>
    </div>
    <div class="np-actions">
      <a class="np-button" href="/" data-t="approvals">Aufträge / Freigaben</a>
      <button class="np-button" type="button" data-language="de">DE</button>
      <button class="np-button" type="button" data-language="en">EN</button>
      <button class="np-button" type="button" id="refresh" data-t="refresh">Aktualisieren</button>
    </div>
  </header>
  <p id="team-notice" class="np-notice" role="status" aria-live="polite"></p>
  <section class="mode-panel" aria-labelledby="team-title">
    <h2 id="team-title" data-t="selectTeam">Team auswählen</h2>
    <label for="team-select" data-t="team">Team</label>
    <select id="team-select"><option value="">—</option></select>
    <label class="inline"><input id="auto-refresh" type="checkbox" checked>
      <span data-t="autoRefresh">Sichtbare Seite alle 5 Sekunden aktualisieren</span></label>
    <details class="np-disclosure" id="create-panel">
      <summary data-t="newTeam">Neues Team anlegen</summary>
      <form id="create-team" class="team-form">
        <label for="new-id" data-t="teamId">Teamkennung</label>
        <input id="new-id" name="team_id" required maxlength="80" value="kirabridge-team">
        <label for="new-name" data-t="teamName">Teamname</label>
        <input id="new-name" name="name" required maxlength="120" value="KiraBridge Team">
        <fieldset><legend data-t="members">Mitglieder</legend><div id="new-members"></div></fieldset>
        <label for="new-coordinator" data-t="coordinator">Koordinator</label>
        <select id="new-coordinator" required></select>
        <button class="np-button" data-variant="primary" type="submit" data-t="create">Team anlegen</button>
      </form>
    </details>
  </section>
  <section id="team-view" hidden aria-labelledby="selected-title">
    <h2 id="selected-title"></h2><p id="team-meta" class="meta"></p>
    <h3 data-t="roles">Mitglieder und Rollen</h3><div id="members"></div>
    <form id="change-coordinator" class="team-form" hidden>
      <label for="coordinator-select" data-t="chooseCoordinator">Koordinator wählen</label>
      <select id="coordinator-select" required></select>
      <button class="np-button" type="submit" data-t="saveCoordinator">Koordinator festlegen</button>
    </form>
    <div class="team-columns">
      <section aria-labelledby="send-title"><h3 id="send-title" data-t="sendTitle">Nachricht senden</h3>
        <form id="send-message" class="team-form">
          <label for="message-recipient" data-t="recipient">An</label>
          <select id="message-recipient" required></select>
          <label for="message-kind" data-t="kind">Art</label>
          <select id="message-kind">
            <option value="question">question</option><option value="answer">answer</option>
            <option value="work">work</option><option value="result">result</option>
            <option value="note">note</option>
          </select>
          <label for="message-body" data-t="body">Inhalt</label>
          <textarea id="message-body" required rows="4" maxlength="65536"></textarea>
          <label for="message-reply" data-t="replyTo">Antwort auf Nachrichten-ID (optional)</label>
          <input id="message-reply" maxlength="128">
          <button class="np-button" type="submit" data-t="send">Nachricht senden</button>
        </form>
        <p class="meta" data-t="inboxNote">Nachrichten landen im Team-Postfach. Nur ein ausdrücklich erteilter Auftrag startet einen Arbeitsagenten.</p>
      </section>
      <section aria-labelledby="delegate-title"><h3 id="delegate-title" data-t="delegateTitle">Auftrag vergeben</h3>
        <form id="delegate-work" class="team-form">
          <label for="work-assignee" data-t="assignee">Verantwortlich</label>
          <select id="work-assignee" required></select>
          <label for="work-title" data-t="workTitle">Titel</label>
          <input id="work-title" required maxlength="240">
          <label for="work-body" data-t="body">Inhalt</label>
          <textarea id="work-body" required rows="4" maxlength="65536"></textarea>
          <label for="work-parent" data-t="parent">Übergeordneter Teamauftrag (optional)</label>
          <input id="work-parent" maxlength="128">
          <button class="np-button" type="submit" data-t="delegate">Auftrag erteilen</button>
        </form>
      </section>
    </div>
    <section aria-labelledby="work-heading"><h3 id="work-heading" data-t="workList">Gemeinsame Aufträge und Ergebnisse</h3>
      <div id="work-list"></div><button id="more-work" class="np-button" type="button" hidden data-t="more">Weitere laden</button>
    </section>
    <section aria-labelledby="messages-heading"><h3 id="messages-heading" data-t="messages">Adressierte Nachrichten</h3>
      <div id="messages"></div><button id="more-messages" class="np-button" type="button" hidden data-t="more">Weitere laden</button>
    </section>
    <details class="np-disclosure"><summary data-t="events">Teamereignisse</summary>
      <pre id="events" class="np-scroll" tabindex="0"></pre></details>
  </section>
  <footer class="np-meta"><p data-t="boundary">Rollen gelten innerhalb des Teams und erweitern keine Datei-, Programm- oder Kontoberechtigungen. Empfang, Ausführung und Ergebnis sind getrennt.</p>
    <p data-t="sessionBoundary">Automatische Aufträge starten separate verwaltete Agentendurchgänge. Bereits offene Terminal-Sitzungen werden nicht übernommen. ChatGPT und andere externe Mitglieder bearbeiten ihr Postfach über die Team-MCP-Werkzeuge.</p>
    <p data-t="unknownBoundary">Ein unklarer Ausgang wird nicht automatisch erneut ausgeführt. Angezeigt werden nur ausdrücklich geteilte Teamdaten.</p>
  </footer>
</main>
</body></html>
"""


JAVASCRIPT = r""""use strict";
const words = {
  de: {
    local: "Auf diesem Gerät · lokaler Zugang",
    intro: "Zusammenarbeiten, delegieren und Ergebnisse prüfen.",
    approvals: "Aufträge / Freigaben", refresh: "Aktualisieren",
    selectTeam: "Team auswählen", team: "Team", newTeam: "Neues Team anlegen",
    autoRefresh: "Sichtbare Seite alle 5 Sekunden aktualisieren",
    teamId: "Teamkennung", teamName: "Teamname", members: "Mitglieder",
    coordinator: "Koordinator", create: "Team anlegen", roles: "Mitglieder und Rollen",
    chooseCoordinator: "Koordinator wählen", saveCoordinator: "Koordinator festlegen",
    sendTitle: "Nachricht senden", recipient: "An", kind: "Art", body: "Inhalt",
    replyTo: "Antwort auf Nachrichten-ID (optional)", send: "Nachricht senden",
    inboxNote: "Nachrichten landen im Team-Postfach. Nur ein ausdrücklich erteilter Auftrag startet einen Arbeitsagenten.",
    delegateTitle: "Auftrag vergeben", assignee: "Verantwortlich", workTitle: "Titel",
    parent: "Übergeordneter Teamauftrag (optional)", delegate: "Auftrag erteilen",
    workList: "Gemeinsame Aufträge und Ergebnisse", messages: "Adressierte Nachrichten",
    events: "Teamereignisse", more: "Weitere laden", active: "Aktiv", save: "Rolle speichern",
    owner: "Eigentümer", revision: "Revision", claim: "Auftrag annehmen",
    result: "Ergebnis", report: "Eigenes Ergebnis melden", successful: "Erfolgreich",
    ack: "Empfang quittieren", acknowledged: "Empfang quittiert", unacknowledged: "Noch nicht quittiert",
    evidence: "Details und Belege", empty: "Noch keine Einträge.",
    sent: "Gespeichert. Der tatsächliche Ausführungsstand steht beim Auftrag.",
    connected: "Teamzustand gelesen. Eine konfigurierte CLI bestätigt keine Anmeldung oder Modellverfügbarkeit.",
    disabled: "Teamfunktion ist in der lokalen Konfiguration noch nicht aktiviert.",
    external: "Extern / manuell · keine automatische Sitzung",
    automatic: "Automatischer Empfänger eingerichtet · Anmeldung nicht geprüft",
    blocked: "Automatischer Empfänger unvollständig eingerichtet",
    noTeam: "Team anlegen oder auswählen. Vorhandene Einzelaufträge werden nicht übernommen.",
    boundary: "Rollen gelten innerhalb des Teams und erweitern keine Datei-, Programm- oder Kontoberechtigungen. Empfang, Ausführung und Ergebnis sind getrennt.",
    sessionBoundary: "Automatische Aufträge starten separate verwaltete Agentendurchgänge. Bereits offene Terminal-Sitzungen werden nicht übernommen. ChatGPT und andere externe Mitglieder bearbeiten ihr Postfach über die Team-MCP-Werkzeuge.",
    unknownBoundary: "Ein unklarer Ausgang wird nicht automatisch erneut ausgeführt. Angezeigt werden nur ausdrücklich geteilte Teamdaten.",
    rolesMap: {coordinator: "Koordinator", worker: "Bearbeiter", reviewer: "Prüfer", observer: "Beobachter"},
    states: {queued: "Wartet auf Ausführung", queued_manual: "Wartet auf externen Bearbeiter",
      dispatching: "Übergabe vorbereitet", created: "Wartet auf Freigabe",
      accepted: "Empfang bestätigt", accepted_manual: "Vom externen Bearbeiter angenommen",
      processing_result: "Bestätigtes Ergebnis wird verarbeitet",
      running: "Ausführung läuft", completed: "Durchgang beendet",
      failed: "Fehlgeschlagen", unknown: "Ausgang unklar", blocked: "Gesperrt",
      cancelled: "Abgebrochen", claimed: "Vom Bearbeiter angenommen", received: "Empfang bestätigt"},
    errors: {unauthorized: "Bitte den lokalen KiraBridge-Freigabestarter erneut öffnen.",
      csrf: "Bitte die Konsole über den lokalen KiraBridge-Starter öffnen.",
      forbidden: "Dieser Zugang hat nicht die erforderliche Team-Berechtigung.",
      team_disabled: "Die Teamfunktion ist in der lokalen Konfiguration noch nicht aktiviert.",
      team_revision_conflict: "Die Rollen wurden inzwischen geändert. Aktualisieren und erneut prüfen.",
      team_role_denied: "Die aktuelle Teamrolle erlaubt diese Aktion nicht.",
      team_member_denied: "Dieses Mitglied ist nicht als aktiver Teilnehmer eingerichtet.",
      team_owner_protected: "Der Eigentümer muss aktives Teammitglied bleiben.",
      team_coordinator_required: "Zuerst einen anderen aktiven Koordinator auswählen.",
      idempotency_conflict: "Die vorhandene Aktion hat einen anderen Inhalt. Zuerst ihren gespeicherten Auftrag prüfen.",
      payload_limit: "Der Inhalt überschreitet die eingerichtete Größenbegrenzung.",
      team_queue_full: "Die Warteschlange dieses Mitglieds ist voll.",
      team_assignee_denied: "Nur der verantwortliche externe Bearbeiter darf diesen Auftrag annehmen oder abschließen.",
      approval_required: "Dieser Zugang ist nicht für automatische Team-Schreibaktionen eingerichtet.",
      network: "Verbindung nicht bestätigt. Aktualisieren liest nur den bestehenden Zustand.",
      uncertain: "Die Antwort fehlt. Zuerst aktualisieren und nachsehen; der Auftrag wird nicht automatisch erneut gesendet.",
      storage: "Lokale Browserdaten sind gesperrt. Bitte den Freigabestarter erneut öffnen.",
      conflict: "Der Zustand wurde geändert. Aktualisieren und erneut prüfen.",
      generic: "Anfrage konnte nicht abgeschlossen werden."}
  },
  en: {
    local: "On this device · local principal",
    intro: "Work together, delegate and inspect results.", approvals: "Tasks / approvals",
    refresh: "Refresh", selectTeam: "Select team", team: "Team", newTeam: "Create team",
    autoRefresh: "Refresh the visible page every 5 seconds",
    teamId: "Team ID", teamName: "Team name", members: "Members",
    coordinator: "Coordinator", create: "Create team", roles: "Members and roles",
    chooseCoordinator: "Choose coordinator", saveCoordinator: "Set coordinator",
    sendTitle: "Send message", recipient: "To", kind: "Kind", body: "Body",
    replyTo: "Reply to message ID (optional)", send: "Send message",
    inboxNote: "Messages go to the team inbox. Only an explicitly assigned task starts a worker.",
    delegateTitle: "Assign work", assignee: "Assignee", workTitle: "Title",
    parent: "Parent team work ID (optional)", delegate: "Assign work",
    workList: "Shared work and results", messages: "Addressed messages",
    events: "Team events", more: "Load more", active: "Active", save: "Save role",
    owner: "Owner", revision: "Revision", claim: "Claim work", result: "Result",
    report: "Report own result", successful: "Successful", ack: "Acknowledge receipt",
    acknowledged: "Receipt acknowledged", unacknowledged: "Not acknowledged yet",
    evidence: "Details and evidence", empty: "No entries yet.",
    sent: "Saved. The task records its actual execution state.",
    connected: "Team state read. A configured CLI does not establish login or model availability.",
    disabled: "Team functionality has not been enabled in the local configuration.",
    external: "External / manual · no automatic session",
    automatic: "Automatic receiver configured · login not checked",
    blocked: "Automatic receiver configuration incomplete",
    noTeam: "Create or select a team. Existing private tasks are not imported.",
    boundary: "Roles apply within this team and do not widen file, executable or account permissions. Receipt, execution and result are separate.",
    sessionBoundary: "Automatic assignments start separate managed agent turns. Existing terminal sessions are not attached. ChatGPT and other external members handle their inbox through team MCP tools.",
    unknownBoundary: "An unknown outcome is never automatically rerun. Only intentionally shared team data is displayed.",
    rolesMap: {coordinator: "Coordinator", worker: "Worker", reviewer: "Reviewer", observer: "Observer"},
    states: {queued: "Waiting to execute", queued_manual: "Waiting for external assignee",
      dispatching: "Dispatch prepared", created: "Awaiting approval", accepted: "Receipt confirmed",
      accepted_manual: "Claimed by external assignee",
      processing_result: "Processing confirmed result",
      running: "Execution running", completed: "Turn ended", failed: "Failed",
      unknown: "Outcome unknown", blocked: "Blocked", cancelled: "Cancelled",
      claimed: "Claimed by assignee", received: "Receipt confirmed"},
    errors: {unauthorized: "Please reopen the local KiraBridge approval launcher.",
      csrf: "Please open the console through the local KiraBridge launcher.",
      forbidden: "This principal does not have the required team capability.",
      team_disabled: "Team functionality has not been enabled in the local configuration.",
      team_revision_conflict: "Roles changed in the meantime. Refresh and review again.",
      team_role_denied: "The current team role does not permit this action.",
      team_member_denied: "This identity is not configured as an active participant.",
      team_owner_protected: "The owner must remain an active team member.",
      team_coordinator_required: "Select a different active coordinator first.",
      idempotency_conflict: "The existing operation has different content. Inspect its stored work first.",
      payload_limit: "The content exceeds the configured size limit.",
      team_queue_full: "This member's work queue is full.",
      team_assignee_denied: "Only the responsible external assignee may claim or complete this work.",
      approval_required: "This principal is not configured for automatic team writes.",
      network: "Connection not confirmed. Refresh only reads existing state.",
      uncertain: "The response is missing. Refresh and inspect existing state first; the task is not automatically resent.",
      storage: "Local browser storage is blocked. Please reopen the approval launcher.",
      conflict: "The state changed. Refresh and review again.",
      generic: "The request could not be completed."}
  }
};
let language = "de";
try { language = localStorage.getItem("kirabridge.locale") || "de"; } catch (_) {}
if (!words[language]) language = "de";
const $ = id => document.getElementById(id);
const t = key => words[language][key] || key;
const node = (tag, value, cls) => {
  const result = document.createElement(tag);
  if (value !== undefined) result.textContent = value;
  if (cls) result.className = cls;
  return result;
};
let catalog = null, current = null, busy = false, uncertain = false;
const uncertainControls = new Map();
let pendingIntents = {};
try {
  const stored = JSON.parse(sessionStorage.getItem("kirabridge.team.intents") || "{}");
  if (stored && typeof stored === "object" && !Array.isArray(stored)) pendingIntents = stored;
} catch (_) {}
let workCursor = 0, messageCursor = 0;
const workRows = new Map(), messageRows = new Map();
function notice(value, error = false) {
  $("team-notice").textContent = value;
  $("team-notice").dataset.state = error ? "error" : "normal";
}
function showError(error) {
  const code = error.code || "generic";
  notice((words[language].errors[code] || words[language].errors.generic) +
    (error.serverCode ? " (" + error.serverCode + ")" : ""), true);
}
function fail(code, serverCode) {
  const error = new Error(code);
  error.code = code;
  error.serverCode = serverCode;
  return error;
}
async function api(path, payload) {
  let token;
  try { token = localStorage.getItem("kirabridge.session") || ""; }
  catch (_) { throw fail("storage"); }
  const options = {cache: "no-store", credentials: "omit",
    headers: {Authorization: "Bearer " + token, "Content-Type": "application/json"}};
  if (payload !== undefined) {
    options.method = "POST";
    options.body = JSON.stringify(payload);
  }
  let response, result;
  try { response = await fetch(path, options); }
  catch (_) { throw fail(payload === undefined ? "network" : "uncertain"); }
  try { result = await response.json(); }
  catch (_) { throw fail(payload === undefined ? "generic" : "uncertain"); }
  if (!response.ok) {
    if (payload !== undefined && response.status >= 500) throw fail("uncertain");
    const code = typeof result.error === "string" ? result.error : "generic";
    throw fail(words[language].errors[code] ? code : "generic", code);
  }
  return result;
}
function key() { return "browser-" + crypto.randomUUID(); }
function saveIntents() {
  try { sessionStorage.setItem("kirabridge.team.intents", JSON.stringify(pendingIntents)); }
  catch (_) { /* The current page still retains its pending idempotency keys. */ }
}
const base = () => "/api/team/" + encodeURIComponent(current.id || current.team_id);
function members() {
  const value = current.members || [];
  if (Array.isArray(value)) return value;
  return Object.entries(value).map(([principal, member]) =>
    typeof member === "string" ? {principal, role: member, active: true} : {principal, ...member});
}
const memberId = value => value.principal || value.member || value.name;
const isActive = value => value.active !== false && value.active !== 0;
function canManage() {
  const own = members().find(value => memberId(value) === catalog.principal);
  return current.owner === catalog.principal ||
    Boolean(own && isActive(own) && own.role === "coordinator");
}
function canWrite() {
  const own = members().find(value => memberId(value) === catalog.principal);
  return Boolean(own && isActive(own) && own.role !== "observer");
}
function selectOptions(select, values, selected) {
  const old = selected || select.value;
  select.replaceChildren();
  for (const value of values) {
    const option = node("option", value.label || value.id);
    option.value = value.id;
    select.append(option);
  }
  if (values.some(value => value.id === old)) select.value = old;
}
function translate() {
  document.documentElement.lang = language;
  document.querySelectorAll("[data-t]").forEach(item => { item.textContent = t(item.dataset.t); });
  document.querySelectorAll("[data-language]").forEach(item => {
    item.setAttribute("aria-pressed", String(item.dataset.language === language));
  });
  if (catalog) renderCatalog();
  if (current) renderTeam();
}
function renderCatalog() {
  const selected = $("team-select").value;
  const teams = catalog.teams.map(team => ({id: team.id || team.team_id,
    label: team.name + " · " + (team.id || team.team_id)}));
  selectOptions($("team-select"), [{id: "", label: "—"}, ...teams], selected);
  $("create-panel").hidden = !catalog.can_create || !catalog.enabled;
  const container = $("new-members");
  if (!container.childElementCount) {
    for (const value of catalog.roster) {
      const label = node("label", undefined, "inline");
      const input = node("input");
      input.type = "checkbox"; input.checked = true; input.value = value.principal;
      if (value.principal === catalog.principal) input.disabled = true;
      input.addEventListener("change", renderCreateCoordinator);
      const title = node("span", value.principal + " · " + t(value.execution));
      label.append(input, title); container.append(label);
    }
  }
  renderCreateCoordinator();
}
function renderCreateCoordinator() {
  const chosen = Array.from($("new-members").querySelectorAll("input:checked"))
    .map(input => ({id: input.value}));
  selectOptions($("new-coordinator"), chosen, $("new-coordinator").value || catalog.principal);
}
function renderTeam() {
  $("team-view").hidden = false;
  $("selected-title").textContent = current.name;
  $("team-meta").textContent = t("owner") + ": " + current.owner + " · " +
    t("revision") + ": " + current.revision;
  const roster = new Map(catalog.roster.map(value => [value.principal, value]));
  const active = [];
  const container = $("members"); container.replaceChildren();
  const present = new Set(members().map(memberId));
  const all = [...members(), ...catalog.roster.filter(value => !present.has(value.principal))
    .map(value => ({principal: value.principal, role: "worker", active: false}))];
  for (const member of all) {
    const id = memberId(member), profile = roster.get(id);
    const row = node("div", undefined, "member-row");
    const identity = node("div");
    identity.append(node("strong", id), node("p", profile ? t(profile.execution) : t("blocked"), "meta"));
    row.append(identity);
    if (isActive(member) && member.role !== "observer") active.push({id});
    const form = node("form", undefined, "np-actions");
    const role = node("select"); role.setAttribute("aria-label", id + " · " + t("roles"));
    selectOptions(role, Object.entries(words[language].rolesMap)
      .map(([value, label]) => ({id: value, label})), member.role);
    const label = node("label", undefined, "inline"), enabled = node("input");
    enabled.type = "checkbox"; enabled.checked = isActive(member);
    label.append(enabled, node("span", t("active")));
    const save = node("button", t("save"), "np-button"); save.type = "submit";
    role.disabled = enabled.disabled = save.disabled = !canManage();
    form.append(role, label, save); row.append(form); container.append(row);
    form.addEventListener("submit", event => {
      event.preventDefault();
      mutate(form, base() + "/roles", {member: id, role: role.value,
        active: enabled.checked, expected_revision: current.revision, idempotency_key: key()});
    });
  }
  $("change-coordinator").hidden = !canManage();
  selectOptions($("coordinator-select"), active, current.coordinator);
  const others = active.filter(value => value.id !== catalog.principal);
  selectOptions($("message-recipient"), others);
  selectOptions($("work-assignee"), active);
  for (const id of ["send-message", "delegate-work"]) {
    for (const control of $(id).elements) control.disabled = !canWrite();
  }
  renderWork(); renderMessages();
}
function detail(value) {
  const content = node("details", undefined, "np-disclosure");
  const output = node("pre", JSON.stringify(value, null, 2), "np-scroll");
  output.tabIndex = 0;
  content.append(node("summary", t("evidence")), output);
  return content;
}
function renderWork() {
  const container = $("work-list"); container.replaceChildren();
  for (const value of workRows.values()) {
    const card = node("article", undefined, "card");
    const line = node("div", undefined, "line");
    line.append(node("h4", value.title), node("span", words[language].states[value.state] || value.state));
    card.append(line, node("p", value.assigned_by + " → " + value.assignee, "meta"),
      node("p", value.id, "identifier"));
    if (value.result !== null && value.result !== undefined) {
      card.append(node("h4", t("result")), node("pre", typeof value.result === "string" ?
        value.result : JSON.stringify(value.result, null, 2), "np-scroll"));
    }
    card.append(detail(value));
    if (value.assignee === catalog.principal && value.state === "queued_manual") {
      const button = node("button", t("claim"), "np-button"); button.type = "button";
      button.addEventListener("click", () => mutate(button,
        base() + "/work/" + encodeURIComponent(value.id) + "/claim", {idempotency_key: key()}));
      card.append(button);
    }
    if (value.assignee === catalog.principal && value.state === "accepted_manual"
      && !value.core_task_id) {
      const form = node("form", undefined, "team-form");
      const label = node("label", t("result")), result = node("textarea");
      result.required = true; result.rows = 3; result.maxLength = 65536; label.append(result);
      const status = node("label", undefined, "inline"), success = node("input");
      success.type = "checkbox"; success.checked = true;
      status.append(success, node("span", t("successful")));
      const submit = node("button", t("report"), "np-button"); submit.type = "submit";
      form.append(label, status, submit);
      form.addEventListener("submit", event => {
        event.preventDefault();
        mutate(form, base() + "/work/" + encodeURIComponent(value.id) + "/complete",
          {result: result.value, success: success.checked, idempotency_key: key()});
      });
      card.append(form);
    }
    container.append(card);
  }
  if (!workRows.size) container.append(node("p", t("empty"), "empty"));
}
function renderMessages() {
  const container = $("messages"); container.replaceChildren();
  for (const value of messageRows.values()) {
    const card = node("article", undefined, "card");
    card.append(node("h4", value.sender + " → " + value.recipient + " · " + value.kind),
      node("pre", value.body, "np-scroll"), node("p", value.id, "identifier"),
      node("p", t(value.acknowledged ? "acknowledged" : "unacknowledged"), "meta"));
    if (value.recipient === catalog.principal && !value.acknowledged) {
      const button = node("button", t("ack"), "np-button"); button.type = "button";
      button.addEventListener("click", () => mutate(button,
        base() + "/messages/" + encodeURIComponent(value.id) + "/ack", {}));
      card.append(button);
    }
    card.append(detail(value)); container.append(card);
  }
  if (!messageRows.size) container.append(node("p", t("empty"), "empty"));
}
async function pages(append = false, which = "both") {
  const requests = [];
  if (which !== "messages") requests.push(api(base() + "/work?after=" + (append ? workCursor : 0))
    .then(data => {
      if (!append) workRows.clear();
      for (const value of data.work) workRows.set(value.id, value);
      workCursor = data.next_cursor;
      $("more-work").hidden = data.work.length < 50;
    }));
  if (which !== "work") requests.push(api(base() + "/messages?after=" + (append ? messageCursor : 0))
    .then(data => {
      if (!append) messageRows.clear();
      for (const value of data.messages) messageRows.set(value.id, value);
      messageCursor = data.next_cursor;
      $("more-messages").hidden = data.messages.length < 50;
    }));
  await Promise.all(requests);
  renderWork(); renderMessages();
}
async function loadSelected() {
  const id = $("team-select").value;
  if (!id) {
    current = null; $("team-view").hidden = true; notice(t("noTeam")); return;
  }
  current = await api("/api/team/" + encodeURIComponent(id));
  await pages();
  const events = await api(base() + "/events");
  $("events").textContent = JSON.stringify(events, null, 2);
  renderTeam();
}
async function refresh() {
  if (busy) return;
  busy = true;
  try {
    catalog = await api("/api/team");
    renderCatalog();
    if (!catalog.enabled) { notice(t("disabled")); return; }
    if (!$("team-select").value && catalog.teams.length === 1) {
      $("team-select").value = catalog.teams[0].id || catalog.teams[0].team_id;
    }
    await loadSelected();
    if (current) notice(t("connected"));
    uncertain = false;
    for (const [control, disabled] of uncertainControls) {
      control.disabled = disabled;
    }
    uncertainControls.clear();
  } catch (error) { showError(error); }
  finally { busy = false; }
}
async function mutate(source, path, payload, created = false) {
  if (busy || uncertain) return;
  busy = true;
  const controls = (source.elements ? Array.from(source.elements) : [source])
    .map(control => [control, control.disabled]);
  for (const [control] of controls) control.disabled = true;
  const intent = path + "|" + (payload.member || "") + "|" + (source.id || "");
  if (Object.hasOwn(payload, "idempotency_key")) {
    if (!Object.hasOwn(pendingIntents, intent)) pendingIntents[intent] = payload.idempotency_key;
    payload.idempotency_key = pendingIntents[intent];
    saveIntents();
  }
  let succeeded = false;
  try {
    const value = await api(path, payload);
    succeeded = true;
    delete pendingIntents[intent]; saveIntents();
    if (created) {
      catalog = await api("/api/team"); renderCatalog();
      $("team-select").value = value.id || value.team_id;
    }
    await loadSelected(); notice(t("sent"));
    if (source.id === "send-message") $("message-body").value = "";
    if (source.id === "delegate-work") {
      $("work-title").value = ""; $("work-body").value = "";
    }
  } catch (error) {
    if (error.code === "uncertain" || succeeded) {
      uncertain = true;
      for (const [control, disabled] of controls) uncertainControls.set(control, disabled);
      if (succeeded) error = fail("uncertain");
    } else {
      delete pendingIntents[intent]; saveIntents();
    }
    showError(error);
  } finally {
    if (!uncertain) for (const [control, disabled] of controls) control.disabled = disabled;
    busy = false;
  }
}
$("create-team").addEventListener("submit", event => {
  event.preventDefault();
  const selected = Array.from($("new-members").querySelectorAll("input:checked"));
  const coordinator = $("new-coordinator").value;
  const roles = Object.fromEntries(selected.map(input =>
    [input.value, input.value === coordinator ? "coordinator" : "worker"]));
  mutate(event.currentTarget, "/api/team", {team_id: $("new-id").value,
    name: $("new-name").value, members: roles, coordinator, idempotency_key: key()}, true);
});
$("change-coordinator").addEventListener("submit", event => {
  event.preventDefault();
  mutate(event.currentTarget, base() + "/roles", {member: $("coordinator-select").value,
    role: "coordinator", active: true, expected_revision: current.revision, idempotency_key: key()});
});
$("send-message").addEventListener("submit", event => {
  event.preventDefault();
  mutate(event.currentTarget, base() + "/messages", {recipient: $("message-recipient").value,
    body: $("message-body").value, kind: $("message-kind").value,
    reply_to: $("message-reply").value || null, idempotency_key: key()});
});
$("delegate-work").addEventListener("submit", event => {
  event.preventDefault();
  mutate(event.currentTarget, base() + "/work", {assignee: $("work-assignee").value,
    title: $("work-title").value, body: $("work-body").value,
    parent_id: $("work-parent").value || null, idempotency_key: key()});
});
$("team-select").addEventListener("change", refresh);
$("refresh").addEventListener("click", refresh);
for (const [id, which] of [["more-work", "work"], ["more-messages", "messages"]]) {
  $(id).addEventListener("click", async () => {
    if (busy) return;
    $("auto-refresh").checked = false;
    busy = true;
    try { await pages(true, which); } catch (error) { showError(error); }
    finally { busy = false; }
  });
}
document.querySelectorAll("[data-language]").forEach(button => {
  button.addEventListener("click", () => {
    language = button.dataset.language;
    try { localStorage.setItem("kirabridge.locale", language); } catch (_) {}
    translate();
  });
});
setInterval(() => {
  const editing = ["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement.tagName);
  if ($("auto-refresh").checked && !document.hidden && !editing && !busy) refresh();
}, 5000);
translate(); refresh();
"""


CSS = r""".team-form { display: grid; gap: var(--np-space-2); margin: var(--np-space-3) 0; }
.team-form label { margin-top: var(--np-space-2); }
.team-form input:not([type="checkbox"]), .team-form select, .team-form textarea,
#team-select { width: 100%; min-width: 0; box-sizing: border-box; }
select, input, textarea { color: var(--np-text); background: var(--np-canvas);
  border: 1px solid var(--np-control-border); padding: var(--np-space-2);
  font: inherit; min-height: var(--np-control); }
textarea { resize: vertical; }
input[type="checkbox"] { min-height: auto; width: 1.25em; height: 1.25em; }
.inline { display: flex; align-items: center; gap: var(--np-space-2); }
.member-row { display: flex; justify-content: space-between; flex-wrap: wrap;
  gap: var(--np-space-3); padding: var(--np-space-3) 0; border-bottom: 1px solid var(--np-divider); }
.member-row form { align-items: center; }
.team-columns { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: var(--np-space-5); margin: var(--np-space-5) 0; }
#team-view > section { margin-top: var(--np-space-5); }
#team-view > h3 { margin-top: var(--np-space-4); }
#team-notice[data-state="error"] { color: var(--np-danger); }
#new-members { display: grid; gap: var(--np-space-2); }
#new-members label { overflow-wrap: anywhere; }
.card h4 { margin: var(--np-space-2) 0; }
[hidden] { display: none !important; }
button:disabled { opacity: .6; }
@media (max-width: 700px) { .team-columns { grid-template-columns: 1fr; } }
"""
