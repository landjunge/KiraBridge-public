"use strict";
const catalog = {
  de: {
    title: "KiraBridge · Aufträge", localDevice: "Auf diesem Gerät", intro: "Aufträge prüfen und ihre Ausführung verfolgen.", refresh: "Aktualisieren", approvalMode: "Freigabemodus", pending: "Deine Entscheidung", recent: "Aufträge und Ergebnisse", connecting: "Verbindung wird geprüft …", connected: "Mit der lokalen KiraBridge-Konsole verbunden. Das bestätigt noch keine vollständige Arbeitsbereitschaft.", boundary: "Der Freigabemodus gilt je Zugang und innerhalb seiner eingerichteten Rechte. Empfang, Ausführung und Abnahme des Gesamtauftrags sind getrennte Nachweise.", limitedList: "Bis zu 100 Vorgänge werden angezeigt. Eine Verbindungsstörung startet keinen Auftrag erneut.", automatic: "Ohne zusätzlichen Freigabeklick: {names}. Nur eingerichtete Fähigkeiten starten automatisch.", manual: "Mit Freigabe je neuem Auftrag: {names}.", modeUnknown: "Freigabemodus noch nicht bestätigt.", from: "Von {name}", adapter: "Adapter {name}", details: "Auftrag und Ergebnis ansehen", requestDetails: "Auftragsinhalt prüfen", result: "Ergebnis dieses Vorgangs", error: "Fehler", evidence: "Technische Belege", parent: "Übergeordneter Auftrag", receipt: "Empfangsbestätigung", taskId: "Auftragskennung", approve: "Diesen Auftrag freigeben", deny: "Ablehnen", cancel: "Vor Ausführung abbrechen", approved: "Dieser Auftrag ist freigegeben. Sein tatsächlicher Ausführungsstatus steht beim Auftrag.", denied: "Dieser Auftrag wurde abgelehnt oder abgebrochen.", noPending: "Keine offene Entscheidung. Neue freigabepflichtige Aufträge erscheinen hier.", noRecent: "Noch keine weiteren Aufträge vorhanden.", loadDetails: "Auftragsdetails werden gelesen …", noArgs: "Keine zusätzlichen Auftragsfelder.", unknownTime: "Zeitpunkt nicht verfügbar", scrollValue: "Wert · mit Tastatur scrollbar",
    states: { created: "Wartet auf Freigabe", queued: "Freigegeben · wartet auf Ausführung", accepted: "Empfang bestätigt", running: "Ausführung läuft", completed: "Ausführung beendet", failed: "Fehlgeschlagen", unknown: "Ausgang unklar", cancelled: "Abgelehnt oder abgebrochen", blocked: "Gesperrt" },
    notes: { created: "Noch nicht gestartet. Die Freigabe gilt nur für den hier dargestellten Auftrag.", queued: "Freigegeben; ein Ausführungsstart ist damit noch nicht belegt.", accepted: "Der Empfang ist quittiert; ein Abschluss ist damit nicht belegt.", running: "Dieser Vorgang läuft. Sein Ende ist noch nicht belegt.", completed: "Nur dieser Vorgang ist beendet. Der Gesamtauftrag ist damit nicht abgenommen.", failed: "Fehler und mögliche Teilwirkung in den Details prüfen.", unknown: "Vorhandene Belege lesen und den Ausgang klären. Nicht automatisch erneut starten.", cancelled: "Umfang und mögliche frühere Wirkung anhand der Belege prüfen.", blocked: "Berechtigung oder Voraussetzung fehlt. Diese Anzeige erteilt keine Freigabe." },
    agentCompleted: "Agentendurchgang beendet",
    operations: { "file.list": "Ordner anzeigen", "file.read": "Datei lesen", "file.write": "Datei schreiben", "file.mkdir": "Ordner erstellen", "file.move": "Datei oder Ordner verschieben", "file.delete": "Datei löschen", "terminal.execute": "Befehl ausführen", "agent.execute": "KI-Agent beauftragen", "clipboard.read": "Zwischenablage lesen", "clipboard.write": "Zwischenablage schreiben", "clipboard.info": "Zwischenablage prüfen", "process.list": "Prozesse anzeigen", "process.inspect": "Prozess prüfen", "process.terminate": "Prozess beenden", "threaddesk.read": "ThreadDesk lesen", "threaddesk.manage": "ThreadDesk verwalten", "workflow.execute": "Zugeordneten Auftrag ausführen" },
    fields: { path: "Datei oder Ordner", destination: "Ziel", text: "Text", overwrite: "Vorhandenen Inhalt ersetzen", argv: "Befehl und Argumente", cwd: "Arbeitsordner", timeout: "Zeitlimit (Sekunden)", max_output: "Ausgabegrenze (Bytes)", max_bytes: "Lesegrenze (Bytes)", agent: "Agent", prompt: "Auftrag an den Agenten", task_id: "Betroffener Auftrag", operation_id: "Operationskennung", expected_revision: "Erwartete Revision", action: "Fachaktion", arguments: "Fachargumente", data: "Auftragsdaten" },
    errors: { unauthorized: "Öffne den lokalen KiraBridge-Freigabestarter oder kirabridge approvals, um diesen Browser anzumelden.", state_conflict: "Der Auftrag hat inzwischen seinen Zustand geändert. Bitte aktualisieren.", review_conflict: "Der angezeigte Auftrag stimmt nicht mehr überein. Aktualisieren und erneut prüfen.", csrf: "Öffne die Freigaben direkt über den lokalen KiraBridge-Starter.", forbidden: "Die eingerichteten Berechtigungen erlauben diesen Auftrag nicht.", storage: "Lokale Browserdaten sind gesperrt. Erlaube sie für diese lokale Adresse und öffne den Freigabestarter erneut.", network: "Verbindung nicht bestätigt. Aktualisieren liest den bestehenden Zustand, ohne einen Auftrag erneut zu starten.", uncertain: "Die Antwort auf die Entscheidung fehlt; ihr Ausgang ist unklar. Zuerst aktualisieren und vorhandene Belege lesen, nicht blind erneut freigeben.", generic: "Die Anfrage konnte nicht abgeschlossen werden." }
  },
  en: {
    title: "KiraBridge · Tasks", localDevice: "On this device", intro: "Review tasks and follow their execution.", refresh: "Refresh", approvalMode: "Approval mode", pending: "Your decision", recent: "Tasks and results", connecting: "Checking connection …", connected: "Connected to the local KiraBridge console. This does not confirm every workflow prerequisite.", boundary: "Approval mode applies per principal within its configured permissions. Receipt, execution and acceptance of the overall assignment are separate evidence.", limitedList: "Up to 100 tasks are shown. A connection failure does not restart a task.", automatic: "No additional approval click: {names}. Only configured capabilities start automatically.", manual: "Approval for each new task: {names}.", modeUnknown: "Approval mode has not been confirmed.", from: "From {name}", adapter: "Adapter {name}", details: "Inspect task and result", requestDetails: "Review the request", result: "Result of this task", error: "Error", evidence: "Technical evidence", parent: "Parent task", receipt: "Receipt", taskId: "Task ID", approve: "Approve this task", deny: "Deny", cancel: "Cancel before execution", approved: "This task is approved. Its actual execution state is shown on the task.", denied: "This task was denied or cancelled.", noPending: "No decision pending. New tasks requiring approval appear here.", noRecent: "No other tasks yet.", loadDetails: "Reading task details …", noArgs: "No additional request fields.", unknownTime: "Time not available", scrollValue: "Value · scroll with keyboard",
    states: { created: "Awaiting approval", queued: "Approved · waiting to execute", accepted: "Receipt confirmed", running: "Execution running", completed: "Execution ended", failed: "Failed", unknown: "Outcome unknown", cancelled: "Denied or cancelled", blocked: "Blocked" },
    notes: { created: "Not started. Approval applies only to the request shown here.", queued: "Approved; this alone is not evidence that execution started.", accepted: "Receipt acknowledged; completion is not established.", running: "This task is running. Its end has not been established.", completed: "Only this task ended. The overall assignment is not accepted on that basis.", failed: "Inspect the error and possible partial effects in the details.", unknown: "Read existing evidence and establish the outcome. Do not restart automatically.", cancelled: "Check the evidence for scope and any earlier effects.", blocked: "A permission or prerequisite is missing. This display grants no approval." },
    agentCompleted: "Agent turn ended",
    operations: { "file.list": "List directory", "file.read": "Read file", "file.write": "Write file", "file.mkdir": "Create directory", "file.move": "Move file or directory", "file.delete": "Delete file", "terminal.execute": "Run command", "agent.execute": "Assign AI agent", "clipboard.read": "Read clipboard", "clipboard.write": "Write clipboard", "clipboard.info": "Inspect clipboard", "process.list": "List processes", "process.inspect": "Inspect process", "process.terminate": "Terminate process", "threaddesk.read": "Read ThreadDesk", "threaddesk.manage": "Manage ThreadDesk", "workflow.execute": "Execute bound assignment" },
    fields: { path: "File or directory", destination: "Destination", text: "Text", overwrite: "Replace existing content", argv: "Command and arguments", cwd: "Working directory", timeout: "Time limit (seconds)", max_output: "Output limit (bytes)", max_bytes: "Read limit (bytes)", agent: "Agent", prompt: "Instruction to the agent", task_id: "Referenced task", operation_id: "Operation ID", expected_revision: "Expected revision", action: "Domain action", arguments: "Domain arguments", data: "Request data" },
    errors: { unauthorized: "Open the local KiraBridge approval launcher or kirabridge approvals to sign this browser in.", state_conflict: "The task state changed. Please refresh.", review_conflict: "The displayed request no longer matches. Refresh and review it again.", csrf: "Open approvals through the local KiraBridge launcher.", forbidden: "Configured permissions do not allow this task.", storage: "Local browser storage is blocked. Allow it for this local address and reopen the approval launcher.", network: "Connection not confirmed. Refresh reads existing state without restarting a task.", uncertain: "The decision response is missing; its outcome is unknown. Refresh and inspect existing evidence before attempting approval again.", generic: "The request could not be completed." }
  }
};
const principals = { chatgpt: "ChatGPT", codex: "Codex", grok: "Grok", local: { de: "lokaler Zugang", en: "local principal" } };
let language = "de";
try { language = localStorage.getItem("kirabridge.locale") || (navigator.language.startsWith("en") ? "en" : "de"); } catch (_) { /* Cosmetic preference only; no authentication fallback. */ }
if (!catalog[language]) language = "de";
const text = (key, values = {}) => Object.entries(values).reduce((out, [name, value]) => out.replaceAll("{" + name + "}", value), catalog[language][key] || key);
const principalName = name => typeof principals[name] === "object" ? principals[name][language] : principals[name] || name;
const message = document.getElementById("message");
let loading = false;
let hadRefreshError = false;
let lastData = null;
let notice = {key: "connecting", values: {}, error: false};
function setNotice(key, values = {}, error = false) {
  notice = {key, values, error};
  message.textContent = text(key, values);
  message.dataset.state = error ? "error" : "normal";
}
function showError(error) {
  message.dataset.state = "error";
  message.textContent = error.message;
  notice = {errorCode: error.code || "generic"};
}
function failure(code) {
  const error = new Error(catalog[language].errors[code] || catalog[language].errors.generic);
  error.code = code;
  return error;
}
async function api(path, options = {}) {
  let token;
  try { token = localStorage.getItem("kirabridge.session") || ""; } catch (_) { throw failure("storage"); }
  let response;
  try {
    response = await fetch(path, { ...options, cache: "no-store", headers: {
      "Authorization": "Bearer " + token, "Content-Type": "application/json"
    }});
  } catch (_) { throw failure(options.method === "POST" ? "uncertain" : "network"); }
  let data;
  try { data = await response.json(); } catch (_) { throw failure(options.method === "POST" ? "uncertain" : "generic"); }
  if (!response.ok) throw failure(data.error || "generic");
  return data;
}
function element(tag, value, className) {
  const node = document.createElement(tag);
  if (value !== undefined) node.textContent = value;
  if (className) node.className = className;
  if (tag === "pre") { node.tabIndex = 0; node.setAttribute("aria-label", text("scrollValue")); }
  return node;
}
function stateLabel(task) {
  return task.operation === "agent.execute" && task.state === "completed" ? text("agentCompleted") : catalog[language].states[task.state] || task.state;
}
function timeLabel(value) {
  if (!value) return text("unknownTime");
  const date = new Date(typeof value === "number" ? value * 1000 : value);
  return Number.isNaN(date.getTime()) ? text("unknownTime") : new Intl.DateTimeFormat(language === "de" ? "de-DE" : "en-GB", {dateStyle: "short", timeStyle: "medium"}).format(date);
}
function card(task) {
  const node = element("article", undefined, "card");
  node.dataset.taskId = task.id;
  node.dataset.state = task.state;
  node.dataset.locale = language;
  const line = element("div", undefined, "line");
  line.append(element("h3", catalog[language].operations[task.operation] || task.operation), element("span", stateLabel(task), "state " + task.state));
  const metadata = value => text("from", {name: principalName(value.principal)}) + (value.agent ? " · " + text("adapter", {name: value.agent}) : "") + " · " + timeLabel(value.updated);
  const meta = element("p", metadata(task), "meta");
  node.append(line, meta);
  const explanation = element("p", catalog[language].notes[task.state] || "", "status-note");
  node.append(explanation);
  const details = element("details", undefined, "np-disclosure");
  details.append(element("summary", text("details")));
  const content = element("div", undefined, "detail-content");
  details.append(content);
  node.append(details);
  let busy = false;
  async function loadDetails() {
    if (!details.open || content.childElementCount || busy) return;
    busy = true;
    try {
      const data = await api("/api/tasks/" + encodeURIComponent(task.id));
      if (!node.isConnected) return;
      const value = data.task;
      if (value.state !== node.dataset.state) return;
      content.append(element("h3", text("requestDetails")));
      const args = Object.entries(value.args || {});
      if (!args.length) content.append(element("p", text("noArgs"), "meta"));
      for (const [name, argument] of args) {
        content.append(element("p", catalog[language].fields[name] || name, "field-label"), element("pre", typeof argument === "string" ? argument : JSON.stringify(argument, null, 2), "np-scroll"));
      }
      const actions = element("div", undefined, "actions np-actions");
      const choices = value.state === "created" ? [["approve", "approve"], ["deny", "deny"]] : value.state === "queued" ? [["deny", "cancel"]] : [];
      for (const [decision, title] of choices) {
        const button = element("button", text(title), "np-button");
        if (decision === "approve") button.dataset.variant = "primary";
        button.type = "button";
        button.addEventListener("click", async () => {
          for (const control of actions.children) control.disabled = true;
          try {
            await api("/api/tasks/" + encodeURIComponent(task.id) + "/" + decision, {method: "POST", body: JSON.stringify({request_hash: data.request_hash})});
            setNotice(decision === "approve" ? "approved" : "denied");
            await refresh(false, true);
            document.getElementById("refresh").focus();
          } catch (error) { showError(error); }
        });
        actions.append(button);
      }
      if (actions.childElementCount) content.append(actions);
      if (value.result !== null && value.result !== undefined) content.append(element("h3", text("result")), element("pre", JSON.stringify(value.result, null, 2), "np-scroll"));
      if (value.error) content.append(element("h3", text("error")), element("pre", JSON.stringify(value.error, null, 2), "np-scroll"));
      const evidence = element("details", undefined, "np-disclosure");
      evidence.append(element("summary", text("evidence")), element("p", text("taskId") + ": " + task.id, "identifier"));
      if (value.parent_id) evidence.append(element("p", text("parent") + ": " + value.parent_id, "identifier"));
      if (value.receipt) evidence.append(element("p", text("receipt") + ": " + value.receipt, "identifier"));
      if (value.evidence && Object.keys(value.evidence).length) evidence.append(element("pre", JSON.stringify(value.evidence, null, 2), "np-scroll"));
      content.append(evidence);
    } catch (error) { showError(error); }
    finally { busy = false; }
  }
  details.addEventListener("toggle", loadDetails);
  node.addEventListener("task-update", event => {
    const current = event.detail;
    const badge = node.querySelector(".state");
    meta.textContent = metadata(current);
    badge.textContent = stateLabel(current);
    badge.className = "state " + current.state;
    explanation.textContent = catalog[language].notes[current.state] || "";
    if (node.dataset.state !== current.state) {
      node.dataset.state = current.state;
      content.replaceChildren();
    }
    if (details.open) loadDetails();
  });
  return node;
}
function render(data, force = false) {
  const auto = [], manual = [];
  for (const [name, mode] of Object.entries(data.approval_modes || {})) {
    if (mode === "automatic") auto.push(principalName(name));
    if (mode === "manual") manual.push(principalName(name));
  }
  const modes = document.getElementById("approval-mode");
  modes.replaceChildren();
  if (auto.length) modes.append(element("p", text("automatic", {names: auto.join(", ")})));
  if (manual.length) modes.append(element("p", text("manual", {names: manual.join(", ")})));
  if (!auto.length && !manual.length) modes.append(element("p", text("modeUnknown")));
  document.getElementById("count").textContent = data.pending;
  const pending = document.getElementById("pending"), recent = document.getElementById("recent");
  const retained = new Map(), opened = new Set();
  for (const node of document.querySelectorAll("article[data-task-id]")) {
    if (node.querySelector("details[open]")) {
      opened.add(node.dataset.taskId);
      if (!force && node.dataset.locale === language) retained.set(node.dataset.taskId, node);
    }
  }
  pending.replaceChildren(); recent.replaceChildren();
  for (const task of data.tasks) {
    const node = retained.get(task.id) || card(task);
    node.dispatchEvent(new CustomEvent("task-update", {detail: task}));
    (task.state === "created" ? pending : recent).append(node);
    if (opened.has(task.id)) node.querySelector("details").open = true;
  }
  if (!data.pending) pending.append(element("p", text("noPending"), "empty"));
  if (!recent.childElementCount) recent.append(element("p", text("noRecent"), "empty"));
}
function translate() {
  document.documentElement.lang = language;
  document.title = text("title");
  document.querySelectorAll("[data-i18n]").forEach(node => { node.textContent = text(node.dataset.i18n); });
  document.querySelectorAll("[data-language]").forEach(node => { node.setAttribute("aria-pressed", String(node.dataset.language === language)); });
  if (lastData) render(lastData, true);
  if (notice.errorCode) showError(failure(notice.errorCode));
  else setNotice(notice.key, notice.values, notice.error);
}
async function refresh(announce = true, force = false) {
  if (loading || (document.hidden && !announce)) return;
  loading = true;
  try {
    const data = await api("/api/tasks");
    lastData = data;
    render(data, force);
    if (announce || hadRefreshError) setNotice("connected");
    hadRefreshError = false;
  } catch (error) { showError(error); hadRefreshError = true; }
  finally { loading = false; }
}
document.querySelectorAll("[data-language]").forEach(button => button.addEventListener("click", () => {
  language = button.dataset.language;
  try { localStorage.setItem("kirabridge.locale", language); } catch (_) { /* Preferences never grant access. */ }
  translate();
}));
document.getElementById("refresh").addEventListener("click", () => refresh(true, true));
translate();
setInterval(() => refresh(false), 5000);
refresh();
