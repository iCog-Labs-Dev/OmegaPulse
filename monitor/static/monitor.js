"use strict";

const logView = document.getElementById("logs");
const filterInput = document.getElementById("filter");
const pauseButton = document.getElementById("pause");
const connectionState = document.getElementById("connection-state");
const statusBox = document.getElementById("status");
const statusText = document.getElementById("status-text");
const actionState = document.getElementById("action-state");
const actionButtons = Array.from(document.querySelectorAll("[data-action]"));
const csrfToken = document.querySelector("meta[name='csrf-token']").content;
const securityState = document.getElementById("security-state");
const securityView = document.getElementById("security-events");
const securityRecords = [];
let securitySource = null;
const maximumLines = Number.parseInt(document.body.dataset.logLimit, 10) || 1000;
const records = [];
let paused = false;
let pendingRender = false;

function scheduleRender() {
  if (paused || pendingRender) return;
  pendingRender = true;
  window.requestAnimationFrame(() => {
    pendingRender = false;
    const needle = filterInput.value.toLocaleLowerCase();
    const visible = needle
      ? records.filter((record) => record.toLocaleLowerCase().includes(needle))
      : records;
    // textContent is deliberate: container output must never be interpreted as HTML.
    logView.textContent = visible.join("\n");
    logView.scrollTop = logView.scrollHeight;
  });
}

function appendRecord(record) {
  records.push(record);
  if (records.length > maximumLines) {
    records.splice(0, records.length - maximumLines);
  }
  scheduleRender();
}

function parseEvent(event, system) {
  try {
    const item = JSON.parse(event.data);
    const prefix = system ? `[monitor ${item.timestamp || ""}] ` : "";
    appendRecord(prefix + String(item.text || ""));
  } catch (_error) {
    appendRecord("[monitor] Received a malformed log event.");
  }
}

function connectLogs() {
  const source = new EventSource("/api/logs");
  source.addEventListener("auth-expired", () => { source.close(); window.location.assign("/login"); });
  source.onopen = () => {
    connectionState.textContent = "Live";
    connectionState.className = "connected";
  };
  source.addEventListener("log", (event) => parseEvent(event, false));
  source.addEventListener("system", (event) => parseEvent(event, true));
  source.onerror = () => {
    connectionState.textContent = "Disconnected — retrying";
    connectionState.className = "disconnected";
  };
}

function renderSecurityEvents() {
  securityView.replaceChildren();
  for (const item of securityRecords) {
    const article = document.createElement("article");
    article.className = `security-event priority-${item.priority.toLocaleLowerCase()}`;
    const heading = document.createElement("strong");
    heading.textContent = `${item.priority} — ${item.rule}`;
    const timestamp = document.createElement("time");
    timestamp.textContent = item.timestamp;
    const detail = document.createElement("pre");
    detail.textContent = item.text;
    article.append(heading, timestamp, detail);
    securityView.append(article);
  }
}

function connectSecurityEvents() {
  if (securitySource) return;
  securitySource = new EventSource("/api/security/events");
  securitySource.addEventListener("auth-expired", () => { securitySource.close(); window.location.assign("/login"); });
  securitySource.addEventListener("security", (event) => {
    try {
      securityRecords.push(JSON.parse(event.data));
      if (securityRecords.length > 500) securityRecords.splice(0, securityRecords.length - 500);
      renderSecurityEvents();
      securityState.textContent = "Detector connected";
    } catch (_error) {
      securityState.textContent = "Malformed detector event ignored";
    }
  });
  securitySource.addEventListener("system", (event) => {
    try { securityState.textContent = JSON.parse(event.data).text; }
    catch (_error) { securityState.textContent = "Detector stream error"; }
  });
  securitySource.onerror = () => { securityState.textContent = "Detector stream disconnected — retrying"; };
}

async function refreshSecurityStatus() {
  try {
    const response = await fetch("/api/security/status", {cache: "no-store"});
    if (response.status === 401) { window.location.assign("/login"); return; }
    const data = await response.json();
    const labels = {
      available: "Detector event file available",
      "not-configured": "Detector not configured",
      "waiting-for-events-file": "Waiting for detector event file",
      "events-file-unreadable": "Detector event file is unreadable",
    };
    securityState.textContent = labels[data.state] || "Detector state unknown";
    if (data.configured) connectSecurityEvents();
  } catch (_error) {
    securityState.textContent = "Detector status unavailable";
  }
}

async function refreshStatus() {
  try {
    const response = await fetch("/api/status", {cache: "no-store"});
    if (response.status === 401) { window.location.assign("/login"); return; }
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    statusBox.className = `status ${data.state}`;
    const labels = {
      running: "Running (health unknown)",
      stopped: "Stopped",
      restarting: "Restarting",
      missing: "Container missing",
      "docker-unavailable": "Docker unavailable",
    };
    statusText.textContent = labels[data.state] || "Unknown";
  } catch (_error) {
    statusBox.className = "status docker-unavailable";
    statusText.textContent = "Monitor status unavailable";
  }
}

async function performAction(action) {
  const labels = {start: "start", stop: "STOP", restart: "RESTART"};
  if (!window.confirm(`Confirm ${labels[action]} of the configured container?`)) return;
  actionButtons.forEach((button) => { button.disabled = true; });
  actionState.textContent = `${labels[action]} requested…`;
  try {
    const response = await fetch(`/api/actions/${action}`, {
      method: "POST",
      headers: {"Content-Type": "application/json", "X-CSRF-Token": csrfToken},
      body: "{}",
    });
    if (response.status === 401) { window.location.assign("/login"); return; }
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
    actionState.textContent = `${labels[action]} completed`;
    await refreshStatus();
  } catch (error) {
    actionState.textContent = `Action failed: ${error.message}`;
  } finally {
    actionButtons.forEach((button) => { button.disabled = false; });
  }
}

pauseButton.addEventListener("click", () => {
  paused = !paused;
  pauseButton.textContent = paused ? "Resume" : "Pause";
  pauseButton.setAttribute("aria-pressed", String(paused));
  connectionState.textContent = paused ? "Display paused; collection continues" : "Live";
  if (!paused) scheduleRender();
});
filterInput.addEventListener("input", scheduleRender);
actionButtons.forEach((button) => {
  button.addEventListener("click", () => performAction(button.dataset.action));
});
document.getElementById("clear-security").addEventListener("click", () => {
  securityRecords.length = 0;
  renderSecurityEvents();
});

connectLogs();
refreshStatus();
refreshSecurityStatus();
window.setInterval(refreshStatus, 5000);
window.setInterval(refreshSecurityStatus, 5000);

document.getElementById("logout").addEventListener("click", async () => {
  const response = await fetch("/logout", {method: "POST", headers: {"X-CSRF-Token": csrfToken}});
  if (response.ok || response.status === 401) window.location.assign("/login");
});
