"use strict";
// uBix Vault console. Vanilla JS, no dependencies. Secret values are rendered via
// textContent only (never innerHTML), so a value can't inject markup.

const $ = (id) => document.getElementById(id);
const TOKEN_KEY = "ubixvault.token";

const getToken = () => sessionStorage.getItem(TOKEN_KEY) || "";
function setToken(t) {
  if (t) sessionStorage.setItem(TOKEN_KEY, t);
  else sessionStorage.removeItem(TOKEN_KEY);
  reflectToken();
}
function reflectToken() {
  const tag = $("token-state");
  const has = !!getToken();
  tag.textContent = has ? "token set" : "no token";
  tag.dataset.set = String(has);
}

// api performs a same-origin request, attaching the token and JSON body if given.
async function api(method, path, body) {
  const headers = {};
  const tok = getToken();
  if (tok) headers["X-Vault-Token"] = tok;
  const opts = { method, headers };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  let payload = null;
  try { payload = await res.json(); } catch (_) { /* 204 / empty */ }
  return { status: res.status, ok: res.ok, body: payload };
}

function friendlyError(status, body) {
  const detail = body && body.errors && body.errors.length ? " — " + body.errors.join("; ") : "";
  switch (status) {
    case 0: return "Can't reach the vault.";
    case 401:
    case 403: return "Not authorized — check your token." + detail;
    case 404: return "No secret at that path." + detail;
    case 501: return "Vault is not initialized.";
    case 503: return "Vault is sealed." + detail;
    default: return "Request failed (" + status + ")" + detail;
  }
}

// ---- seal state ----
function fmtUptime(s) {
  s = Math.floor(s || 0);
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600),
    m = Math.floor((s % 3600) / 60), sec = s % 60;
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${sec}s`;
  return `${sec}s`;
}

async function refreshStatus() {
  const el = $("seal");
  try {
    const [health, seal] = await Promise.all([
      api("GET", "/v1/sys/health"),
      api("GET", "/v1/sys/seal-status"),
    ]);
    const st = seal.body || {};
    const h = health.body || {};
    $("version").textContent = h.version ? "v" + h.version : "";
    $("m-init").textContent = st.initialized ? "yes" : "no";
    $("m-type").textContent = st.type || "—";
    $("m-uptime").textContent = h.uptime_seconds != null ? fmtUptime(h.uptime_seconds) : "—";

    let state, word, tag;
    if (!st.initialized) {
      state = "uninitialized"; word = "Uninitialized"; tag = "Run operator init to set up the vault";
    } else if (st.sealed) {
      state = "sealed"; word = "Sealed"; tag = "The vault is locked; unseal to serve secrets";
    } else {
      state = "unsealed"; word = "Unsealed"; tag = "The vault is unlocked and serving";
    }
    el.dataset.state = state;
    $("seal-word").textContent = word;
    $("seal-tagline").textContent = tag;
  } catch (_) {
    el.dataset.state = "error";
    $("seal-word").textContent = "Unreachable";
    $("seal-tagline").textContent = "Could not reach the vault";
  }
}

// ---- KV paths ----
const KV_DATA = (p) => "/v1/secret/data/" + p;
const KV_META = (p) => "/v1/secret/metadata/" + p;
const KV_UNDELETE = (p) => "/v1/secret/undelete/" + p;

function cleanPath(raw) {
  let p = (raw || "").trim().replace(/^\/+/, "");
  p = p.replace(/^secret\/(data|metadata)\//, ""); // tolerate a pasted full path
  return p;
}

function outMsg(cls, text) {
  const out = $("kv-out");
  out.replaceChildren();
  const d = document.createElement("div");
  d.className = "msg " + cls;
  d.textContent = text;
  out.appendChild(d);
}

function actionButton(label, cls, onClick) {
  const b = document.createElement("button");
  b.type = "button"; b.textContent = label;
  if (cls) b.className = cls;
  b.addEventListener("click", onClick);
  return b;
}

// ---- read + lifecycle ----
// Reading a soft-deleted current version returns 404 on the data endpoint but
// the metadata endpoint still describes it, so fall back to metadata to show the
// deleted state (and the Undelete action).
async function kvRead(path) {
  const p = cleanPath(path);
  if (!p) { outMsg("error", "Enter a secret path."); return; }
  const r = await api("GET", KV_DATA(p));
  if (r.ok) { renderSecret(p, r.body); return; }
  if (r.status === 404) {
    const meta = await api("GET", KV_META(p));
    if (meta.ok) { renderDeleted(p, meta.body); return; }
  }
  outMsg("error", friendlyError(r.status, r.body));
}

function renderSecret(p, body) {
  const data = (body && body.data && body.data.data) || {};
  const meta = (body && body.data && body.data.metadata) || {};
  const out = $("kv-out");
  out.replaceChildren();

  const keys = Object.keys(data);
  if (!keys.length) {
    const m = document.createElement("div");
    m.className = "msg ok"; m.textContent = "Secret at “" + p + "” has no fields.";
    out.appendChild(m);
  } else {
    const table = document.createElement("table");
    table.className = "kv-table";
    for (const k of keys) {
      const tr = document.createElement("tr");
      const th = document.createElement("th"); th.textContent = k;
      const td = document.createElement("td");
      td.textContent = typeof data[k] === "string" ? data[k] : JSON.stringify(data[k]);
      tr.append(th, td);
      table.appendChild(tr);
    }
    out.appendChild(table);
  }

  if (meta.version != null) {
    const line = document.createElement("div");
    line.className = "kv-metaline";
    line.textContent = "version " + meta.version + (meta.created_time ? " · created " + meta.created_time : "");
    out.appendChild(line);
  }

  const actions = document.createElement("div");
  actions.className = "kv-actions";
  actions.appendChild(actionButton("Edit", "", () => openEditor(p, data)));
  actions.appendChild(actionButton("Delete (soft)", "btn-danger", () => kvDelete(p)));
  out.appendChild(actions);
}

function renderDeleted(p, body) {
  const md = (body && body.data) || {};
  const cv = md.current_version;
  const vinfo = (md.versions && md.versions[String(cv)]) || {};
  const out = $("kv-out");
  out.replaceChildren();

  const m = document.createElement("div");
  m.className = "msg";
  m.textContent = vinfo.destroyed
    ? "Version " + cv + " of “" + p + "” is destroyed (permanently gone)."
    : "Version " + cv + " of “" + p + "” is soft-deleted.";
  out.appendChild(m);

  const actions = document.createElement("div");
  actions.className = "kv-actions";
  if (!vinfo.destroyed) {
    actions.appendChild(actionButton("Undelete", "", () => kvUndelete(p, cv)));
    actions.appendChild(actionButton("New version", "", () => openEditor(p, null)));
  }
  if (actions.childElementCount) out.appendChild(actions);
}

async function kvDelete(path) {
  const r = await api("DELETE", KV_DATA(path));
  if (!r.ok) { outMsg("error", friendlyError(r.status, r.body)); return; }
  kvRead(path); // re-read; renderDeleted shows the Undelete action
}

async function kvUndelete(path, version) {
  const r = await api("POST", KV_UNDELETE(path), { versions: [version] });
  if (!r.ok) { outMsg("error", friendlyError(r.status, r.body)); return; }
  kvRead(path);
}

async function kvList(path) {
  const p = cleanPath(path);
  const r = await api("LIST", KV_META(p));
  if (!r.ok) { outMsg("error", friendlyError(r.status, r.body)); return; }
  const keys = (r.body && r.body.data && r.body.data.keys) || [];
  const out = $("kv-out");
  out.replaceChildren();
  if (!keys.length) { outMsg("ok", "No keys under “" + (p || "/") + "”."); return; }

  const ul = document.createElement("ul");
  ul.className = "kv-keys";
  for (const k of keys) {
    const li = document.createElement("li");
    const child = (p ? p.replace(/\/?$/, "/") : "") + k;
    const b = actionButton(k, "linklike", () => {
      $("kv-path").value = child;
      if (k.endsWith("/")) kvList(child); else kvRead(child);
    });
    li.appendChild(b);
    ul.appendChild(li);
  }
  out.appendChild(ul);
}

// ---- editor (write) ----
function addFieldRow(key = "", value = "") {
  const row = document.createElement("div");
  row.className = "editor-row";
  const k = document.createElement("input");
  k.type = "text"; k.className = "k"; k.placeholder = "key"; k.value = key; k.spellcheck = false;
  const v = document.createElement("input");
  v.type = "text"; v.placeholder = "value"; v.value = value; v.spellcheck = false;
  const del = actionButton("✕", "del", () => row.remove());
  del.setAttribute("aria-label", "remove field");
  row.append(k, v, del);
  $("editor-fields").appendChild(row);
  return row;
}

function openEditor(path, existing) {
  const p = cleanPath(path);
  if (!p) { outMsg("error", "Enter a path first, then New / edit."); $("kv-path").focus(); return; }
  const ed = $("kv-editor");
  ed.dataset.path = p;
  $("editor-title").textContent = existing ? "Edit secret" : "New secret";
  $("editor-path").textContent = p;
  $("editor-fields").replaceChildren();
  const entries = existing ? Object.entries(existing) : [];
  if (entries.length) {
    for (const [k, v] of entries) addFieldRow(k, typeof v === "string" ? v : JSON.stringify(v));
  } else {
    addFieldRow();
  }
  ed.hidden = false;
  ed.scrollIntoView({ block: "nearest" });
}

function closeEditor() {
  const ed = $("kv-editor");
  ed.hidden = true;
  ed.dataset.path = "";
  $("editor-fields").replaceChildren();
}

function collectFields() {
  const data = {};
  for (const row of $("editor-fields").querySelectorAll(".editor-row")) {
    const inputs = row.querySelectorAll("input");
    const k = inputs[0].value.trim();
    if (k) data[k] = inputs[1].value;
  }
  return data;
}

async function saveSecret() {
  const p = $("kv-editor").dataset.path;
  if (!p) return;
  const data = collectFields();
  if (!Object.keys(data).length) { outMsg("error", "Add at least one field with a key."); return; }
  const r = await api("POST", KV_DATA(p), { data });
  if (!r.ok) { outMsg("error", friendlyError(r.status, r.body)); return; }
  closeEditor();
  $("kv-path").value = p;
  kvRead(p); // show the new version
}

// ---- wire up ----
document.addEventListener("DOMContentLoaded", () => {
  reflectToken();
  refreshStatus();

  $("refresh").addEventListener("click", refreshStatus);
  $("token-form").addEventListener("submit", (e) => {
    e.preventDefault();
    setToken($("token").value.trim());
    $("token").value = "";
  });
  $("token-clear").addEventListener("click", () => setToken(""));

  $("kv-form").addEventListener("submit", (e) => { e.preventDefault(); kvRead($("kv-path").value); });
  $("kv-list").addEventListener("click", () => kvList($("kv-path").value));
  $("kv-new").addEventListener("click", () => openEditor($("kv-path").value, null));

  $("editor-add").addEventListener("click", () => addFieldRow());
  $("editor-cancel").addEventListener("click", closeEditor);
  $("kv-editor").addEventListener("submit", (e) => { e.preventDefault(); saveSecret(); });
});
