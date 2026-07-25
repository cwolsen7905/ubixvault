"use strict";
// uBix Vault console — read-only. Vanilla JS, no dependencies. Secret values are
// rendered via textContent only (never innerHTML), so a value can't inject markup.

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

// api performs a same-origin request, attaching the token when present.
async function api(method, path) {
  const headers = {};
  const tok = getToken();
  if (tok) headers["X-Vault-Token"] = tok;
  const res = await fetch(path, { method, headers });
  let body = null;
  try { body = await res.json(); } catch (_) { /* empty/non-JSON */ }
  return { status: res.status, ok: res.ok, body };
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

// ---- KV ----
const KV_DATA = (p) => "/v1/secret/data/" + p;
const KV_META = (p) => "/v1/secret/metadata/" + p;

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

async function kvRead(path) {
  const p = cleanPath(path);
  if (!p) { outMsg("error", "Enter a secret path."); return; }
  const r = await api("GET", KV_DATA(p));
  if (!r.ok) { outMsg("error", friendlyError(r.status, r.body)); return; }

  const data = (r.body && r.body.data && r.body.data.data) || {};
  const meta = (r.body && r.body.data && r.body.data.metadata) || {};
  const out = $("kv-out");
  out.replaceChildren();

  const keys = Object.keys(data);
  if (!keys.length) {
    outMsg("ok", "Secret at “" + p + "” has no fields.");
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
    line.textContent = "version " + meta.version +
      (meta.created_time ? " · created " + meta.created_time : "") +
      (meta.destroyed ? " · destroyed" : meta.deleted ? " · deleted" : "");
    out.appendChild(line);
  }
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
    const b = document.createElement("button");
    b.type = "button"; b.className = "linklike"; b.textContent = k;
    const child = (p ? p.replace(/\/?$/, "/") : "") + k;
    b.addEventListener("click", () => {
      if (k.endsWith("/")) { $("kv-path").value = child; kvList(child); }
      else { $("kv-path").value = child; kvRead(child); }
    });
    li.appendChild(b);
    ul.appendChild(li);
  }
  out.appendChild(ul);
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
  $("token-clear").addEventListener("click", () => { setToken(""); });
  $("kv-form").addEventListener("submit", (e) => { e.preventDefault(); kvRead($("kv-path").value); });
  $("kv-list").addEventListener("click", () => kvList($("kv-path").value));
});
