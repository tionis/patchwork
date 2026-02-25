package httpserver

import (
	"io"
	"net/http"
)

const mainUIHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Patchwork Console</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f4f7fb;
      --card: #ffffff;
      --text: #10223a;
      --muted: #53627d;
      --border: #d3ddeb;
      --field: #ffffff;
      --accent: #1354d3;
      --accent-2: #4f6186;
      --code-bg: #0f1b33;
      --code-text: #e7eefc;
      --chip: #edf2ff;
      --shadow: 0 8px 28px rgba(22, 36, 66, 0.07);
    }

    :root[data-theme="dark"] {
      color-scheme: dark;
      --bg: #0d1118;
      --card: #141b27;
      --text: #e5ecfb;
      --muted: #9aaccc;
      --border: #243248;
      --field: #111826;
      --accent: #6d9dff;
      --accent-2: #4f6b9d;
      --code-bg: #091020;
      --code-text: #dce7ff;
      --chip: #1f2a40;
      --shadow: 0 8px 28px rgba(0, 0, 0, 0.35);
    }

    @media (prefers-color-scheme: dark) {
      :root:not([data-theme]) {
        color-scheme: dark;
        --bg: #0d1118;
        --card: #141b27;
        --text: #e5ecfb;
        --muted: #9aaccc;
        --border: #243248;
        --field: #111826;
        --accent: #6d9dff;
        --accent-2: #4f6b9d;
        --code-bg: #091020;
        --code-text: #dce7ff;
        --chip: #1f2a40;
        --shadow: 0 8px 28px rgba(0, 0, 0, 0.35);
      }
    }

    * { box-sizing: border-box; }
    body {
      margin: 0;
      padding: 24px;
      font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
      color: var(--text);
      background: radial-gradient(circle at top right, rgba(19, 84, 211, 0.12), transparent 36%), var(--bg);
      line-height: 1.38;
    }

    h1, h2, h3 { margin-top: 0; }
    h1 { margin-bottom: 6px; }

    .layout { max-width: 1240px; margin: 0 auto; }

    .topbar {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 14px;
    }

    .muted { color: var(--muted); }

    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      box-shadow: var(--shadow);
      padding: 16px;
      margin-bottom: 12px;
    }

    .quick-nav {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin: 8px 0 0;
    }

    .chip {
      display: inline-block;
      text-decoration: none;
      color: var(--text);
      background: var(--chip);
      border: 1px solid var(--border);
      border-radius: 999px;
      padding: 6px 10px;
      font-size: 13px;
    }

    .row {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 12px;
    }

    details.group {
      border: 1px solid var(--border);
      background: var(--card);
      border-radius: 12px;
      margin-bottom: 12px;
      box-shadow: var(--shadow);
    }

    details.group > summary {
      cursor: pointer;
      list-style: none;
      font-weight: 700;
      padding: 14px 16px;
      border-bottom: 1px solid var(--border);
    }

    details.group[open] > summary {
      background: color-mix(in srgb, var(--card) 92%, var(--accent) 8%);
    }

    details.group > summary::-webkit-details-marker { display: none; }

    details.group .section-body { padding: 12px; }

    label {
      display: block;
      margin-top: 8px;
      font-weight: 600;
      font-size: 14px;
    }

    input, textarea, select {
      width: 100%;
      margin-top: 4px;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 8px;
      background: var(--field);
      color: var(--text);
    }

    textarea {
      min-height: 92px;
      font-family: "IBM Plex Mono", monospace;
    }

    button {
      margin-top: 10px;
      margin-right: 6px;
      background: var(--accent);
      color: white;
      border: none;
      border-radius: 8px;
      padding: 8px 12px;
      cursor: pointer;
    }

    button.secondary { background: var(--accent-2); }

    code {
      background: var(--chip);
      border-radius: 4px;
      padding: 2px 5px;
    }

    pre {
      background: var(--code-bg);
      color: var(--code-text);
      border-radius: 10px;
      padding: 12px;
      min-height: 84px;
      overflow-x: auto;
      white-space: pre-wrap;
    }

    .small { font-size: 12px; color: var(--muted); }
    a { color: var(--accent); }

    .theme-control {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 14px;
    }

    @media (max-width: 700px) {
      body { padding: 14px; }
      .topbar { align-items: flex-start; }
    }
  </style>
</head>
<body>
  <div class="layout">
    <div class="topbar">
      <div>
        <h1>Patchwork Console</h1>
        <div class="muted">DB-scoped API console for runtime, queries, pubsub, streams, webhooks, leases, and blob tooling.</div>
      </div>
      <label class="theme-control" for="themeMode">
        Theme
        <select id="themeMode" aria-label="Theme mode">
          <option value="system">System</option>
          <option value="light">Light</option>
          <option value="dark">Dark</option>
        </select>
      </label>
    </div>

    <div class="card" id="start">
      <h2>Start Here</h2>
      <ol>
        <li>Use <a href="/auth/oidc/login?next=/ui">OIDC Login</a> to start a web session.</li>
        <li>If needed, open <a href="/ui/tokens">Token Admin</a> and create a machine token.</li>
        <li>Set a DB ID below and run actions. Bearer token can stay empty for admin OIDC sessions.</li>
      </ol>
      <div class="quick-nav">
        <a class="chip" href="#session">Session</a>
        <a class="chip" href="#service-runtime">Service + Runtime</a>
        <a class="chip" href="#query">Query</a>
        <a class="chip" href="#messages">Messages</a>
        <a class="chip" href="#streams">Streams</a>
        <a class="chip" href="#webhooks-leases">Webhooks + Leases</a>
        <a class="chip" href="#custom">Custom Call</a>
      </div>
    </div>

    <div class="card" id="session">
      <h2>Session</h2>
      <label for="baseURL">Base URL</label>
      <input id="baseURL" value="" placeholder="Defaults to current origin" />
      <label for="authToken">Bearer Token (optional)</label>
      <input id="authToken" type="password" placeholder="Used for scoped machine-token requests" />
      <label for="dbID">DB ID</label>
      <input id="dbID" value="public" />
      <p class="small">Web sessions are for user login. Machine tokens are for explicit scope-based API calls.</p>
      <p>
        <a href="/ui/tokens">Token Admin</a> |
        <a href="/ui/blobs">Blob Manager</a> |
        <a href="/auth/oidc/login?next=/ui">OIDC Login</a> |
        <a href="/auth/logout">Logout</a>
      </p>
    </div>

    <details class="group" id="service-runtime" open>
      <summary>Service and Runtime</summary>
      <div class="section-body row">
        <div class="card">
          <h3>Service</h3>
          <div class="small">Public probes and metrics.</div>
          <button onclick="callService('GET', '/healthz', '', 'serviceOut')">Health</button>
          <button onclick="callService('GET', '/status', '', 'serviceOut')">Status</button>
          <button onclick="callService('GET', '/metrics', '', 'serviceOut')">Metrics</button>
          <pre id="serviceOut"></pre>
        </div>

        <div class="card">
          <h3>Runtime</h3>
          <div class="small">Needs <code>query.read</code> scope.</div>
          <button onclick="dbCall('POST', '/_open', '', 'runtimeOut')">Open</button>
          <button onclick="dbCall('GET', '/_status', '', 'runtimeOut')">Status</button>
          <pre id="runtimeOut"></pre>
        </div>
      </div>
    </details>

    <details class="group" id="query" open>
      <summary>SQL Query</summary>
      <div class="section-body row">
        <div class="card">
          <h3>Query Exec</h3>
          <label for="querySQL">SQL</label>
          <textarea id="querySQL">SELECT 1 AS ok;</textarea>
          <label for="queryArgs">Args JSON array</label>
          <input id="queryArgs" value="[]" />
          <button onclick="runQueryExec()">Run</button>
          <pre id="queryExecOut"></pre>
        </div>

        <div class="card">
          <h3>Query Watch</h3>
          <div class="small">SSE updates for read-only SQL.</div>
          <label for="watchSQL">SQL</label>
          <textarea id="watchSQL">SELECT datetime('now') AS now;</textarea>
          <label for="watchArgs">Args JSON array</label>
          <input id="watchArgs" value="[]" />
          <button onclick="startQueryWatch()">Start</button>
          <button class="secondary" onclick="stopStream('queryWatch')">Stop</button>
          <pre id="queryWatchOut"></pre>
        </div>
      </div>
    </details>

    <details class="group" id="messages" open>
      <summary>Durable Message PubSub</summary>
      <div class="section-body row">
        <div class="card">
          <h3>Publish</h3>
          <label for="msgTopic">Topic</label>
          <input id="msgTopic" value="events/demo" />
          <label for="msgPayloadText">Payload Text</label>
          <textarea id="msgPayloadText">hello patchwork</textarea>
          <label for="msgContentType">Content Type</label>
          <input id="msgContentType" value="text/plain" />
          <button onclick="publishMessage()">Publish</button>
          <pre id="msgPublishOut"></pre>
        </div>

        <div class="card">
          <h3>Events Stream</h3>
          <label for="eventTopics">Topics (comma separated; supports + and #)</label>
          <input id="eventTopics" value="events/#" />
          <label for="eventSinceID">since_id (optional)</label>
          <input id="eventSinceID" />
          <label for="eventTail">tail (optional)</label>
          <input id="eventTail" />
          <button onclick="startEventStream()">Start</button>
          <button class="secondary" onclick="stopStream('eventStream')">Stop</button>
          <pre id="eventStreamOut"></pre>
        </div>
      </div>
    </details>

    <details class="group" id="streams" open>
      <summary>Byte Streams (Legacy Stream Mode)</summary>
      <div class="section-body row">
        <div class="card">
          <h3>Queue</h3>
          <label for="queueTopic">Queue Topic Path</label>
          <input id="queueTopic" value="jobs" />
          <label for="queuePayload">Payload</label>
          <textarea id="queuePayload">job-1</textarea>
          <button onclick="streamQueueSend()">Send</button>
          <button class="secondary" onclick="streamQueueNext()">Next</button>
          <pre id="queueOut"></pre>
        </div>

        <div class="card">
          <h3>Request and Responder</h3>
          <label for="reqPath">Path</label>
          <input id="reqPath" value="service/demo" />
          <label for="reqPayload">Requester Payload</label>
          <textarea id="reqPayload">ping</textarea>
          <label for="resPayload">Responder Payload</label>
          <textarea id="resPayload">pong</textarea>
          <button onclick="streamRequester()">Requester</button>
          <button class="secondary" onclick="streamResponderOnce()">Responder Once</button>
          <pre id="reqResOut"></pre>
        </div>
      </div>
    </details>

    <details class="group" id="webhooks-leases" open>
      <summary>Webhook Ingest and Leases</summary>
      <div class="section-body row">
        <div class="card">
          <h3>Webhook Ingest</h3>
          <label for="webhookEndpoint">Endpoint</label>
          <input id="webhookEndpoint" value="vendor/event" />
          <label for="webhookBody">JSON payload</label>
          <textarea id="webhookBody">{"ok":true}</textarea>
          <button onclick="webhookIngest()">Send</button>
          <pre id="webhookOut"></pre>
        </div>

        <div class="card">
          <h3>Leases</h3>
          <label for="leaseResource">Resource</label>
          <input id="leaseResource" value="jobs/demo" />
          <label for="leaseOwner">Owner</label>
          <input id="leaseOwner" value="worker-a" />
          <label for="leaseTTL">TTL Seconds</label>
          <input id="leaseTTL" value="30" />
          <label for="leaseToken">Lease Token (for renew/release)</label>
          <input id="leaseToken" />
          <button onclick="leaseAcquire()">Acquire</button>
          <button class="secondary" onclick="leaseRenew()">Renew</button>
          <button class="secondary" onclick="leaseRelease()">Release</button>
          <pre id="leaseOut"></pre>
        </div>
      </div>
    </details>

    <details class="group" id="custom" open>
      <summary>Custom API Call</summary>
      <div class="section-body card" style="margin: 0; box-shadow: none; border: 0; background: transparent; padding: 0;">
        <label for="customMethod">Method</label>
        <select id="customMethod">
          <option>GET</option>
          <option>POST</option>
          <option>PUT</option>
          <option>DELETE</option>
        </select>
        <label for="customPath">Path</label>
        <input id="customPath" value="/api/v1/db/public/_status" />
        <label for="customBody">Body (optional)</label>
        <textarea id="customBody"></textarea>
        <button onclick="customCall()">Send</button>
        <pre id="customOut"></pre>
      </div>
    </details>
  </div>

  <script>
    var controllers = {};
    var themeStorageKey = "patchwork_theme_mode";

    function applyThemeMode(mode) {
      var root = document.documentElement;
      if (mode === "light" || mode === "dark") {
        root.setAttribute("data-theme", mode);
      } else {
        root.removeAttribute("data-theme");
      }
    }

    function initThemeMode() {
      var select = document.getElementById("themeMode");
      if (!select) return;

      var stored = "";
      try {
        stored = localStorage.getItem(themeStorageKey) || "";
      } catch (_) {
        stored = "";
      }

      var mode = (stored === "light" || stored === "dark" || stored === "system") ? stored : "system";
      select.value = mode;
      applyThemeMode(mode);

      select.addEventListener("change", function() {
        var next = select.value;
        try {
          localStorage.setItem(themeStorageKey, next);
        } catch (_) {}
        applyThemeMode(next);
      });

      if (window.matchMedia) {
        var media = window.matchMedia("(prefers-color-scheme: dark)");
        var onChange = function() {
          var current = "system";
          try {
            current = localStorage.getItem(themeStorageKey) || "system";
          } catch (_) {
            current = "system";
          }
          if (current === "system") {
            applyThemeMode("system");
          }
        };
        if (media.addEventListener) {
          media.addEventListener("change", onChange);
        } else if (media.addListener) {
          media.addListener(onChange);
        }
      }
    }

    function baseURL() {
      var raw = document.getElementById("baseURL").value.trim();
      return raw || window.location.origin;
    }

    function dbID() {
      return document.getElementById("dbID").value.trim();
    }

    function authHeaders(contentType) {
      var headers = {};
      if (contentType) headers["Content-Type"] = contentType;
      var token = document.getElementById("authToken").value.trim();
      if (token) headers["Authorization"] = "Bearer " + token;
      return headers;
    }

    function encodePath(path) {
      var parts = path.split("/");
      var clean = [];
      for (var i = 0; i < parts.length; i++) {
        var p = parts[i].trim();
        if (!p) continue;
        clean.push(encodeURIComponent(p));
      }
      return clean.join("/");
    }

    function prettyText(text) {
      if (!text) return "";
      try {
        var parsed = JSON.parse(text);
        return JSON.stringify(parsed, null, 2);
      } catch (_) {
        return text;
      }
    }

    function setOut(id, text) {
      document.getElementById(id).textContent = text;
    }

    function appendOut(id, text) {
      var el = document.getElementById(id);
      el.textContent = (el.textContent || "") + text;
    }

    async function request(method, path, body, outID, contentType) {
      try {
        var opts = { method: method, headers: authHeaders(contentType) };
        if (body !== "") opts.body = body;
        var res = await fetch(baseURL() + path, opts);
        var text = await res.text();
        setOut(outID, "[" + res.status + "] " + prettyText(text));
      } catch (err) {
        setOut(outID, String(err));
      }
    }

    async function callService(method, path, body, outID) {
      await request(method, path, body, outID, "");
    }

    async function dbCall(method, actionPath, body, outID) {
      var id = dbID();
      if (!id) {
        setOut(outID, "DB ID is required");
        return;
      }
      await request(method, "/api/v1/db/" + encodeURIComponent(id) + actionPath, body, outID, body ? "application/json" : "");
    }

    function parseJSONInput(inputID, fallback) {
      var raw = document.getElementById(inputID).value.trim();
      if (!raw) return fallback;
      return JSON.parse(raw);
    }

    async function runQueryExec() {
      try {
        var body = {
          sql: document.getElementById("querySQL").value,
          args: parseJSONInput("queryArgs", [])
        };
        await dbCall("POST", "/query/exec", JSON.stringify(body), "queryExecOut");
      } catch (err) {
        setOut("queryExecOut", String(err));
      }
    }

    async function publishMessage() {
      var body = {
        topic: document.getElementById("msgTopic").value.trim(),
        payload_text: document.getElementById("msgPayloadText").value,
        content_type: document.getElementById("msgContentType").value.trim() || "text/plain"
      };
      await dbCall("POST", "/messages", JSON.stringify(body), "msgPublishOut");
    }

    async function streamQueueSend() {
      var id = dbID();
      var topic = encodePath(document.getElementById("queueTopic").value.trim());
      if (!id || !topic) {
        setOut("queueOut", "DB ID and queue topic are required");
        return;
      }
      await request("POST", "/api/v1/db/" + encodeURIComponent(id) + "/streams/queue/" + topic, document.getElementById("queuePayload").value, "queueOut", "");
    }

    async function streamQueueNext() {
      var id = dbID();
      var topic = encodePath(document.getElementById("queueTopic").value.trim());
      if (!id || !topic) {
        setOut("queueOut", "DB ID and queue topic are required");
        return;
      }
      await request("GET", "/api/v1/db/" + encodeURIComponent(id) + "/streams/queue/" + topic + "/next", "", "queueOut", "");
    }

    async function streamRequester() {
      var id = dbID();
      var path = encodePath(document.getElementById("reqPath").value.trim());
      if (!id || !path) {
        setOut("reqResOut", "DB ID and request path are required");
        return;
      }
      await request("POST", "/api/v1/db/" + encodeURIComponent(id) + "/streams/req/" + path, document.getElementById("reqPayload").value, "reqResOut", "");
    }

    async function streamResponderOnce() {
      var id = dbID();
      var path = encodePath(document.getElementById("reqPath").value.trim());
      if (!id || !path) {
        setOut("reqResOut", "DB ID and responder path are required");
        return;
      }
      await request("POST", "/api/v1/db/" + encodeURIComponent(id) + "/streams/res/" + path, document.getElementById("resPayload").value, "reqResOut", "");
    }

    async function webhookIngest() {
      var id = dbID();
      var endpoint = encodePath(document.getElementById("webhookEndpoint").value.trim());
      if (!id || !endpoint) {
        setOut("webhookOut", "DB ID and webhook endpoint are required");
        return;
      }
      await request("POST", "/api/v1/db/" + encodeURIComponent(id) + "/webhooks/" + endpoint, document.getElementById("webhookBody").value, "webhookOut", "application/json");
    }

    async function leaseAcquire() {
      var body = {
        resource: document.getElementById("leaseResource").value.trim(),
        owner: document.getElementById("leaseOwner").value.trim(),
        ttl_seconds: Number(document.getElementById("leaseTTL").value || "30")
      };
      await dbCall("POST", "/leases/acquire", JSON.stringify(body), "leaseOut");
    }

    async function leaseRenew() {
      var body = {
        resource: document.getElementById("leaseResource").value.trim(),
        owner: document.getElementById("leaseOwner").value.trim(),
        token: document.getElementById("leaseToken").value.trim(),
        ttl_seconds: Number(document.getElementById("leaseTTL").value || "30")
      };
      await dbCall("POST", "/leases/renew", JSON.stringify(body), "leaseOut");
    }

    async function leaseRelease() {
      var body = {
        resource: document.getElementById("leaseResource").value.trim(),
        owner: document.getElementById("leaseOwner").value.trim(),
        token: document.getElementById("leaseToken").value.trim()
      };
      await dbCall("POST", "/leases/release", JSON.stringify(body), "leaseOut");
    }

    async function customCall() {
      var method = document.getElementById("customMethod").value;
      var path = document.getElementById("customPath").value.trim();
      var body = document.getElementById("customBody").value;
      if (!path) {
        setOut("customOut", "Path is required");
        return;
      }
      var contentType = body.trim() ? "application/json" : "";
      await request(method, path, body.trim() ? body : "", "customOut", contentType);
    }

    async function startStream(name, method, path, body, outID) {
      stopStream(name);
      setOut(outID, "");

      var controller = new AbortController();
      controllers[name] = controller;

      try {
        var opts = {
          method: method,
          headers: authHeaders(body ? "application/json" : ""),
          signal: controller.signal
        };
        if (body) opts.body = body;

        var res = await fetch(baseURL() + path, opts);
        if (!res.ok) {
          var errText = await res.text();
          setOut(outID, "[" + res.status + "] " + errText);
          return;
        }
        if (!res.body) {
          setOut(outID, "Streaming body unavailable");
          return;
        }

        appendOut(outID, "[stream connected]\n");
        var reader = res.body.getReader();
        var decoder = new TextDecoder();
        while (true) {
          var item = await reader.read();
          if (item.done) break;
          appendOut(outID, decoder.decode(item.value, { stream: true }));
        }
        appendOut(outID, "\n[stream ended]");
      } catch (err) {
        if (controller.signal.aborted) {
          appendOut(outID, "\n[stream stopped]");
        } else {
          appendOut(outID, "\n" + String(err));
        }
      }
    }

    function stopStream(name) {
      if (controllers[name]) {
        controllers[name].abort();
        delete controllers[name];
      }
    }

    async function startQueryWatch() {
      try {
        var id = dbID();
        var body = {
          sql: document.getElementById("watchSQL").value,
          args: parseJSONInput("watchArgs", [])
        };
        await startStream("queryWatch", "POST", "/api/v1/db/" + encodeURIComponent(id) + "/query/watch", JSON.stringify(body), "queryWatchOut");
      } catch (err) {
        setOut("queryWatchOut", String(err));
      }
    }

    async function startEventStream() {
      var id = dbID();
      var parts = [];
      var topicsRaw = document.getElementById("eventTopics").value.trim();
      if (topicsRaw) {
        var topics = topicsRaw.split(",");
        for (var i = 0; i < topics.length; i++) {
          var t = topics[i].trim();
          if (t) parts.push("topic=" + encodeURIComponent(t));
        }
      }
      var sinceID = document.getElementById("eventSinceID").value.trim();
      var tail = document.getElementById("eventTail").value.trim();
      if (sinceID) parts.push("since_id=" + encodeURIComponent(sinceID));
      if (tail) parts.push("tail=" + encodeURIComponent(tail));
      var qs = parts.length ? "?" + parts.join("&") : "";
      await startStream("eventStream", "GET", "/api/v1/db/" + encodeURIComponent(id) + "/events/stream" + qs, "", "eventStreamOut");
    }

    initThemeMode();
  </script>
</body>
</html>`

func (s *Server) handleMainUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/ui" && r.URL.Path != "/ui/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := s.requireWebUIAccess(w, r); !ok {
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, mainUIHTML)
}
