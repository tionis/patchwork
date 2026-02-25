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
    :root { color-scheme: light; }
    body { font-family: "IBM Plex Sans", "Segoe UI", sans-serif; margin: 24px; background: #f7f8fb; color: #162033; }
    h1, h2, h3 { margin-top: 0; }
    .row { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 12px; }
    .card { background: white; border: 1px solid #d5dbe8; border-radius: 10px; padding: 16px; margin-bottom: 12px; }
    label { display: block; margin-top: 8px; font-weight: 600; }
    input, textarea, select { width: 100%; box-sizing: border-box; margin-top: 4px; border: 1px solid #b8c0d5; border-radius: 6px; padding: 8px; }
    textarea { min-height: 92px; font-family: "IBM Plex Mono", monospace; }
    button { margin-top: 10px; margin-right: 6px; background: #1449d6; color: white; border: none; border-radius: 6px; padding: 8px 12px; cursor: pointer; }
    button.secondary { background: #516080; }
    code { background: #eef2ff; padding: 2px 4px; border-radius: 4px; }
    pre { background: #0f172a; color: #e5e7eb; padding: 12px; border-radius: 8px; overflow-x: auto; white-space: pre-wrap; min-height: 84px; }
    .small { font-size: 12px; color: #516080; }
    a { color: #1449d6; }
  </style>
</head>
<body>
  <h1>Patchwork Console</h1>
  <p class="small">Comprehensive API UI for DB-scoped runtime, query/watch, pubsub, streams, webhook ingest, and leases.</p>

  <div class="card">
    <h2>Session</h2>
    <label for="baseURL">Base URL</label>
    <input id="baseURL" value="" placeholder="Defaults to current origin" />
    <label for="authToken">Bearer Token (optional for public endpoints)</label>
    <input id="authToken" type="password" placeholder="Token for DB/admin actions" />
    <label for="dbID">DB ID</label>
    <input id="dbID" value="public" />
    <p><a href="/ui/tokens">Token Admin</a> | <a href="/ui/blobs">Blob Manager</a> | <a href="/auth/oidc/login?next=/ui">OIDC Login</a> | <a href="/auth/logout">Logout</a></p>
  </div>

  <div class="row">
    <div class="card">
      <h2>Service</h2>
      <button onclick="callService('GET', '/healthz', '', 'serviceOut')">Health</button>
      <button onclick="callService('GET', '/status', '', 'serviceOut')">Status</button>
      <button onclick="callService('GET', '/metrics', '', 'serviceOut')">Metrics</button>
      <pre id="serviceOut"></pre>
    </div>

    <div class="card">
      <h2>Runtime</h2>
      <button onclick="dbCall('POST', '/_open', '', 'runtimeOut')">Open</button>
      <button onclick="dbCall('GET', '/_status', '', 'runtimeOut')">Status</button>
      <pre id="runtimeOut"></pre>
    </div>
  </div>

  <div class="row">
    <div class="card">
      <h2>Query Exec</h2>
      <label for="querySQL">SQL</label>
      <textarea id="querySQL">SELECT 1 AS ok;</textarea>
      <label for="queryArgs">Args JSON array</label>
      <input id="queryArgs" value="[]" />
      <button onclick="runQueryExec()">Run</button>
      <pre id="queryExecOut"></pre>
    </div>

    <div class="card">
      <h2>Query Watch</h2>
      <label for="watchSQL">SQL (read-only)</label>
      <textarea id="watchSQL">SELECT datetime('now') AS now;</textarea>
      <label for="watchArgs">Args JSON array</label>
      <input id="watchArgs" value="[]" />
      <button onclick="startQueryWatch()">Start</button>
      <button class="secondary" onclick="stopStream('queryWatch')">Stop</button>
      <pre id="queryWatchOut"></pre>
    </div>
  </div>

  <div class="row">
    <div class="card">
      <h2>Durable Messages</h2>
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
      <h2>Event Stream</h2>
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

  <div class="row">
    <div class="card">
      <h2>Streams Queue</h2>
      <label for="queueTopic">Queue Topic Path</label>
      <input id="queueTopic" value="jobs" />
      <label for="queuePayload">Payload</label>
      <textarea id="queuePayload">job-1</textarea>
      <button onclick="streamQueueSend()">Send</button>
      <button class="secondary" onclick="streamQueueNext()">Next</button>
      <pre id="queueOut"></pre>
    </div>

    <div class="card">
      <h2>Streams Request/Responder</h2>
      <label for="reqPath">Path</label>
      <input id="reqPath" value="service/demo" />
      <label for="reqPayload">Requester Payload</label>
      <textarea id="reqPayload">ping</textarea>
      <label for="resPayload">Responder Payload (used for one blocking responder call)</label>
      <textarea id="resPayload">pong</textarea>
      <button onclick="streamRequester()">Requester</button>
      <button class="secondary" onclick="streamResponderOnce()">Responder Once</button>
      <pre id="reqResOut"></pre>
    </div>
  </div>

  <div class="row">
    <div class="card">
      <h2>Webhook Ingest</h2>
      <label for="webhookEndpoint">Endpoint</label>
      <input id="webhookEndpoint" value="vendor/event" />
      <label for="webhookBody">JSON payload</label>
      <textarea id="webhookBody">{"ok":true}</textarea>
      <button onclick="webhookIngest()">Send</button>
      <pre id="webhookOut"></pre>
    </div>

    <div class="card">
      <h2>Leases</h2>
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

  <div class="card">
    <h2>Custom API Call</h2>
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

  <script>
    var controllers = {};

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
        var label = "[" + res.status + "] ";
        setOut(outID, label + prettyText(text));
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

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, mainUIHTML)
}
