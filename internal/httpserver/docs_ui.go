package httpserver

import (
	"io"
	"net/http"
)

const docsUIHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Patchwork Documentation</title>
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
      --chip: #edf2ff;
      --code-bg: #0f1b33;
      --code-text: #e7eefc;
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
      --chip: #1f2a40;
      --code-bg: #091020;
      --code-text: #dce7ff;
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
        --chip: #1f2a40;
        --code-bg: #091020;
        --code-text: #dce7ff;
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
      line-height: 1.4;
    }
    h1, h2, h3 { margin-top: 0; }
    .layout { max-width: 1180px; margin: 0 auto; }
    .topbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 14px;
    }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      box-shadow: var(--shadow);
      padding: 16px;
      margin-bottom: 12px;
    }
    .small { font-size: 12px; color: var(--muted); }
    .chips {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 8px;
    }
    .chip {
      display: inline-block;
      padding: 6px 10px;
      border-radius: 999px;
      text-decoration: none;
      background: var(--chip);
      border: 1px solid var(--border);
      color: var(--text);
    }
    table { width: 100%; border-collapse: collapse; }
    th, td {
      border-bottom: 1px solid var(--border);
      text-align: left;
      padding: 8px;
      vertical-align: top;
    }
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
      overflow-x: auto;
      white-space: pre-wrap;
    }
    a { color: var(--accent); }
    .theme-control { display: flex; align-items: center; gap: 8px; font-size: 14px; }
    @media (max-width: 700px) { body { padding: 14px; } }
  </style>
</head>
<body>
  <div class="layout">
    <div class="topbar">
      <div>
        <h1>Patchwork Documentation</h1>
        <div class="small">Built-in docs for operators, developers, and LLM/tooling agents.</div>
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

    <div class="card">
      <h2>Quick Links</h2>
      <div class="chips">
        <a class="chip" href="/ui">Console</a>
        <a class="chip" href="/ui/tokens">Token Admin</a>
        <a class="chip" href="/ui/blobs">Blob Manager</a>
        <a class="chip" href="/docs/llm">LLM Quick Reference</a>
        <a class="chip" href="/healthz">Health</a>
        <a class="chip" href="/status">Status</a>
        <a class="chip" href="/metrics">Metrics</a>
      </div>
      <p class="small">Repository docs: <code>README.md</code>, <code>LLM_API.md</code>, <code>ops/RUNBOOK.md</code>, <code>ops/RELEASE.md</code>.</p>
    </div>

    <div class="card">
      <h2>Auth Model</h2>
      <ul>
        <li>Machine API calls: <code>Authorization: Bearer &lt;token&gt;</code> with DB-scoped actions.</li>
        <li>Web login path: OIDC session for UI access; admin subjects can use admin APIs.</li>
        <li>Most APIs are DB-scoped under <code>/api/v1/db/:db_id/...</code>.</li>
      </ul>
    </div>

    <div class="card">
      <h2>Core Endpoints</h2>
      <table>
        <thead>
          <tr>
            <th>Capability</th>
            <th>Method + Route</th>
            <th>Scope</th>
          </tr>
        </thead>
        <tbody>
          <tr><td>Runtime Open</td><td><code>POST /api/v1/db/:db_id/_open</code></td><td><code>query.read</code></td></tr>
          <tr><td>Runtime Status</td><td><code>GET /api/v1/db/:db_id/_status</code></td><td><code>query.read</code></td></tr>
          <tr><td>SQL Execute</td><td><code>POST /api/v1/db/:db_id/query/exec</code></td><td><code>query.read|write|admin</code></td></tr>
          <tr><td>SQL Watch (SSE)</td><td><code>POST /api/v1/db/:db_id/query/watch</code></td><td><code>query.read</code></td></tr>
          <tr><td>Publish Message</td><td><code>POST /api/v1/db/:db_id/messages</code></td><td><code>pub.publish</code></td></tr>
          <tr><td>Subscribe Messages</td><td><code>GET /api/v1/db/:db_id/events/stream</code></td><td><code>pub.subscribe</code></td></tr>
          <tr><td>Webhook Ingest</td><td><code>POST /api/v1/db/:db_id/webhooks/:endpoint</code></td><td><code>webhook.ingest</code></td></tr>
          <tr><td>Leases</td><td><code>POST /api/v1/db/:db_id/leases/*</code></td><td><code>lease.*</code></td></tr>
          <tr><td>Blobs</td><td><code>/api/v1/db/:db_id/blobs/*</code></td><td><code>blob.*</code></td></tr>
        </tbody>
      </table>
    </div>

    <div class="card">
      <h2>cURL Quickstart</h2>
      <pre>BASE_URL=http://127.0.0.1:8080
TOKEN=&lt;machine-token&gt;

curl -sS -X POST "$BASE_URL/api/v1/db/public/query/exec" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"sql":"SELECT 1 AS ok","args":[]}'

curl -N "$BASE_URL/api/v1/db/public/events/stream?topic=jobs/%23&tail=10" \
  -H "Authorization: Bearer $TOKEN"</pre>
    </div>
  </div>

  <script>
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
        try {
          localStorage.setItem(themeStorageKey, select.value);
        } catch (_) {}
        applyThemeMode(select.value);
      });
    }

    initThemeMode();
  </script>
</body>
</html>`

const docsLLMText = `# Patchwork LLM Quick Reference

Use this as an in-server machine-readable shortcut. For full contract details, use repository file LLM_API.md.

Core routing:
- Most APIs: /api/v1/db/:db_id/...
- DB ID regex: ^[A-Za-z0-9._-]{1,128}$

Auth:
- Machine token: Authorization: Bearer <token>
- OIDC admin session can authorize admin/UI flows when configured.

High-value endpoints:
- POST /api/v1/admin/tokens
- POST /api/v1/db/:db_id/_open
- GET  /api/v1/db/:db_id/_status
- POST /api/v1/db/:db_id/query/exec
- POST /api/v1/db/:db_id/query/watch (SSE)
- POST /api/v1/db/:db_id/messages
- GET  /api/v1/db/:db_id/events/stream (SSE)
- POST /api/v1/db/:db_id/webhooks/:endpoint
- POST /api/v1/db/:db_id/leases/{acquire|renew|release}
- POST /api/v1/db/:db_id/blobs/init-upload
- POST /api/v1/db/:db_id/blobs/complete-upload
- GET  /o/:blob_hash[.suffix]

Key limits:
- Durable message payload max: 1 MiB
- Query exec timeout: 5s
- Query max rows: 5000
- Query max result bytes: 1 MiB

Smoke/verification commands:
- make smoke-first-deploy
- make smoke-first-deploy-oidc
- make edge-hardening-check
- ops/scripts/release-check.sh
`

func (s *Server) handleDocsUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path != "/docs" && r.URL.Path != "/docs/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, docsUIHTML)
}

func (s *Server) handleDocsLLM(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path != "/docs/llm" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, docsLLMText)
}
