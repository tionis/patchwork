package httpserver

import (
	"io"
	"net/http"
)

const blobUIHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Patchwork Blob Manager</title>
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
    h1 { margin-top: 0; }
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
    label { display: block; margin-top: 8px; font-weight: 600; }
    input, select {
      width: 100%;
      margin-top: 4px;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 8px;
      background: var(--field);
      color: var(--text);
    }
    button {
      margin-top: 12px;
      background: var(--accent);
      color: white;
      border: none;
      border-radius: 8px;
      padding: 8px 12px;
      cursor: pointer;
    }
    button.secondary { background: var(--accent-2); }
    table { width: 100%; border-collapse: collapse; }
    th, td {
      border-bottom: 1px solid var(--border);
      text-align: left;
      padding: 8px;
      vertical-align: top;
    }
    code {
      background: var(--chip);
      padding: 2px 5px;
      border-radius: 4px;
    }
    pre {
      background: #0f1b33;
      color: #e7eefc;
      padding: 12px;
      border-radius: 10px;
      overflow-x: auto;
      white-space: pre-wrap;
    }
    a { color: var(--accent); }
    .small { font-size: 12px; color: var(--muted); }
    .theme-control { display: flex; align-items: center; gap: 8px; font-size: 14px; }
    @media (max-width: 700px) { body { padding: 14px; } }
  </style>
</head>
<body>
  <div class="layout">
    <div class="topbar">
      <div>
        <h1>Patchwork Blob Manager</h1>
        <div class="small">Upload, inspect, publish, and keep blobs for DB-scoped archives.</div>
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
      <label for="authToken">Bearer Token (optional if admin OIDC session is allowed)</label>
      <input id="authToken" type="password" placeholder="Token with blob.read/blob.upload/blob.publish scopes" />
      <label for="dbID">DB ID</label>
      <input id="dbID" value="public" />
      <button class="secondary" onclick="loadBlobs()">Load Blobs</button>
      <p><a href="/ui">Console</a> | <a href="/ui/tokens">Token Admin</a> | <a href="/auth/logout">Logout</a></p>
    </div>

    <div class="card">
      <h2>Upload (SingleFile REST Form)</h2>
      <label for="fileField">File Field Name</label>
      <input id="fileField" value="file" />
      <label for="urlField">URL Field Name</label>
      <input id="urlField" value="url" />
      <label for="sourceURL">Source URL (optional)</label>
      <input id="sourceURL" placeholder="https://example.com/page" />
      <label for="description">Description (optional)</label>
      <input id="description" placeholder="Archived copy of ..." />
      <label for="tags">Tags (comma separated)</label>
      <input id="tags" placeholder="archive/news, singlefile" />
      <label for="uploadFile">Archive File</label>
      <input id="uploadFile" type="file" />
      <button onclick="uploadSingleFile()">Upload</button>
      <pre id="uploadResult">No upload yet.</pre>
    </div>

    <div class="card">
      <h2>Blobs</h2>
      <button class="secondary" onclick="loadBlobs()">Refresh</button>
      <table>
        <thead>
          <tr>
            <th>Hash</th>
            <th>Status</th>
            <th>Size</th>
            <th>Type</th>
            <th>Kept</th>
            <th>Public</th>
            <th>Tags</th>
            <th>Claims</th>
            <th>Last Seen</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody id="blobRows"></tbody>
      </table>
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

    function getDBID() {
      return document.getElementById("dbID").value.trim();
    }

    function getAuthHeaders() {
      var token = document.getElementById("authToken").value.trim();
      if (!token) return {};
      return { "Authorization": "Bearer " + token };
    }

    async function uploadSingleFile() {
      var output = document.getElementById("uploadResult");
      output.textContent = "Uploading...";
      try {
        var dbID = getDBID();
        if (!dbID) throw new Error("DB ID is required");

        var fileField = document.getElementById("fileField").value.trim() || "file";
        var urlField = document.getElementById("urlField").value.trim() || "url";
        var fileInput = document.getElementById("uploadFile");
        if (!fileInput.files || !fileInput.files[0]) throw new Error("Select a file");

        var sourceURL = document.getElementById("sourceURL").value.trim();
        var description = document.getElementById("description").value.trim();
        var tags = document.getElementById("tags").value.trim();
        var data = new FormData();
        data.append(fileField, fileInput.files[0], fileInput.files[0].name);
        if (sourceURL) data.append(urlField, sourceURL);
        if (description) data.append("description", description);
        if (tags) data.append("tags", tags);

        var endpoint = "/api/v1/db/" + encodeURIComponent(dbID) + "/apps/singlefile/rest-form";
        var res = await fetch(endpoint, {
          method: "POST",
          headers: getAuthHeaders(),
          body: data
        });
        var text = await res.text();
        if (!res.ok) throw new Error(text);

        output.textContent = text;
        await loadBlobs();
      } catch (err) {
        output.textContent = String(err);
      }
    }

    async function openBlob(hash) {
      try {
        var dbID = getDBID();
        var endpoint = "/api/v1/db/" + encodeURIComponent(dbID) + "/blobs/" + encodeURIComponent(hash) + "/read-url";
        var res = await fetch(endpoint, { headers: getAuthHeaders() });
        var text = await res.text();
        if (!res.ok) throw new Error(text);
        var payload = JSON.parse(text);
        if (!payload.read_url) throw new Error("missing read_url in response");
        window.open(new URL(payload.read_url, window.location.origin).toString(), "_blank");
      } catch (err) {
        alert(String(err));
      }
    }

    async function setBlobPublic(hash, makePublic) {
      try {
        var dbID = getDBID();
        var op = makePublic ? "publish" : "unpublish";
        var endpoint = "/api/v1/db/" + encodeURIComponent(dbID) + "/blobs/" + encodeURIComponent(hash) + "/" + op;
        var res = await fetch(endpoint, {
          method: "POST",
          headers: Object.assign({ "Content-Type": "application/json" }, getAuthHeaders()),
          body: "{}"
        });
        var text = await res.text();
        if (!res.ok) throw new Error(text);
        await loadBlobs();
      } catch (err) {
        alert(String(err));
      }
    }

    async function setBlobKept(hash, keep) {
      try {
        var dbID = getDBID();
        var op = keep ? "keep" : "unkeep";
        var endpoint = "/api/v1/db/" + encodeURIComponent(dbID) + "/blobs/" + encodeURIComponent(hash) + "/" + op;
        var res = await fetch(endpoint, {
          method: "POST",
          headers: Object.assign({ "Content-Type": "application/json" }, getAuthHeaders()),
          body: "{}"
        });
        var text = await res.text();
        if (!res.ok) throw new Error(text);
        await loadBlobs();
      } catch (err) {
        alert(String(err));
      }
    }

    async function loadBlobs() {
      var tbody = document.getElementById("blobRows");
      tbody.innerHTML = "";
      try {
        var dbID = getDBID();
        if (!dbID) throw new Error("DB ID is required");
        var endpoint = "/api/v1/db/" + encodeURIComponent(dbID) + "/blobs/list?limit=200";
        var res = await fetch(endpoint, { headers: getAuthHeaders() });
        var text = await res.text();
        if (!res.ok) throw new Error(text);

        var payload = JSON.parse(text);
        var blobs = payload.blobs || [];
        if (!blobs.length) {
          var empty = document.createElement("tr");
          empty.innerHTML = "<td colspan=\"10\">No blobs found</td>";
          tbody.appendChild(empty);
          return;
        }

        for (var i = 0; i < blobs.length; i++) {
          var blob = blobs[i];
          var row = document.createElement("tr");
          var tags = (blob.tags || []).join(", ");
          var publicAction = blob.public
            ? "<button onclick=\"setBlobPublic('" + blob.hash + "', false)\">Unpublish</button>"
            : "<button onclick=\"setBlobPublic('" + blob.hash + "', true)\">Publish</button>";
          var keepAction = blob.kept
            ? "<button class=\"secondary\" onclick=\"setBlobKept('" + blob.hash + "', false)\">Unkeep</button>"
            : "<button class=\"secondary\" onclick=\"setBlobKept('" + blob.hash + "', true)\">Keep</button>";
          var publicCell = blob.public ? "yes" : "no";
          if (blob.public && blob.public_url) {
            publicCell = "<a href=\"" + blob.public_url + "\" target=\"_blank\">yes</a>";
          }
          row.innerHTML =
            "<td><code>" + blob.hash + "</code></td>" +
            "<td>" + (blob.status || "") + "</td>" +
            "<td>" + String(blob.size_bytes || "") + "</td>" +
            "<td>" + (blob.content_type || "") + "</td>" +
            "<td>" + String(!!blob.kept) + "</td>" +
            "<td>" + publicCell + "</td>" +
            "<td>" + tags + "</td>" +
            "<td>" + String(blob.active_claims || 0) + "</td>" +
            "<td>" + (blob.last_seen || "") + "</td>" +
            "<td><button onclick=\"openBlob('" + blob.hash + "')\">Open</button> " + publicAction + " " + keepAction + "</td>";
          tbody.appendChild(row);
        }
      } catch (err) {
        var row = document.createElement("tr");
        row.innerHTML = "<td colspan=\"10\">" + String(err) + "</td>";
        tbody.appendChild(row);
      }
    }

    initThemeMode();
  </script>
</body>
</html>`

func (s *Server) handleBlobUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := s.requireWebUIAccess(w, r); !ok {
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, blobUIHTML)
}
