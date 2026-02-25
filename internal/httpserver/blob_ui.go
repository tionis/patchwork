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
    :root { color-scheme: light; }
    body { font-family: "IBM Plex Sans", "Segoe UI", sans-serif; margin: 24px; background: #f7f8fb; color: #162033; }
    h1 { margin-top: 0; }
    .card { background: white; border: 1px solid #d5dbe8; border-radius: 10px; padding: 16px; margin-bottom: 16px; }
    label { display: block; margin-top: 8px; font-weight: 600; }
    input, select { width: 100%; box-sizing: border-box; margin-top: 4px; border: 1px solid #b8c0d5; border-radius: 6px; padding: 8px; }
    button { margin-top: 12px; background: #1449d6; color: white; border: none; border-radius: 6px; padding: 8px 12px; cursor: pointer; }
    button.secondary { background: #516080; }
    table { width: 100%; border-collapse: collapse; }
    th, td { border-bottom: 1px solid #e2e8f0; text-align: left; padding: 8px; vertical-align: top; }
    code { background: #eef2ff; padding: 2px 4px; border-radius: 4px; }
    pre { background: #0f172a; color: #e5e7eb; padding: 12px; border-radius: 8px; overflow-x: auto; }
  </style>
</head>
<body>
  <h1>Patchwork Blob Manager</h1>

  <div class="card">
    <label for="authToken">Bearer Token</label>
    <input id="authToken" type="password" placeholder="Token with blob.read/blob.upload/blob.publish scopes" />
    <label for="dbID">DB ID</label>
    <input id="dbID" value="public" />
    <button class="secondary" onclick="loadBlobs()">Load Blobs</button>
    <p><a href="/ui/tokens">Token Admin</a> | <a href="/auth/oidc/login?next=/ui/blobs">OIDC Login</a> | <a href="/auth/logout">Logout</a></p>
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

  <script>
    function getDBID() {
      return document.getElementById("dbID").value.trim();
    }

    function getAuthHeaders() {
      var token = document.getElementById("authToken").value.trim();
      if (!token) throw new Error("Bearer token is required");
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
  </script>
</body>
</html>`

func (s *Server) handleBlobUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, blobUIHTML)
}
