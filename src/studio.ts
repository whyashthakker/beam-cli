// Served directly by the collector at GET / and GET /studio. Self-contained: no build step,
// no external resources (fonts/CDNs/analytics) — everything this local security tool touches
// stays on this machine. The page itself carries no secret; API calls still require the token.
export function studioPage(): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>beam studio</title>
<style>
:root { color-scheme: dark; --bg:#0b0d10; --panel:#14171b; --border:#242830; --text:#e6e8eb; --muted:#8b93a1; --accent:#6ee7b7; --amber:#f5b942; --red:#ef6f6f; --blue:#7aa2f7; }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--text); font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
header { display:flex; align-items:center; justify-content:space-between; padding:14px 20px; border-bottom:1px solid var(--border); }
header h1 { font-size:15px; margin:0; letter-spacing:.02em; }
header h1 b { color:var(--accent); }
.status { display:flex; align-items:center; gap:8px; font-size:12px; color:var(--muted); }
.dot { width:8px; height:8px; border-radius:50%; background:#555; }
.dot.on { background:var(--accent); }
.dot.off { background:var(--red); }
main { max-width:1100px; margin:0 auto; padding:20px; }
nav.tabs { display:flex; gap:4px; margin-bottom:16px; border-bottom:1px solid var(--border); }
nav.tabs button { background:none; border:none; color:var(--muted); padding:10px 14px; cursor:pointer; font-size:13px; border-bottom:2px solid transparent; }
nav.tabs button.active { color:var(--text); border-color:var(--accent); }
nav.tabs button .n { background:var(--border); border-radius:10px; padding:1px 6px; margin-left:6px; font-size:11px; }
.panel { background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:16px; margin-bottom:16px; }
.pair { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
.pair input[type=password] { flex:1; min-width:220px; background:#0e1013; border:1px solid var(--border); color:var(--text); padding:8px 10px; border-radius:6px; font-family:monospace; }
button.btn { background:var(--accent); color:#08110d; border:none; padding:8px 14px; border-radius:6px; font-weight:600; cursor:pointer; font-size:13px; }
button.btn.secondary { background:none; border:1px solid var(--border); color:var(--text); }
button.btn:disabled { opacity:.5; cursor:default; }
.filters { display:flex; gap:8px; margin-bottom:12px; flex-wrap:wrap; }
.filters input, .filters select { background:#0e1013; border:1px solid var(--border); color:var(--text); padding:7px 10px; border-radius:6px; font-size:13px; }
.filters input { flex:1; min-width:200px; }
table { width:100%; border-collapse:collapse; font-size:13px; }
th { text-align:left; color:var(--muted); font-weight:500; padding:6px 8px; border-bottom:1px solid var(--border); font-size:11px; text-transform:uppercase; letter-spacing:.04em; }
td { padding:8px; border-bottom:1px solid var(--border); vertical-align:top; }
tr.row:hover { background:#0e1013; cursor:pointer; }
.mono { font-family:monospace; color:var(--muted); }
.badge { display:inline-block; padding:2px 8px; border-radius:10px; font-size:11px; text-transform:capitalize; }
.badge.critical { background:#3a1414; color:var(--red); }
.badge.high { background:#3a2712; color:var(--amber); }
.badge.medium { background:#1c2a3a; color:var(--blue); }
.badge.info { background:#132018; color:var(--accent); }
.empty { text-align:center; padding:40px 10px; color:var(--muted); }
.scan-grid { display:grid; grid-template-columns:1fr 1fr; gap:16px; }
.scan-grid label { display:block; margin-bottom:10px; font-size:12px; color:var(--muted); }
.scan-grid input[type=text], .scan-grid select, .scan-grid textarea { width:100%; background:#0e1013; border:1px solid var(--border); color:var(--text); padding:8px; border-radius:6px; font-size:13px; margin-top:4px; font-family:inherit; }
.scan-grid textarea { font-family:monospace; min-height:220px; resize:vertical; }
.finding { border:1px solid var(--border); border-radius:8px; padding:10px 12px; margin-bottom:10px; }
.finding pre { white-space:pre-wrap; word-break:break-word; background:#0e1013; padding:8px; border-radius:6px; font-size:12px; margin:8px 0 0; }
.drawer-backdrop { position:fixed; inset:0; background:rgba(0,0,0,.5); display:flex; justify-content:flex-end; z-index:10; }
.drawer { width:min(480px,100%); background:var(--panel); border-left:1px solid var(--border); padding:20px; overflow-y:auto; }
.drawer dl { display:grid; grid-template-columns:110px 1fr; gap:6px 10px; font-size:12px; margin:12px 0; }
.drawer dt { color:var(--muted); }
.close { float:right; background:none; border:none; color:var(--muted); font-size:18px; cursor:pointer; }
.muted { color:var(--muted); }
.stats { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-bottom:16px; }
.stats article { background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:12px 14px; }
.stats span { font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.03em; }
.stats strong { display:block; font-size:22px; margin-top:4px; }
.notice { padding:10px 14px; border-radius:8px; margin-bottom:14px; font-size:13px; }
.notice.error { background:#3a1414; color:var(--red); }
</style>
</head>
<body>
<header>
  <h1><b>beam</b> studio <span class="muted" style="font-weight:400">— local machine, observe only</span></h1>
  <div class="status"><span class="dot" id="dot"></span><span id="statusText">Not connected</span><button class="btn secondary" id="disconnectBtn" style="display:none;padding:4px 10px;font-size:12px;margin-left:8px">Disconnect</button></div>
</header>
<main>
  <div id="notice"></div>
  <div class="panel" id="pairPanel">
    <div class="pair">
      <input type="password" id="tokenInput" autocomplete="off" placeholder="Paste the pairing token from 'beam token'">
      <button class="btn" id="connectBtn">Connect</button>
    </div>
    <p class="muted" style="margin:8px 0 0">Saved in this browser's local storage so reloading the page stays connected. It's only readable by pages served from this collector (127.0.0.1) — use Disconnect to clear it.</p>
  </div>

  <div id="app" style="display:none">
    <div class="stats" id="stats"></div>
    <nav class="tabs">
      <button data-tab="activity" class="active">Activity</button>
      <button data-tab="findings">Findings <span class="n" id="flagCount">0</span></button>
      <button data-tab="scan">Skill &amp; MCP scan</button>
    </nav>

    <div id="tab-activity" class="tabpanel">
      <div class="filters">
        <input id="search" placeholder="Search actions, sessions, or tools…">
        <select id="agentFilter"><option value="all">All agents</option></select>
        <select id="severityFilter"><option value="all">All risk levels</option><option>critical</option><option>high</option><option>medium</option><option>info</option></select>
      </div>
      <div class="panel"><table><thead><tr><th>Time</th><th>Action / context</th><th>Agent</th><th>Risk</th><th>Review</th></tr></thead><tbody id="eventRows"></tbody></table><div class="empty" id="eventsEmpty" style="display:none">Your timeline starts with the first event. Run <code>beam agent install &lt;agent&gt;</code> or <code>beam hook &lt;agent&gt;</code> to send one.</div></div>
    </div>

    <div id="tab-findings" class="tabpanel" style="display:none">
      <div class="panel"><table><thead><tr><th>Time</th><th>Action / context</th><th>Agent</th><th>Risk</th><th>Review</th></tr></thead><tbody id="findingRows"></tbody></table><div class="empty" id="findingsEmpty" style="display:none">No flagged activity yet.</div></div>
    </div>

    <div id="tab-scan" class="tabpanel" style="display:none">
      <div class="scan-grid">
        <div class="panel">
          <label>What are you checking?
            <select id="scanKind"><option value="skill">Skill instructions / SKILL.md</option><option value="mcp">MCP configuration (JSON)</option></select>
          </label>
          <label>File name<input type="text" id="scanName" value="SKILL.md" maxlength="200"></label>
          <label>Content<textarea id="scanContent" maxlength="500000" placeholder="Paste the content you want to inspect…"></textarea></label>
          <button class="btn" id="scanBtn" style="width:100%">Scan for risky instructions</button>
          <p class="muted" style="margin-top:10px">Content is analyzed locally and never executed. Heuristic rules can miss attacks and flag legitimate instructions.</p>
        </div>
        <div class="panel" id="scanResult"><p class="muted">Findings will appear here after you run a scan.</p></div>
      </div>
    </div>
  </div>
</main>
<div id="drawerRoot"></div>
<script>
(function () {
  var STORAGE_KEY = "beam-studio-token";
  var token = "";
  var origin = window.location.origin;
  var state = { events: [], scans: [], reviews: {}, retention: 0 };
  var pollTimer = null;

  // localStorage can throw (private browsing, blocked site data) -- never let that break the page.
  function saveToken(t) { try { localStorage.setItem(STORAGE_KEY, t); } catch (e) { /* ignore */ } }
  function loadToken() { try { return localStorage.getItem(STORAGE_KEY) || ""; } catch (e) { return ""; } }
  function clearToken() { try { localStorage.removeItem(STORAGE_KEY); } catch (e) { /* ignore */ } }

  var params = new URLSearchParams(window.location.search);
  var qsToken = params.get("token");
  if (qsToken) {
    history.replaceState(null, "", window.location.pathname);
    connect(qsToken);
  } else {
    var stored = loadToken();
    if (stored) connect(stored);
  }

  document.getElementById("connectBtn").addEventListener("click", function () {
    var t = document.getElementById("tokenInput").value.trim();
    if (t) connect(t);
  });
  document.getElementById("tokenInput").addEventListener("keydown", function (e) {
    if (e.key === "Enter") document.getElementById("connectBtn").click();
  });
  document.getElementById("disconnectBtn").addEventListener("click", disconnect);

  function notice(message, isError) {
    var el = document.getElementById("notice");
    if (!message) { el.innerHTML = ""; return; }
    el.innerHTML = '<div class="notice ' + (isError ? "error" : "") + '">' + escapeHtml(message) + "</div>";
  }

  function api(path, init) {
    return fetch(origin + path, Object.assign({ cache: "no-store" }, init, {
      headers: Object.assign({ "Authorization": "Bearer " + token, "Content-Type": "application/json" }, (init && init.headers) || {})
    })).then(function (res) {
      if (!res.ok) return res.json().then(function (d) { throw new Error(d.error || "Request failed (" + res.status + ")"); });
      return res.json();
    });
  }

  function connect(t) {
    token = t;
    api("/state").then(function (data) {
      state = data;
      saveToken(t);
      document.getElementById("pairPanel").style.display = "none";
      document.getElementById("app").style.display = "block";
      document.getElementById("disconnectBtn").style.display = "inline-block";
      setStatus(true);
      notice("");
      render();
      if (pollTimer) clearInterval(pollTimer);
      pollTimer = setInterval(poll, 3000);
    }).catch(function (e) {
      var reachable = e.message !== "Failed to fetch";
      setStatus(false);
      // A stored token that the collector now rejects (e.g. it was reinstalled with a fresh
      // one) would otherwise silently fail on every reload; clear it so the pair form works.
      if (reachable) clearToken();
      notice(reachable ? e.message : "Cannot reach the collector. Is 'beam start' or 'beam service install' running?", true);
    });
  }

  function disconnect() {
    token = "";
    clearToken();
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = null;
    state = { events: [], scans: [], reviews: {}, retention: 0 };
    document.getElementById("pairPanel").style.display = "block";
    document.getElementById("app").style.display = "none";
    document.getElementById("disconnectBtn").style.display = "none";
    document.getElementById("tokenInput").value = "";
    setStatus(false);
    notice("");
  }

  function poll() {
    api("/state").then(function (data) { state = data; setStatus(true); render(); }).catch(function () { setStatus(false); });
  }

  function setStatus(on) {
    document.getElementById("dot").className = "dot " + (on ? "on" : "off");
    document.getElementById("statusText").textContent = on ? "Collector connected" : "Connection lost — retrying";
  }

  function risk(event) {
    var order = { critical: 3, high: 2, medium: 1, info: 0 };
    var top = "info";
    (event.findings || []).forEach(function (f) { if (order[f.severity] > order[top]) top = f.severity; });
    return top;
  }

  function escapeHtml(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function timeOf(iso) { try { return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }); } catch (e) { return iso; } }

  var activeTab = "activity";
  document.querySelectorAll("nav.tabs button").forEach(function (btn) {
    btn.addEventListener("click", function () {
      activeTab = btn.getAttribute("data-tab");
      document.querySelectorAll("nav.tabs button").forEach(function (b) { b.classList.toggle("active", b === btn); });
      document.querySelectorAll(".tabpanel").forEach(function (p) { p.style.display = "none"; });
      document.getElementById("tab-" + activeTab).style.display = "block";
      render();
    });
  });
  ["search", "agentFilter", "severityFilter"].forEach(function (id) {
    document.getElementById(id).addEventListener("input", render);
  });

  function render() {
    var events = state.events.slice().sort(function (a, b) { return Date.parse(b.timestamp) - Date.parse(a.timestamp); });
    var agents = Array.from(new Set(events.map(function (e) { return e.agent; }))).sort();
    var agentSelect = document.getElementById("agentFilter");
    var currentAgent = agentSelect.value;
    agentSelect.innerHTML = '<option value="all">All agents</option>' + agents.map(function (a) { return "<option" + (a === currentAgent ? " selected" : "") + ">" + escapeHtml(a) + "</option>"; }).join("");

    var flagged = events.filter(function (e) { return e.findings && e.findings.length && !state.reviews[e.id]; });
    document.getElementById("flagCount").textContent = flagged.length;

    document.getElementById("stats").innerHTML = [
      ["Recorded actions", events.length, "Latest " + (state.retention || 0).toLocaleString() + " retained locally"],
      ["Needs review", flagged.length, "Flagged events, not blocked actions"],
      ["Observed agents", agents.length, "Distinct source_agent values"],
      ["Saved scans", state.scans.length, "Skill / MCP reports"]
    ].map(function (s) { return "<article><span>" + s[0] + "</span><strong>" + s[1] + '</strong><small class="muted">' + s[2] + "</small></article>"; }).join("");

    if (activeTab === "activity" || activeTab === "findings") {
      var q = document.getElementById("search").value.toLowerCase();
      var agentFilter = agentSelect.value;
      var sevFilter = document.getElementById("severityFilter").value;
      var visible = events.filter(function (e) {
        if (activeTab === "findings" && (!e.findings || !e.findings.length)) return false;
        if (agentFilter !== "all" && e.agent !== agentFilter) return false;
        if (sevFilter !== "all" && risk(e) !== sevFilter) return false;
        var haystack = (e.summary + " " + e.agent + " " + e.session + " " + e.type).toLowerCase();
        return !q || haystack.indexOf(q) !== -1;
      });
      var rows = visible.slice(0, 500).map(function (e) {
        var r = risk(e);
        var reviewCell = (e.findings && e.findings.length)
          ? '<button class="btn secondary" data-review="' + e.id + '" style="padding:4px 10px;font-size:12px">' + (state.reviews[e.id] ? "✓ Reviewed" : "Mark reviewed") + "</button>"
          : '<span class="muted">—</span>';
        return '<tr class="row" data-id="' + e.id + '"><td class="mono">' + timeOf(e.timestamp) + "</td><td><strong>" + escapeHtml(e.summary).slice(0, 140) + '</strong><br><small class="muted">' + escapeHtml(e.type) + " · " + escapeHtml(e.session) + "</small></td><td>" + escapeHtml(e.agent) + '</td><td><span class="badge ' + r + '">' + (r === "info" ? "no flags" : r) + "</span></td><td>" + reviewCell + "</td></tr>";
      }).join("");
      var bodyId = activeTab === "findings" ? "findingRows" : "eventRows";
      var emptyId = activeTab === "findings" ? "findingsEmpty" : "eventsEmpty";
      document.getElementById(bodyId).innerHTML = rows;
      document.getElementById(emptyId).style.display = visible.length ? "none" : "block";
      document.querySelectorAll("#" + bodyId + " tr.row").forEach(function (tr) {
        tr.addEventListener("click", function (ev) {
          if (ev.target.hasAttribute("data-review")) return;
          openDrawer(events.find(function (e) { return e.id === tr.getAttribute("data-id"); }));
        });
      });
      document.querySelectorAll("#" + bodyId + " [data-review]").forEach(function (btn) {
        btn.addEventListener("click", function () {
          var id = btn.getAttribute("data-review");
          var reviewed = !state.reviews[id];
          api("/review", { method: "POST", body: JSON.stringify({ id: id, reviewed: reviewed }) }).then(poll).catch(function (e) { notice(e.message, true); });
        });
      });
    }

  }

  function openDrawer(event) {
    if (!event) return;
    var root = document.getElementById("drawerRoot");
    var findings = (event.findings || []).map(function (f) {
      return '<div class="finding"><span class="badge ' + f.severity + '">' + f.severity + "</span><h3>" + escapeHtml(f.title) + '</h3><p class="muted">' + escapeHtml(f.explanation) + "</p><pre>" + escapeHtml(f.evidence) + "</pre></div>";
    }).join("") || '<p class="muted">No configured rule matched. This does not establish that an action is safe.</p>';
    root.innerHTML = '<div class="drawer-backdrop"><section class="drawer"><button class="close">×</button><h2>Action detail</h2><span class="badge ' + risk(event) + '">' + risk(event) + '</span><pre style="white-space:pre-wrap;background:#0e1013;padding:10px;border-radius:6px;margin-top:10px">' + escapeHtml(event.summary) + '</pre><dl>' +
      [["Agent", event.agent], ["Session", event.session], ["Time", new Date(event.timestamp).toLocaleString()], ["Source", event.source], ["Status", event.phase], ["Project", event.project || "Not supplied"], ["Endpoint", event.endpoint], ["Model", event.model || "Not supplied"]]
        .map(function (kv) { return "<dt>" + kv[0] + "</dt><dd>" + escapeHtml(kv[1]) + "</dd>"; }).join("") +
      "</dl>" + findings + "</section></div>";
    root.querySelector(".close").addEventListener("click", function () { root.innerHTML = ""; });
    root.querySelector(".drawer-backdrop").addEventListener("click", function (e) { if (e.target === e.currentTarget) root.innerHTML = ""; });
  }

  document.getElementById("scanBtn").addEventListener("click", function () {
    var name = document.getElementById("scanName").value.trim() || "SKILL.md";
    var kind = document.getElementById("scanKind").value;
    var content = document.getElementById("scanContent").value;
    if (!content.trim()) { notice("Paste some content to scan first.", true); return; }
    api("/scan", { method: "POST", body: JSON.stringify({ name: name, kind: kind, content: content }) }).then(function (scan) {
      renderScanResult(scan);
      poll();
    }).catch(function (e) { notice(e.message, true); });
  });

  function renderScanResult(scan) {
    var findings = (scan.findings || []).map(function (f) {
      return '<div class="finding"><span class="badge ' + f.severity + '">' + f.severity + "</span><h3>" + escapeHtml(f.title) + '</h3><p class="muted">' + escapeHtml(f.explanation) + "</p>" + (f.line ? '<small class="muted">Near line ' + f.line + "</small>" : "") + "<pre>" + escapeHtml(f.evidence) + "</pre></div>";
    }).join("") || '<p class="muted">No configured rule matched. This is not a safety guarantee.</p>';
    document.getElementById("scanResult").innerHTML = '<p class="muted">' + escapeHtml(scan.kind) + " · " + scan.lines + ' lines</p><h3 style="margin-top:0">' + escapeHtml(scan.name) + "</h3>" + findings + '<p class="mono muted" style="margin-top:10px">sha256 ' + scan.hash + "</p>";
  }

  setStatus(false);
})();
</script>
</body>
</html>
`;
}
