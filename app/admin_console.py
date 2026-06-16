"""Self-contained admin console served by the backend itself at
`GET /admin/console` (HTTP-Basic gated, same as every other /admin route).

This is the SELF-HOST counterpart to the managed `console.rcq.app` /
`admin.rcq.app` SPA: an operator running `rcq-server-ref` just opens
`https://<their-server>/admin/console`, the browser prompts for the
`ADMIN_USERNAME` / `ADMIN_PASSWORD` they set in `.env`, and they manage
their own server — UIN reservations (vanity numbers), invites, users,
reports, stats, and a Server/federation info panel — with zero dependency
on our infrastructure.

Vanilla JS, no build step, single file. Calls the existing /admin API; the
browser replays the Basic credentials it already prompted for. The page is
MOCK-gated (`location.protocol==='file:' || ?mock`) so the exact same html
renders as a clickable design preview off the live backend.
"""

ADMIN_CONSOLE_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RCQ Server Admin</title>
<style>
  :root {
    --bg:#ffffff; --shell:#fafafa; --card:#ffffff; --line:#ececec; --line-2:#f3f3f3;
    --ink:#0c0d0e; --fg:#1c1e22; --mut:#6b7280; --dim:#9aa1ab;
    --acc:#16a34a; --acc-dim:#15803d; --acc-soft:#f0fdf4; --acc-line:#bbf7d0;
    --red:#e5484d; --red-soft:#fef2f2; --amber:#d97706;
    --flower:#ef3e36;
    --radius:14px; --shadow:0 1px 2px rgba(12,13,14,.04), 0 4px 16px rgba(12,13,14,.04);
  }
  * { box-sizing:border-box; }
  html,body { height:100%; }
  body { margin:0; background:var(--shell); color:var(--fg);
    font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    -webkit-font-smoothing:antialiased; }
  a { color:var(--acc); text-decoration:none; }
  .mono { font:12px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace; }

  /* shell */
  .layout { display:grid; grid-template-columns:236px 1fr; min-height:100vh; }
  aside { background:var(--bg); border-right:1px solid var(--line); padding:18px 14px; display:flex; flex-direction:column; gap:4px; position:sticky; top:0; height:100vh; }
  .brand { display:flex; align-items:center; gap:10px; padding:6px 8px 16px; }
  .brand .name { font-weight:650; font-size:15px; color:var(--ink); letter-spacing:-.01em; }
  .brand .host { font:11px/1.3 ui-monospace,monospace; color:var(--dim); }
  nav.side { display:flex; flex-direction:column; gap:2px; }
  .navlink { display:flex; align-items:center; gap:10px; padding:8px 10px; border-radius:10px; color:var(--mut); font-weight:500; cursor:pointer; transition:background .12s,color .12s; }
  .navlink:hover { background:var(--line-2); color:var(--fg); }
  .navlink.active { background:var(--acc-soft); color:var(--acc-dim); }
  .navlink svg { width:17px; height:17px; flex:none; }
  .navlink .badge { margin-left:auto; min-width:18px; height:18px; padding:0 5px; border-radius:999px; background:var(--red); color:#fff; font-size:11px; font-weight:600; display:none; align-items:center; justify-content:center; }
  .navlink .badge.on { display:inline-flex; }
  aside .foot { margin-top:auto; padding:10px 8px 0; color:var(--dim); font-size:11px; line-height:1.5; }

  main { padding:30px 34px 64px; max-width:1080px; }
  .view { display:none; }
  .view.active { display:block; animation:fade .18s ease; }
  @keyframes fade { from { opacity:0; transform:translateY(4px); } to { opacity:1; transform:none; } }
  .head { display:flex; align-items:flex-end; justify-content:space-between; gap:16px; margin-bottom:22px; }
  .head h1 { font-size:23px; font-weight:660; letter-spacing:-.02em; color:var(--ink); margin:0; }
  .head p { margin:4px 0 0; color:var(--mut); font-size:13.5px; }

  /* cards */
  .card { background:var(--card); border:1px solid var(--line); border-radius:var(--radius); box-shadow:var(--shadow); }
  .card.pad { padding:18px 20px; }
  .card + .card, .stack > * + * { margin-top:16px; }
  .card h3 { font-size:13px; font-weight:600; color:var(--ink); margin:0 0 2px; }
  .card .sub { color:var(--mut); font-size:12.5px; margin:0 0 14px; }

  /* stats */
  .stats { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:14px; }
  .stat { background:var(--card); border:1px solid var(--line); border-radius:var(--radius); padding:15px 16px; box-shadow:var(--shadow); }
  .stat .n { font-size:26px; font-weight:680; letter-spacing:-.02em; color:var(--ink); line-height:1.1; }
  .stat .l { color:var(--mut); font-size:12.5px; margin-top:3px; }
  .stat .n .dot { display:inline-block; width:7px; height:7px; border-radius:50%; background:var(--acc); margin-right:7px; vertical-align:middle; }
  .stat.warn .n { color:var(--amber); }

  /* chart */
  .chart { display:flex; align-items:flex-end; gap:3px; height:84px; margin-top:6px; }
  .chart .bar { flex:1; background:var(--acc-soft); border:1px solid var(--acc-line); border-bottom:0; border-radius:4px 4px 0 0; min-height:2px; position:relative; transition:background .12s; }
  .chart .bar:hover { background:var(--acc-line); }
  .chart-x { display:flex; justify-content:space-between; color:var(--dim); font-size:11px; margin-top:6px; }

  /* table */
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th,td { text-align:left; padding:10px 10px; border-bottom:1px solid var(--line-2); vertical-align:middle; }
  th { color:var(--mut); font-weight:500; font-size:12px; text-transform:uppercase; letter-spacing:.03em; }
  tr:last-child td { border-bottom:0; }
  tbody tr:hover { background:var(--line-2); }
  td.mono { color:var(--fg); }

  /* controls */
  input,select { background:var(--bg); border:1px solid var(--line); color:var(--fg); border-radius:10px; padding:9px 11px; font-size:13px; outline:none; transition:border .12s,box-shadow .12s; }
  input:focus,select:focus { border-color:var(--acc); box-shadow:0 0 0 3px var(--acc-soft); }
  input::placeholder { color:var(--dim); }
  .row { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
  button { font:inherit; font-size:13px; font-weight:600; border:0; border-radius:10px; padding:9px 15px; cursor:pointer; transition:background .12s,opacity .12s,border-color .12s; }
  .btn { background:var(--acc); color:#fff; }
  .btn:hover { background:var(--acc-dim); }
  .btn.ghost { background:var(--bg); border:1px solid var(--line); color:var(--fg); }
  .btn.ghost:hover { border-color:var(--dim); }
  .btn.danger { background:var(--bg); border:1px solid var(--line); color:var(--red); }
  .btn.danger:hover { background:var(--red-soft); border-color:var(--red); }
  .btn.sm { padding:6px 11px; font-size:12.5px; }
  /* features tab rows */
  .frow { display:flex; align-items:flex-start; gap:14px; padding:12px 0; border-top:1px solid var(--line-2); }
  .frow.first { border-top:none; padding-top:2px; }
  .frow .finfo { flex:1; min-width:0; }
  .frow .flabel { font-weight:600; font-size:13.5px; display:flex; align-items:center; gap:8px; }
  .frow .fhelp { color:var(--mut); font-size:12px; margin-top:2px; }
  .frow .fctl { flex:none; display:flex; gap:8px; align-items:center; }
  .ftitle { font-size:11.5px; text-transform:uppercase; letter-spacing:.04em; color:var(--mut); margin:0 0 8px; font-weight:600; }

  .seg { display:inline-flex; background:var(--line-2); border-radius:10px; padding:3px; gap:2px; }
  .seg button { background:transparent; color:var(--mut); padding:6px 14px; border-radius:8px; }
  .seg button.on { background:var(--bg); color:var(--ink); box-shadow:var(--shadow); }

  .pill { display:inline-flex; align-items:center; gap:5px; padding:2px 9px; border-radius:999px; font-size:11.5px; font-weight:500; border:1px solid var(--line); color:var(--mut); }
  .pill.green { color:var(--acc-dim); border-color:var(--acc-line); background:var(--acc-soft); }
  .pill.red { color:var(--red); border-color:#fecaca; background:var(--red-soft); }
  .pill.vanity { color:var(--acc-dim); border-color:var(--acc-line); background:var(--acc-soft); }

  .err { color:var(--red); font-size:13px; margin-top:8px; }
  .empty { color:var(--dim); padding:18px 4px; font-size:13px; }
  .link { color:var(--acc); cursor:pointer; }
  .kv { display:grid; grid-template-columns:160px 1fr; gap:10px 16px; font-size:13.5px; }
  .kv dt { color:var(--mut); }
  .kv dd { margin:0; color:var(--fg); }
  .note { background:var(--acc-soft); border:1px solid var(--acc-line); border-radius:12px; padding:14px 16px; font-size:13px; color:var(--fg); line-height:1.6; }
  .note b { color:var(--ink); }

  /* mobile */
  .menubtn { display:none; }
  .scrim { display:none; }            /* never a grid item on desktop */
  @media (max-width:820px) {
    .layout { grid-template-columns:1fr; }
    aside { position:fixed; z-index:40; width:236px; left:0; top:0; transform:translateX(-100%); transition:transform .2s; box-shadow:var(--shadow); }
    aside.open { transform:none; }
    .menubtn { display:inline-flex; }
    main { padding:18px 16px 56px; }
    .scrim { display:none; position:fixed; inset:0; background:rgba(12,13,14,.25); z-index:30; }
    .scrim.on { display:block; }
  }
  /* On a phone a dense table (a long crash REASON especially) crushed the
     other columns into tall thin strips. Make tables scroll horizontally
     instead so every column keeps a usable width — standard mobile pattern. */
  @media (max-width:640px) {
    .card.pad { overflow-x:auto; -webkit-overflow-scrolling:touch; }
    table { min-width:520px; }
    th, td { white-space:nowrap; }
    td:nth-child(3) { white-space:normal; min-width:200px; }  /* the reason/long cell wraps within its own width */
  }
</style>
</head>
<body>
<div id="updbar" style="display:none;position:fixed;top:0;left:0;right:0;z-index:9999;background:#b45309;color:#fff;padding:10px 16px;font-size:14px;line-height:1.45;text-align:center;box-shadow:0 1px 6px rgba(0,0,0,.25)"></div>
<div class="layout">
  <aside id="side">
    <div class="brand">
      <span id="flower"></span>
      <div>
        <div class="name">RCQ Server</div>
        <div class="host" id="host"></div>
      </div>
    </div>
    <nav class="side" id="nav"></nav>
    <div class="foot">Self-hosted · runs entirely on your server.<br>No dependency on rcq.app.</div>
  </aside>
  <div class="scrim" id="scrim" onclick="closeSide()"></div>

  <main>
    <button class="btn ghost sm menubtn" style="margin-bottom:14px" onclick="openSide()">☰ Menu</button>

    <!-- OVERVIEW -->
    <section class="view active" id="v-overview">
      <div class="head"><div><h1>Overview</h1><p>Your server at a glance.</p></div></div>
      <div class="stats" id="stats"><span class="empty">Loading…</span></div>
      <div class="card pad" style="margin-top:16px">
        <h3>New users · last 30 days</h3>
        <p class="sub">Signups per day (fake accounts excluded).</p>
        <div class="chart" id="chart"></div>
        <div class="chart-x" id="chart-x"></div>
      </div>
      <div class="card pad" style="margin-top:16px">
        <h3>Recent activity</h3>
        <p class="sub">Latest moderation actions.</p>
        <div id="activity"></div>
      </div>
    </section>

    <!-- INVITES -->
    <section class="view" id="v-invites">
      <div class="head"><div><h1>Invites &amp; UINs</h1><p>Mint join codes, or reserve a specific (vanity) number.</p></div></div>
      <div class="card pad">
        <div class="row">
          <input id="i_label" placeholder="Label (e.g. Acme HR)" style="flex:1;min-width:160px">
          <input id="i_uin" type="number" placeholder="UIN (optional)" style="width:170px">
          <input id="i_uses" type="number" value="1" min="1" title="Max uses" style="width:84px">
          <input id="i_ttl" type="number" placeholder="TTL hrs" title="Expires after N hours" style="width:96px">
          <button class="btn" onclick="mintInvite()">Create</button>
        </div>
        <p class="sub" style="margin:10px 0 0">Leave the UIN blank for a random number. Set one to hand someone a specific vanity number; use max-uses&nbsp;1 to reserve it.</p>
        <div class="err" id="i_err"></div>
      </div>
      <div class="card pad">
        <table><thead><tr><th>Code</th><th>UIN</th><th>Uses</th><th>Label</th><th></th><th></th></tr></thead>
          <tbody id="invites"></tbody></table>
      </div>
    </section>

    <!-- ACCESS TOKENS (closed/private island gate) -->
    <section class="view" id="v-access">
      <div class="head"><div><h1>Access tokens</h1><p>For a PRIVATE (closed) island only — per-person, revocable keys to reach this server. Used when you run the masquerade Caddyfile.</p></div></div>
      <div class="card pad">
        <div class="row">
          <input id="a_label" placeholder="Label (e.g. Alice)" style="flex:1;min-width:160px">
          <select id="a_kind" style="width:150px"><option value="invite">One-time invite</option><option value="standing">Standing</option></select>
          <input id="a_ttl" type="number" placeholder="Expires (days)" title="Expires after N days" style="width:130px">
          <button class="btn" onclick="createAccess()">Create</button>
        </div>
        <p class="sub" style="margin:10px 0 0">A one-time invite is redeemed by the first device that uses it (a re-posted invite then stops working). A standing token is multi-use. The full token is shown ONCE on creation — copy it then.</p>
        <div class="err" id="a_err"></div>
        <div id="a_new" style="display:none;margin-top:10px"></div>
      </div>
      <div class="card pad">
        <table><thead><tr><th>Label</th><th>Kind</th><th>Uses</th><th>Last used</th><th></th></tr></thead>
          <tbody id="access"></tbody></table>
      </div>
    </section>

    <!-- USERS -->
    <section class="view" id="v-users">
      <div class="head"><div><h1>Users</h1><p>Search by number or nickname, suspend abusers.</p></div></div>
      <div class="card pad">
        <div class="row">
          <input id="u_q" placeholder="Search by UIN or nickname" style="flex:1" onkeydown="if(event.key==='Enter')searchUsers()">
          <button class="btn ghost" onclick="searchUsers()">Search</button>
        </div>
      </div>
      <div class="card pad">
        <table><thead><tr><th>UIN</th><th>Nickname</th><th>Status</th><th>Reports</th><th></th></tr></thead>
          <tbody id="users"><tr><td colspan="5" class="empty">Search to list users.</td></tr></tbody></table>
      </div>
    </section>

    <!-- REPORTS -->
    <section class="view" id="v-reports">
      <div class="head">
        <div><h1>Reports</h1><p>User reports.</p></div>
        <div class="seg" id="report-seg">
          <button class="on" onclick="setReportKind('user')">User</button>
          <button onclick="setReportKind('crash')">Crashes</button>
        </div>
      </div>
      <div class="card pad">
        <table><thead><tr><th>#</th><th>Target</th><th>Reason</th><th>Context</th><th></th></tr></thead>
          <tbody id="reports"></tbody></table>
      </div>
    </section>

    <!-- SERVER -->
    <!-- FEATURES (operator toggles) -->
    <section class="view" id="v-features">
      <div class="head"><div><h1>Features</h1><p>Turn optional features on or off, and set limits &amp; branding for your island. Changes apply live — no restart.</p></div></div>
      <div id="features"><div class="card pad"><div class="empty">Loading…</div></div></div>
    </section>

    <section class="view" id="v-server">
      <div class="head"><div><h1>Server &amp; federation</h1><p>How your island is configured and how it joins the wider RCQ network.</p></div></div>
      <div class="card pad">
        <h3>This island</h3>
        <p class="sub">Read from your live configuration.</p>
        <dl class="kv" id="srv-kv"><dt>Loading…</dt><dd></dd></dl>
      </div>
      <div class="card pad">
        <h3>Joining the public network</h3>
        <p class="sub">What makes your server reachable by people on other islands.</p>
        <div class="note" id="fed-note">
          <p style="margin:0 0 10px"><b>Your island already federates.</b> Anyone can reach a contact or join a group on your server using <span class="mono">number@your-host</span> or a group link <span class="mono">your-host/g/&lt;id&gt;</span> — no central registry is involved, and you do not need to be in any catalogue for this to work.</p>
          <p style="margin:0 0 10px">The <b>public catalogue</b> (the <a href="https://rcq.app/servers" target="_blank">rcq.app/servers</a> list + the in-app auto-backup picker) is <b>only for discovery</b>: it lets strangers find your island and lets the app offer it as a backup. Listing is optional and is a maintainer-reviewed pull request to the <span class="mono">rcq-servers</span> repo.</p>
          <p style="margin:0"><b>To join a group on another island:</b> open that group's invite link (it must carry the host, e.g. <span class="mono">rcq.app/g/42@island.example</span>) in the app and confirm — your client guest-registers you there automatically. If the target island has <b>invite-only</b> registration, you need one of its invite codes first.</p>
        </div>
      </div>
    </section>
  </main>
</div>

<script>
const $ = (id) => document.getElementById(id);
const MOCK = location.protocol === 'file:' || location.search.includes('mock');
// Crash-reports tab gate. The backend rewrites this to false for self-hosters
// (RCQ_ADMIN_SHOW_CRASHES, default off); the raw file keeps true for the preview.
const SHOW_CRASHES = true;

/* ---- brand flower (red daisy, brand mark) ---- */
$('flower').innerHTML = `<svg width="26" height="26" viewBox="0 0 24 24" fill="#ef3e36" aria-hidden>
  <g>${Array.from({length:8},(_,i)=>{const a=i*45*Math.PI/180;const x=12+6.2*Math.cos(a);const y=12+6.2*Math.sin(a);return `<ellipse cx="${x.toFixed(2)}" cy="${y.toFixed(2)}" rx="3.1" ry="4.5" transform="rotate(${i*45} ${x.toFixed(2)} ${y.toFixed(2)})"/>`}).join('')}</g>
  <circle cx="12" cy="12" r="3.1" fill="#fff"/><circle cx="12" cy="12" r="2.1" fill="#ef3e36"/></svg>`;

/* ---- nav ---- */
const NAV = [
  ['overview','Overview','M3 12l9-8 9 8M5 10v9h5v-5h4v5h5v-9'],
  ['invites','Invites','M4 7h16v10H4zM4 7l8 6 8-6'],
  ['access','Access tokens','M6 10V7a6 6 0 1112 0v3M5 10h14v10H5zM12 14v3'],
  ['users','Users','M8 11a3 3 0 100-6 3 3 0 000 6zM2 20c0-3 3-5 6-5s6 2 6 5M16 7a3 3 0 110 6'],
  ['reports','Reports','M12 3l9 16H3zM12 10v4M12 17v.5','reports-badge'],
  ['features','Features','M4 6h16M4 12h16M4 18h16M8 6v0M16 12v0M10 18v0'],
  ['server','Server','M4 5h16v5H4zM4 14h16v5H4zM7 7.5h.5M7 16.5h.5'],
];
let cur = 'overview';
$('nav').innerHTML = NAV.map(n => `<div class="navlink${n[0]==='overview'?' active':''}" data-v="${n[0]}" onclick="go('${n[0]}')">
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="${n[2]}"/></svg>
  <span>${n[1]}</span>${n[3]?`<span class="badge" id="${n[3]}"></span>`:''}</div>`).join('');
function go(v) {
  cur = v;
  document.querySelectorAll('.navlink').forEach(e => e.classList.toggle('active', e.dataset.v===v));
  document.querySelectorAll('.view').forEach(e => e.classList.toggle('active', e.id==='v-'+v));
  closeSide();
  if (v==='invites') loadInvites();
  if (v==='access') loadAccess();
  if (v==='reports') loadReports();
  if (v==='features') loadFeatures();
  if (v==='server') loadServer();
}
function openSide(){ $('side').classList.add('open'); $('scrim').classList.add('on'); }
function closeSide(){ $('side').classList.remove('open'); $('scrim').classList.remove('on'); }
$('host').textContent = MOCK ? 'island.example' : location.host;

/* ---- api ---- */
async function api(method, path, body) {
  if (MOCK) return mock(method, path, body);
  const opt = { method, headers:{}, credentials:'same-origin' };
  if (body !== undefined) { opt.headers['Content-Type']='application/json'; opt.body=JSON.stringify(body); }
  const r = await fetch('/admin' + path, opt);
  if (r.status === 204) return null;
  const txt = await r.text(); let data=null; try{ data = txt?JSON.parse(txt):null; }catch(e){}
  if (!r.ok) { const d=data&&data.detail; throw new Error((d&&(d.code||d))||('HTTP '+r.status)); }
  return data;
}
async function serverInfo() {
  if (MOCK) return { name:'Example Island', capabilities:{ registration_policy:'open', uin_shop:false } };
  const r = await fetch('/server/info'); return r.json();
}

/* ---- overview ---- */
async function loadStats() {
  try {
    const s = await api('GET','/stats');
    let online='—'; try{ online=(await api('GET','/presence/online-count')).count; }catch(e){}
    const cells = [
      ['Users', s.total_users, false, true], ['Online now', online, false, false],
      ['New · 24h', s.new_users_24h], ['New · 7d', s.new_users_7d],
      ['Open reports', s.open_reports, s.open_reports>0], ...(SHOW_CRASHES ? [['Crashes', s.open_crashes||0, (s.open_crashes||0)>0]] : []),
    ];
    $('stats').innerHTML = cells.map(c => `<div class="stat${c[2]?' warn':''}"><div class="n">${c[3]?'<span class="dot"></span>':''}${c[1]}</div><div class="l">${c[0]}</div></div>`).join('');
    const badge = $('reports-badge'); const open=(s.open_reports||0)+(SHOW_CRASHES?(s.open_crashes||0):0);
    badge.textContent = open; badge.classList.toggle('on', open>0);
  } catch (e) { $('stats').innerHTML = '<span class="err">'+e.message+' — check ADMIN_USERNAME / ADMIN_PASSWORD</span>'; }
}
async function loadChart() {
  try {
    const t = await api('GET','/timeseries/signups?days=30');
    const pts = t.points||[]; const max = Math.max(1, ...pts.map(p=>p.count));
    $('chart').innerHTML = pts.map(p=>`<div class="bar" style="height:${Math.round(p.count/max*100)}%" title="${p.date}: ${p.count}"></div>`).join('');
    if (pts.length) $('chart-x').innerHTML = `<span>${pts[0].date.slice(5)}</span><span>${pts[pts.length-1].date.slice(5)}</span>`;
  } catch(e){ $('chart').innerHTML=''; }
}
async function loadActivity() {
  try {
    const rows = await api('GET','/activity?limit=12');
    $('activity').innerHTML = (rows&&rows.length) ? '<table><tbody>'+rows.map(a=>`<tr>
      <td class="mono" style="width:90px">${a.uin}</td>
      <td>${a.summary}</td>
      <td class="mono" style="color:var(--dim);text-align:right">${timeago(a.occurred_at)}</td></tr>`).join('')+'</tbody></table>'
      : '<div class="empty">No moderation actions yet.</div>';
  } catch(e){ $('activity').innerHTML='<div class="empty">'+e.message+'</div>'; }
}

/* ---- invites ---- */
async function loadInvites() {
  try {
    const rows = await api('GET','/invites');
    $('invites').innerHTML = rows.map(v=>`<tr>
      <td><span class="mono">${v.code.slice(0,10)}…</span></td>
      <td>${v.uin?'<span class="pill vanity">'+v.uin+'</span>':'<span style="color:var(--dim)">random</span>'}</td>
      <td>${v.used_count}/${v.max_uses}</td>
      <td>${v.label||''}</td>
      <td><span class="link" onclick="navigator.clipboard.writeText('${v.join_url}');this.textContent='copied ✓'">copy link</span></td>
      <td style="text-align:right"><button class="btn danger sm" onclick="revoke('${v.code}')">Revoke</button></td>
    </tr>`).join('') || '<tr><td colspan="6" class="empty">No invites yet.</td></tr>';
  } catch(e){ $('invites').innerHTML='<tr><td colspan="6" class="err">'+e.message+'</td></tr>'; }
}
async function mintInvite() {
  $('i_err').textContent='';
  const body = { max_uses: parseInt($('i_uses').value)||1 };
  if ($('i_label').value.trim()) body.label=$('i_label').value.trim();
  if ($('i_uin').value.trim()) body.uin=parseInt($('i_uin').value);
  if ($('i_ttl').value.trim()) body.ttl_hours=parseInt($('i_ttl').value);
  try { await api('POST','/invites',body); $('i_label').value='';$('i_uin').value=''; loadInvites(); }
  catch(e){ $('i_err').textContent='Could not create: '+e.message; }
}
async function revoke(code){ try{ await api('DELETE','/invites/'+encodeURIComponent(code)); loadInvites(); }catch(e){ alert(e.message); } }

/* ---- access tokens (closed island) ---- */
async function loadAccess() {
  try {
    const rows = await api('GET','/access-tokens');
    $('access').innerHTML = rows.map(t=>`<tr>
      <td>${t.label||'<span style="color:var(--dim)">—</span>'}${t.parent_id?' <span style="color:var(--dim)">(device)</span>':''}</td>
      <td>${t.kind}</td>
      <td>${t.uses}${t.max_uses?('/'+t.max_uses):''}</td>
      <td style="color:var(--dim)">${t.last_used_at?timeago(t.last_used_at):'—'}</td>
      <td style="text-align:right">${t.revoked?'<span style="color:var(--dim)">revoked</span>':'<button class="btn danger sm" onclick="revokeAccess('+t.id+')">Revoke</button>'}</td>
    </tr>`).join('') || '<tr><td colspan="5" class="empty">No access tokens yet.</td></tr>';
  } catch(e){ $('access').innerHTML='<tr><td colspan="5" class="err">'+e.message+'</td></tr>'; }
}
async function createAccess() {
  $('a_err').textContent=''; $('a_new').style.display='none';
  const body = { kind: $('a_kind').value };
  if ($('a_label').value.trim()) body.label=$('a_label').value.trim();
  if ($('a_ttl').value.trim()) body.expires_in_days=parseInt($('a_ttl').value);
  try {
    const out = await api('POST','/access-tokens',body);
    $('a_label').value='';
    const n=$('a_new'); n.style.display='block';
    n.innerHTML='<p class="sub">Copy this token now — it is shown only once. Give it to the person (and have them paste it in the app under Add account / Add contact).</p>'+
      '<div class="row"><input class="mono" readonly value="'+out.token+'" style="flex:1" onclick="this.select()">'+
      `<button class="btn ghost" onclick="navigator.clipboard.writeText('${out.token}');this.textContent='copied ✓'">Copy</button></div>`;
    loadAccess();
  } catch(e){ $('a_err').textContent='Could not create: '+e.message; }
}
async function revokeAccess(id){ try{ await api('POST','/access-tokens/'+id+'/revoke'); loadAccess(); }catch(e){ alert(e.message); } }

/* ---- users ---- */
async function searchUsers() {
  const q=$('u_q').value.trim(); if(!q) return;
  try {
    const r = await api('GET','/users?q='+encodeURIComponent(q));
    $('users').innerHTML = (r.items||[]).map(u=>`<tr>
      <td class="mono">${u.uin}</td><td>${u.nickname||''}</td>
      <td>${u.is_suspended?'<span class="pill red">suspended</span>':'<span class="pill green">'+u.status+'</span>'}</td>
      <td>${u.reports_against}</td>
      <td style="text-align:right"><button class="btn ${u.is_suspended?'ghost':'danger'} sm" onclick="ban(${u.uin},${!u.is_suspended})">${u.is_suspended?'Unban':'Ban'}</button></td>
    </tr>`).join('') || '<tr><td colspan="5" class="empty">No matches.</td></tr>';
  } catch(e){ $('users').innerHTML='<tr><td colspan="5" class="err">'+e.message+'</td></tr>'; }
}
async function ban(uin,suspended){ try{ await api('POST','/users/'+uin+'/ban',{suspended}); searchUsers(); }catch(e){ alert(e.message); } }

/* ---- reports ---- */
let reportKind='user';
function setReportKind(k){ reportKind=k; document.querySelectorAll('#report-seg button').forEach((b,i)=>b.classList.toggle('on',(i===0)===(k==='user'))); loadReports(); }
async function loadReports() {
  try {
    const r = await api('GET','/reports?status=open&kind='+reportKind);
    $('reports').innerHTML = (r.items||[]).map(rp=>`<tr>
      <td>${rp.id}</td>
      <td class="mono">${rp.target_uin}${rp.target_nickname?' <span style="color:var(--dim)">('+rp.target_nickname+')</span>':''}</td>
      <td>${(rp.reason||'').slice(0,120)}</td><td><span class="pill">${rp.context||'—'}</span></td>
      <td style="text-align:right;white-space:nowrap"><button class="btn ghost sm" onclick="resolve(${rp.id},false)">Dismiss</button> <button class="btn danger sm" onclick="resolve(${rp.id},true)">Ban</button></td>
    </tr>`).join('') || '<tr><td colspan="5" class="empty">No open '+(reportKind==='crash'?'crashes':'reports')+'.</td></tr>';
  } catch(e){ $('reports').innerHTML='<tr><td colspan="5" class="err">'+e.message+'</td></tr>'; }
}
async function resolve(id,ban_target){ try{ await api('POST','/reports/'+id+'/resolve',{action:ban_target?'banned':'dismissed',notes:'',ban_target}); loadReports(); loadStats(); }catch(e){ alert(e.message); } }

/* ---- server ---- */
async function loadServer() {
  try {
    const info = await serverInfo();
    const reg = info.capabilities.registration_policy;
    $('srv-kv').innerHTML = `
      <dt>Name</dt><dd>${info.name||'—'}</dd>
      <dt>Host</dt><dd class="mono">${MOCK?'island.example':location.host}</dd>
      <dt>Registration</dt><dd>${reg==='invite'?'<span class="pill">invite-only</span> &nbsp;<span style="color:var(--mut)">new users need an invite code</span>':'<span class="pill green">open</span> &nbsp;<span style="color:var(--mut)">anyone can register</span>'}</dd>
      <dt>UIN shop</dt><dd>${info.capabilities.uin_shop?'enabled':'<span style="color:var(--dim)">off (self-host default)</span>'}</dd>
      <dt>Federation</dt><dd><span class="pill green">on</span> &nbsp;<span style="color:var(--mut)">reachable as <span class="mono">number@${MOCK?'island.example':location.host}</span></span></dd>`;
  } catch(e){ $('srv-kv').innerHTML='<dt class="err">'+e.message+'</dt><dd></dd>'; }
}

/* ---- utils ---- */
function timeago(iso){ const s=(Date.parse(iso))?(Date.now()-Date.parse(iso))/1000:0; if(s<60)return 'just now'; if(s<3600)return Math.floor(s/60)+'m'; if(s<86400)return Math.floor(s/3600)+'h'; return Math.floor(s/86400)+'d'; }

/* ---- mock data for preview ---- */
/* ---- features (operator toggles) ---- */
const FGROUPS = { features:'Features', limits:'Limits & policy', branding:'Branding' };
function escAttr(s){ return String(s==null?'':s).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;'); }
async function loadFeatures(){
  try { const r = await api('GET','/settings'); renderFeatures((r&&r.settings)||[]); }
  catch(e){ $('features').innerHTML='<div class="card pad"><span class="err">'+e.message+' — check ADMIN_USERNAME / ADMIN_PASSWORD</span></div>'; }
}
function renderFeatures(list){
  const groups = {}; list.forEach(s=>{ (groups[s.group]=groups[s.group]||[]).push(s); });
  $('features').innerHTML = Object.keys(FGROUPS).filter(g=>groups[g]).map(g=>`
    <div class="card pad"><div class="ftitle">${FGROUPS[g]}</div>
      ${groups[g].map((s,i)=>frow(s,i===0)).join('')}</div>`).join('')
    || '<div class="card pad"><div class="empty">No settings.</div></div>';
}
function frow(s, first){
  let ctl;
  if (s.type==='bool')
    ctl = `<button class="btn sm ${s.value?'':'ghost'}" onclick="setFeature('${s.key}', ${!s.value})">${s.value?'On':'Off'}</button>`;
  else if (s.type==='int')
    ctl = `<input type="number" id="f_${s.key}" value="${s.value}"${s.min!=null?' min='+s.min:''}${s.max!=null?' max='+s.max:''} style="width:88px"><button class="btn sm" onclick="setFeature('${s.key}', parseInt($('f_${s.key}').value,10))">Save</button>`;
  else if (s.choices)
    ctl = `<select onchange="setFeature('${s.key}', this.value)">${s.choices.map(c=>`<option value="${c}"${c===s.value?' selected':''}>${c}</option>`).join('')}</select>`;
  else
    ctl = `<input id="f_${s.key}" value="${escAttr(s.value)}" placeholder="(none)" style="width:220px"><button class="btn sm" onclick="setFeature('${s.key}', $('f_${s.key}').value)">Save</button>`;
  const badge = s.overridden ? ' <span class="pill green">custom</span>' : '';
  return `<div class="frow${first?' first':''}"><div class="finfo"><div class="flabel">${s.label}${badge}</div><div class="fhelp">${s.help||''}</div></div><div class="fctl">${ctl}</div></div>`;
}
async function setFeature(key, value){
  if (typeof value==='number' && isNaN(value)) { alert('Enter a number.'); return; }
  try { const r = await api('PATCH','/settings', {[key]: value}); renderFeatures((r&&r.settings)||[]); }
  catch(e){ alert('Could not save: '+e.message); loadFeatures(); }
}

let MOCK_SETTINGS = [
  {key:'nearby_enabled',type:'bool',group:'features',label:'Nearby',help:'Geo people-near-you discovery.',value:true,default:true,overridden:false,min:null,max:null,choices:null},
  {key:'random_enabled',type:'bool',group:'features',label:'Random Chat',help:'Anonymous roulette-style chat.',value:true,default:true,overridden:false,min:null,max:null,choices:null},
  {key:'hood_enabled',type:'bool',group:'features',label:'Hood Chat',help:'Anonymous neighbourhood (geohash) chat.',value:true,default:true,overridden:false,min:null,max:null,choices:null},
  {key:'stories_enabled',type:'bool',group:'features',label:'Stories',help:'24h ephemeral photo/video stories.',value:false,default:true,overridden:true,min:null,max:null,choices:null},
  {key:'registration_policy',type:'str',group:'limits',label:'Registration',help:'Who may create an account on this island.',value:'open',default:'open',overridden:false,min:null,max:null,choices:['open','invite']},
  {key:'max_accounts_per_device',type:'int',group:'limits',label:'Max accounts / device',help:'How many accounts one device may hold.',value:5,default:5,overridden:false,min:1,max:50,choices:null},
  {key:'island_name',type:'str',group:'branding',label:'Island name',help:'Display name clients read from /server/info.',value:'Example Island',default:'RCQ Backend',overridden:true,min:null,max:null,choices:null},
  {key:'welcome_text',type:'str',group:'branding',label:'Welcome / rules',help:'Optional welcome or rules text shown in the app.',value:'',default:'',overridden:false,min:null,max:null,choices:null},
];

function mock(method, path, body) {
  if (path==='/settings') {
    if (method==='PATCH' && body) Object.keys(body).forEach(k=>{ const s=MOCK_SETTINGS.find(x=>x.key===k); if(s){ s.value=body[k]; s.overridden=true; } });
    return { settings: MOCK_SETTINGS };
  }
  if (path==='/stats') return {total_users:1284, fake_users:0, suspended_users:7, new_users_24h:23, new_users_7d:141, open_reports:3, open_crashes:1, resolved_reports_7d:12};
  if (path==='/presence/online-count') return {count:48};
  if (path.startsWith('/timeseries/signups')) return {points:Array.from({length:30},(_,i)=>{const d=new Date(Date.UTC(2026,4,14+i));return {date:d.toISOString().slice(0,10), count:Math.round(8+14*Math.abs(Math.sin(i/3))+ (i%5===0?10:0))}})};
  if (path.startsWith('/activity')) return [
    {kind:'report_resolved',uin:710335446,nickname:'nosferatu',summary:'Report #14 dismissed',occurred_at:new Date(Date.now()-1200e3).toISOString()},
    {kind:'report_resolved',uin:901003980,nickname:'q_anon',summary:'Banned + report #12 resolved',occurred_at:new Date(Date.now()-9000e3).toISOString()},
    {kind:'report_resolved',uin:524060806,nickname:'dev',summary:'Report #9 dismissed',occurred_at:new Date(Date.now()-86400e3).toISOString()},
  ];
  if (path==='/access-tokens' && method==='POST') return {id:99, kind:body.kind, token:'rcq_demo_'+Math.random().toString(36).slice(2,18), label:body.label};
  if (path.startsWith('/access-tokens')) return [
    {id:1, kind:'invite', label:'Alice', uses:1, max_uses:1, revoked:false, last_used_at:new Date(Date.now()-3600e3).toISOString(), parent_id:null},
    {id:2, kind:'standing', label:'Bridge bot', uses:42, max_uses:null, revoked:false, last_used_at:new Date(Date.now()-600e3).toISOString(), parent_id:null},
  ];
  if (path==='/invites') return [
    {code:'ACME7H2K9Qd1',uin:777777,used_count:0,max_uses:1,label:'Acme HR (vanity)',join_url:'https://island.example/r/ACME7H2K9Qd1'},
    {code:'TEAMx48fZb22',uin:null,used_count:3,max_uses:25,label:'Team launch',join_url:'https://island.example/r/TEAMx48fZb22'},
  ];
  if (path.startsWith('/users')) return {items:[
    {uin:524060806,nickname:'dev',status:'online',is_suspended:false,reports_against:0},
    {uin:901003980,nickname:'q_anon',status:'offline',is_suspended:true,reports_against:4},
  ]};
  if (path.startsWith('/reports')) {
    if (path.includes('kind=crash')) return {items:[{id:21,target_uin:0,target_nickname:null,reason:'[Android 0.47] [CRASH] drain_queue',context:'crash'}]};
    return {items:[
      {id:14,target_uin:710335446,target_nickname:'nosferatu',reason:'spam in group',context:'group'},
      {id:15,target_uin:901003980,target_nickname:'q_anon',reason:'harassment',context:'dm'},
      {id:16,target_uin:333000111,target_nickname:'newbie',reason:'impersonation',context:'profile'},
    ]};
  }
  return null;
}

/* ---- update check ---- */
async function checkUpdate() {
  if (MOCK) return;
  try {
    const u = await api('GET','/update-check');
    if (!u || !u.update_available) return;
    const bar = $('updbar');
    bar.innerHTML = '🔔 Доступно обновление RCQ-сервера: <b>'+u.latest+'</b> (у вас '+u.current+'). '
      + 'Обновите: <code style="background:rgba(0,0,0,.25);padding:1px 5px;border-radius:4px">git pull</code> и перезапустите сервис &middot; '
      + '<a href="'+u.repo_url+'" target="_blank" rel="noopener" style="color:#fff;text-decoration:underline">что изменилось</a>'
      + ' &nbsp;|&nbsp; Update available — pull &amp; restart.';
    bar.style.display='block';
    document.body.style.paddingTop='46px';
  } catch(e) {}
}

/* ---- boot ---- */
loadStats(); loadChart(); loadActivity(); checkUpdate();
if (!SHOW_CRASHES) { const seg=$('report-seg'); if (seg) seg.style.display='none'; }
</script>
</body>
</html>"""
