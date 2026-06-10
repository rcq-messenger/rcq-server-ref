"""Self-contained admin console served by the backend itself at
`GET /admin/console` (HTTP-Basic gated, same as every other /admin route).

This is the SELF-HOST counterpart to the managed `console.rcq.app` /
`admin.rcq.app` SPA: an operator running `rcq-server-ref` just opens
`https://<their-server>/admin/console`, the browser prompts for the
`ADMIN_USERNAME` / `ADMIN_PASSWORD` they set in `.env`, and they manage
their own server — UIN reservations (vanity numbers), invites, users,
reports, stats — with zero dependency on our infrastructure.

Vanilla JS, no build step, single file. Calls the existing /admin API; the
browser replays the Basic credentials it already prompted for.
"""

ADMIN_CONSOLE_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RCQ Server Admin</title>
<style>
  :root { --bg:#0f1115; --card:#171a21; --line:#262b36; --fg:#e6e8ec; --mut:#9aa3b2; --acc:#3b82f6; --red:#e5484d; --green:#30a46c; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--fg); font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }
  header { padding:18px 22px; border-bottom:1px solid var(--line); display:flex; align-items:baseline; gap:12px; }
  header h1 { font-size:17px; margin:0; font-weight:600; }
  header .host { color:var(--mut); font:12px ui-monospace,monospace; }
  main { max-width:980px; margin:0 auto; padding:22px; }
  section { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:16px 18px; margin-bottom:18px; }
  section h2 { font-size:13px; letter-spacing:.4px; text-transform:uppercase; color:var(--mut); margin:0 0 12px; font-weight:600; }
  .stats { display:grid; grid-template-columns:repeat(auto-fit,minmax(120px,1fr)); gap:12px; }
  .stat { background:var(--bg); border:1px solid var(--line); border-radius:10px; padding:12px; }
  .stat .n { font-size:22px; font-weight:600; }
  .stat .l { color:var(--mut); font-size:12px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th, td { text-align:left; padding:8px 8px; border-bottom:1px solid var(--line); vertical-align:top; }
  th { color:var(--mut); font-weight:500; }
  code, .mono { font:12px ui-monospace,monospace; }
  input, select { background:var(--bg); border:1px solid var(--line); color:var(--fg); border-radius:8px; padding:8px 10px; font-size:13px; }
  input::placeholder { color:var(--mut); }
  button { background:var(--acc); color:#fff; border:0; border-radius:8px; padding:8px 14px; font-size:13px; font-weight:600; cursor:pointer; }
  button.ghost { background:transparent; border:1px solid var(--line); color:var(--fg); }
  button.danger { background:transparent; border:1px solid var(--red); color:var(--red); }
  .row { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
  .pill { display:inline-block; padding:1px 7px; border-radius:999px; font-size:11px; border:1px solid var(--line); color:var(--mut); }
  .pill.vanity { color:var(--green); border-color:var(--green); }
  .muted { color:var(--mut); }
  .err { color:var(--red); font-size:13px; margin-top:8px; }
  a { color:var(--acc); }
</style>
</head>
<body>
<header>
  <h1>🌸 RCQ Server Admin</h1>
  <span class="host" id="host"></span>
</header>
<main>
  <section>
    <h2>Server</h2>
    <div class="stats" id="stats"><span class="muted">Loading…</span></div>
  </section>

  <section>
    <h2>Reserve a UIN / mint an invite</h2>
    <p class="muted" style="margin-top:-4px">Leave the UIN blank for a normal invite (random number). Set a UIN to hand someone a specific (vanity) number — they get it when they register with this code. Use max-uses 1 for a reserved number.</p>
    <div class="row">
      <input id="i_label" placeholder="Label (e.g. Acme HR)" style="flex:1;min-width:160px">
      <input id="i_uin" type="number" placeholder="UIN (optional, e.g. 777777)" style="width:200px">
      <input id="i_uses" type="number" value="1" min="1" title="Max uses" style="width:90px">
      <input id="i_ttl" type="number" placeholder="TTL hours" title="Expires after N hours (blank = never)" style="width:110px">
      <button onclick="mintInvite()">Create</button>
    </div>
    <div class="err" id="i_err"></div>
    <table style="margin-top:14px"><thead><tr><th>Code</th><th>UIN</th><th>Uses</th><th>Label</th><th>Join link</th><th></th></tr></thead>
      <tbody id="invites"></tbody></table>
  </section>

  <section>
    <h2>Users</h2>
    <div class="row">
      <input id="u_q" placeholder="Search by UIN or nickname" style="flex:1" onkeydown="if(event.key==='Enter')searchUsers()">
      <button class="ghost" onclick="searchUsers()">Search</button>
    </div>
    <table style="margin-top:12px"><thead><tr><th>UIN</th><th>Nickname</th><th>Status</th><th>Reports</th><th></th></tr></thead>
      <tbody id="users"></tbody></table>
  </section>

  <section>
    <h2>Open reports</h2>
    <table><thead><tr><th>#</th><th>Target</th><th>Reason</th><th>Context</th><th></th></tr></thead>
      <tbody id="reports"></tbody></table>
  </section>

  <section>
    <h2>Hall of Fame</h2>
    <p class="muted" style="margin:0 0 10px">Users who opted in from their client. Add the ones who earned it to your public wall (<span class="mono">/public/hof</span>).</p>
    <table><thead><tr><th>UIN</th><th>Nickname</th><th>On wall</th><th></th></tr></thead>
      <tbody id="hof"></tbody></table>
  </section>
</main>

<script>
const $ = (id) => document.getElementById(id);
document.getElementById('host').textContent = location.host;
async function api(method, path, body) {
  const opt = { method, headers: {} , credentials: 'same-origin' };
  if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
  const r = await fetch('/admin' + path, opt);
  if (r.status === 204) return null;
  const txt = await r.text();
  let data = null; try { data = txt ? JSON.parse(txt) : null; } catch (e) {}
  if (!r.ok) { const d = data && data.detail; throw new Error((d && (d.code || d)) || ('HTTP ' + r.status)); }
  return data;
}
async function loadStats() {
  try {
    const s = await api('GET', '/stats');
    let online = '?'; try { online = (await api('GET', '/presence/online-count')).count; } catch(e){}
    const cells = [
      ['Users', s.total_users], ['Online', online], ['Suspended', s.suspended_users],
      ['New 24h', s.new_users_24h], ['New 7d', s.new_users_7d], ['Open reports', s.open_reports],
    ];
    $('stats').innerHTML = cells.map(c => `<div class="stat"><div class="n">${c[1]}</div><div class="l">${c[0]}</div></div>`).join('');
  } catch (e) { $('stats').innerHTML = '<span class="err">'+e.message+' — check ADMIN_USERNAME / ADMIN_PASSWORD</span>'; }
}
async function loadInvites() {
  try {
    const rows = await api('GET', '/invites');
    $('invites').innerHTML = rows.map(v => `<tr>
      <td><code>${v.code.slice(0,10)}…</code></td>
      <td>${v.uin ? '<span class="pill vanity">'+v.uin+'</span>' : '<span class="muted">random</span>'}</td>
      <td>${v.used_count}/${v.max_uses}</td>
      <td>${v.label || ''}</td>
      <td><a href="#" onclick="navigator.clipboard.writeText('${v.join_url}');this.textContent='copied';return false">copy</a></td>
      <td><button class="danger" onclick="revoke('${v.code}')">Revoke</button></td>
    </tr>`).join('') || '<tr><td colspan="6" class="muted">No invites yet.</td></tr>';
  } catch (e) { $('invites').innerHTML = '<tr><td colspan="6" class="err">'+e.message+'</td></tr>'; }
}
async function mintInvite() {
  $('i_err').textContent = '';
  const body = { max_uses: parseInt($('i_uses').value) || 1 };
  if ($('i_label').value.trim()) body.label = $('i_label').value.trim();
  if ($('i_uin').value.trim()) body.uin = parseInt($('i_uin').value);
  if ($('i_ttl').value.trim()) body.ttl_hours = parseInt($('i_ttl').value);
  try { await api('POST', '/invites', body); $('i_label').value=''; $('i_uin').value=''; loadInvites(); }
  catch (e) { $('i_err').textContent = 'Could not create: ' + e.message; }
}
async function revoke(code) { try { await api('DELETE', '/invites/' + encodeURIComponent(code)); loadInvites(); } catch(e){ alert(e.message); } }
async function searchUsers() {
  const q = $('u_q').value.trim(); if (!q) return;
  try {
    const r = await api('GET', '/users?q=' + encodeURIComponent(q));
    $('users').innerHTML = (r.items||[]).map(u => `<tr>
      <td class="mono">${u.uin}</td><td>${u.nickname||''}</td>
      <td>${u.is_suspended ? '<span class="pill" style="color:var(--red);border-color:var(--red)">suspended</span>' : u.status}</td>
      <td>${u.reports_against}</td>
      <td><button class="${u.is_suspended?'ghost':'danger'}" onclick="ban(${u.uin}, ${!u.is_suspended})">${u.is_suspended?'Unban':'Ban'}</button></td>
    </tr>`).join('') || '<tr><td colspan="5" class="muted">No matches.</td></tr>';
  } catch (e) { $('users').innerHTML = '<tr><td colspan="5" class="err">'+e.message+'</td></tr>'; }
}
async function ban(uin, suspended) { try { await api('POST', '/users/' + uin + '/ban', { suspended }); searchUsers(); } catch(e){ alert(e.message); } }
async function loadReports() {
  try {
    const r = await api('GET', '/reports?status=open');
    $('reports').innerHTML = (r.items||[]).map(rp => `<tr>
      <td>${rp.id}</td>
      <td class="mono">${rp.target_uin}${rp.target_nickname?' ('+rp.target_nickname+')':''}</td>
      <td>${(rp.reason||'').slice(0,120)}</td><td class="muted">${rp.context||''}</td>
      <td><button class="ghost" onclick="resolve(${rp.id},false)">Dismiss</button> <button class="danger" onclick="resolve(${rp.id},true)">Ban + resolve</button></td>
    </tr>`).join('') || '<tr><td colspan="5" class="muted">No open reports.</td></tr>';
  } catch (e) { $('reports').innerHTML = '<tr><td colspan="5" class="err">'+e.message+'</td></tr>'; }
}
async function resolve(id, ban_target) {
  try { await api('POST', '/reports/' + id + '/resolve', { action: ban_target?'banned':'dismissed', notes:'', ban_target }); loadReports(); loadStats(); }
  catch(e){ alert(e.message); }
}
async function loadHof() {
  try {
    const r = await api('GET', '/hof');
    $('hof').innerHTML = (r.items||[]).map(u => `<tr>
      <td class="mono">${u.uin}</td><td>${u.nickname}</td>
      <td>${u.approved?'<span style="color:#3a7">yes</span>':'<span class="muted">no</span>'}</td>
      <td><button class="${u.approved?'ghost':''}" onclick="hofToggle(${u.uin}, ${!u.approved})">${u.approved?'Remove':'Add to wall'}</button></td>
    </tr>`).join('') || '<tr><td colspan="4" class="muted">Nobody opted in yet.</td></tr>';
  } catch (e) { $('hof').innerHTML = '<tr><td colspan="4" class="err">'+e.message+'</td></tr>'; }
}
async function hofToggle(uin, approved) {
  try { await api('POST', '/hof/' + uin, { approved }); loadHof(); } catch(e){ alert(e.message); }
}
loadStats(); loadInvites(); loadReports(); loadHof();
</script>
</body>
</html>"""
