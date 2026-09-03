"""Self-contained admin console served by the backend itself at
`GET /admin/console` (HTTP-Basic gated, same as every other /admin route).

This is the SELF-HOST counterpart to the managed `console.rcq.app` /
`admin.rcq.app` SPA: an operator running `rcq-server-ref` just opens
`https://<their-server>/admin/console`, the browser prompts for the
`ADMIN_USERNAME` / `ADMIN_PASSWORD` they set in `.env`, and they manage
their own server — UIN reservations (vanity numbers), invites, users,
reports, the `.rcq` sites it hosts, stats, and a Server/federation info
panel — with zero dependency on our infrastructure.

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
  input,select,textarea { background:var(--bg); border:1px solid var(--line); color:var(--fg); border-radius:10px; padding:9px 11px; font-size:13px; outline:none; transition:border .12s,box-shadow .12s; font-family:inherit; }
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
  .btn:disabled { opacity:.45; cursor:not-allowed; }
  /* features tab rows */
  .frow { display:flex; align-items:flex-start; gap:14px; padding:12px 0; border-top:1px solid var(--line-2); }
  .frow.first { border-top:none; padding-top:2px; }
  .frow .finfo { flex:1; min-width:0; }
  .frow .flabel { font-weight:600; font-size:13.5px; display:flex; align-items:center; gap:8px; }
  .frow .fhelp { color:var(--mut); font-size:12px; margin-top:2px; }
  .frow .fctl { flex:none; display:flex; gap:8px; align-items:center; }
  /* The island's logo preview, and the lettered tile a client draws when there
     is none. Rounded square, not a circle: a person is a circle and a group is
     a circle, and an island is neither (same shape iOS IslandAvatarView draws). */
  .logoimg, .logotile { width:44px; height:44px; border-radius:12px; flex:none; }
  .logoimg { object-fit:cover; background:var(--line-2); }
  .logotile { display:flex; align-items:center; justify-content:center;
    color:#fff; font-weight:700; font-size:20px; line-height:1; }
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

  /* The site viewer: a bundle under review is shown INSIDE the console, in a
     locked frame, never as a page of its own (see siteRender below). */
  .viewer { display:none; position:fixed; inset:0; z-index:50; background:rgba(12,13,14,.45); padding:24px; }
  .viewer.on { display:flex; flex-direction:column; }
  .viewer .vbox { flex:1; display:flex; flex-direction:column; min-height:0; background:var(--card); border-radius:var(--radius); box-shadow:var(--shadow); overflow:hidden; }
  .viewer .vhead { display:flex; align-items:center; gap:10px; flex-wrap:wrap; padding:10px 14px; border-bottom:1px solid var(--line); }
  .viewer .vhead .addr { font-weight:600; color:var(--ink); font-size:13px; }
  .viewer .vhead .pages { display:flex; gap:4px; flex-wrap:wrap; }
  .viewer .vhead .pages button.on { border-color:var(--acc); color:var(--acc-dim); }
  .viewer .vhead .vnote { color:var(--mut); font-size:12px; margin-left:auto; }
  .viewer iframe { flex:1; width:100%; border:0; background:#fff; }
  @media (max-width:640px) { .viewer { padding:8px; } .viewer .vhead .vnote { display:none; } }

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
<div id="updbar" style="display:none;position:fixed;top:0;left:0;right:0;z-index:9999;background:#b45309;color:#fff;padding:10px 16px;font-size:14px;line-height:1.5;text-align:center;white-space:normal;overflow-wrap:anywhere;box-shadow:0 1px 6px rgba(0,0,0,.25)"></div>
<!-- The site viewer (Sites tab). `sandbox` with nothing allowed: no scripts,
     no forms, no popups, no origin of ours, and no way to navigate anything.
     What goes into the frame has already been through siteRender. -->
<div class="viewer" id="viewer" onclick="if(event.target===this)closeViewer()">
  <div class="vbox">
    <div class="vhead">
      <span class="mono addr" id="v_addr"></span>
      <span class="pages" id="v_pages"></span>
      <span class="vnote">Locked frame, same rules as the app's reader: links do nothing, nothing loads from outside.</span>
      <button class="btn ghost sm" onclick="closeViewer()">Close</button>
    </div>
    <iframe id="v_frame" sandbox referrerpolicy="no-referrer" title="Site under review"></iframe>
  </div>
</div>
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
        <p class="sub">Signups per day.</p>
        <div class="chart" id="chart"></div>
        <div class="chart-x" id="chart-x"></div>
      </div>
      <div class="card pad" style="margin-top:16px">
        <h3>Active users · last 30 days</h3>
        <p class="sub">Distinct users active per day.</p>
        <div class="chart" id="chart-dau"></div>
        <div class="chart-x" id="chart-dau-x"></div>
      </div>
      <div class="card pad" style="margin-top:16px">
        <h3>Online now</h3>
        <p class="sub">Users connected to your server right now.</p>
        <div id="online"></div>
      </div>
      <div class="card pad" style="margin-top:16px">
        <h3>Recent activity</h3>
        <p class="sub">Latest moderation actions.</p>
        <div id="activity"></div>
      </div>
    </section>

    <!-- INSTRUMENTS -->
    <section class="view" id="v-instruments">
      <div class="head"><div><h1>Instruments</h1><p>What your server is doing to itself, last hour. Counted inside the process, so on a multi-worker install these are <b>one worker&rsquo;s</b> numbers, and they reset whenever the server restarts. Read the shape, not the absolute.</p></div></div>
      <div class="stats" id="inst-stats"><span class="empty">Loading…</span></div>
      <div class="card pad" style="margin-top:16px">
        <h3>Requests · last hour</h3>
        <p class="sub">One bar per minute. Hover a bar for the count.</p>
        <div class="chart" id="inst-chart"></div>
        <div class="chart-x" id="inst-chart-x"></div>
      </div>
      <div class="card pad" style="margin-top:16px">
        <h3>Where the time goes</h3>
        <p class="sub">Sorted by total time spent, not by how often it is called: the endpoint worth fixing is the one the server spends its life in. &ldquo;Worst&rdquo; is the slowest single call, which an average hides. The clock counts <b>server work only</b>: the time a client spends sending its request body is measured separately, so a phone dying mid-upload no longer paints an endpoint red.</p>
        <p class="sub" id="inst-slowbodies" style="display:none"></p>
        <table><thead><tr><th>Path</th><th style="text-align:right">Calls/min</th><th style="text-align:right">Typical</th><th style="text-align:right">Worst</th><th style="text-align:right">5xx</th></tr></thead>
          <tbody id="inst-paths"></tbody></table>
      </div>
    </section>

    <!-- INVITES -->
    <section class="view" id="v-invites">
      <div class="head"><div><h1>Invites &amp; UINs</h1><p>Join codes for an <b>invite-only</b> server. If you set Registration to “invite” (Features tab), new users must enter one of these codes to sign up — otherwise this tab is optional. You can also pre-assign a specific UIN to someone.</p></div></div>
      <div class="card pad">
        <div class="row">
          <input id="i_label" placeholder="Label (e.g. Acme HR)" style="flex:1;min-width:160px">
          <input id="i_uin" type="number" placeholder="UIN (optional)" style="width:170px">
          <input id="i_uses" type="number" value="1" min="1" title="Max uses" style="width:84px">
          <input id="i_ttl" type="number" placeholder="TTL hrs" title="Expires after N hours" style="width:96px">
          <button class="btn" onclick="mintInvite()">Create</button>
        </div>
        <p class="sub" style="margin:10px 0 0"><b>Label</b> is just a note for you. <b>UIN</b>: leave blank for a random number, or set one to reserve a specific (vanity) number for the holder. <b>Max uses</b>: how many people may register with this code (use 1 for a single person). <b>TTL hrs</b>: auto-expire after N hours (blank = never). After Create, copy the code straight away: this island keeps only a hash of it and cannot show it to you again.</p>
        <div class="err" id="i_err"></div>
        <div id="i_new" style="display:none;margin-top:12px"></div>
      </div>
      <div class="card pad">
        <table><thead><tr><th>Code (hash)</th><th>UIN</th><th>Uses</th><th>Label</th><th></th></tr></thead>
          <tbody id="invites"></tbody></table>
      </div>
    </section>

    <!-- ACCESS TOKENS (closed/private island gate) -->
    <section class="view" id="v-access">
      <div class="head"><div><h1>Access tokens</h1><p>Only for a <b>closed (private) island</b> — one that runs the masquerade Caddyfile so the server looks like an ordinary website and refuses anyone without a valid token. These are the per-person, revocable keys you hand out. <b>If you haven’t set up the masquerade Caddyfile, ignore this tab.</b></p></div></div>
      <div class="card pad">
        <div class="row">
          <input id="a_label" placeholder="Label (e.g. Alice)" style="flex:1;min-width:160px">
          <select id="a_kind" style="width:150px" onchange="$('a_max').style.display=this.value==='standing'?'':'none'"><option value="invite">One-time invite</option><option value="standing">Standing</option></select>
          <input id="a_max" type="number" min="1" placeholder="Max uses (∞ if blank)" title="Standing token: how many times it may be used" style="width:170px;display:none">
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
        <div><h1>Reports</h1><p>What your users sent you: abuse reports about other members, and bug reports about the island itself. Answer, then dismiss or ban. Your answer is delivered to the reporter in the app, so it is worth writing one even when you dismiss.</p></div>
      </div>
      <div class="card pad">
        <table><thead><tr><th>#</th><th>Target</th><th>Reason</th><th>Context</th><th></th></tr></thead>
          <tbody id="reports"></tbody></table>
      </div>
    </section>

    <!-- SERVER -->
    <!-- NEWS / ANNOUNCEMENTS -->
    <section class="view" id="v-news">
      <div class="head"><div><h1>News</h1><p>Broadcast an announcement to every user's in-app news feed — patch notes, planned downtime, rules.</p></div></div>
      <div class="card pad">
        <textarea id="n_body" rows="4" placeholder="Write an announcement… (up to 4000 chars)" style="width:100%;box-sizing:border-box;resize:vertical"></textarea>
        <div class="row" style="margin-top:10px">
          <input id="n_author" placeholder="Author (empty = this island's name)" style="flex:1;min-width:150px">
          <input id="n_files" type="file" multiple accept="image/*,video/*" title="Optional image/video attachments" style="flex:1;min-width:150px">
          <button class="btn" onclick="publishNews()">Publish</button>
        </div>
        <p class="sub" style="margin:10px 0 0">Posts appear in every user's News feed, signed with the author you typed, or with this island's name when the field is empty. Attachments are optional (images / video).</p>
        <div class="err" id="n_err"></div>
      </div>
      <div class="card pad">
        <table><thead><tr><th>Posted</th><th>Body</th><th>Media</th><th></th></tr></thead>
          <tbody id="news"></tbody></table>
      </div>
    </section>

    <!-- SITES (.rcq bundles this island hosts) -->
    <section class="view" id="v-sites">
      <div class="head"><div><h1>Sites</h1><p>The <b>.rcq</b> pages this island hosts — the one kind of content here you can actually read, because it is public by definition. <b>View</b> shows a site here, in a locked frame and through the same sanitiser as the app's reader: its links do nothing and nothing in it loads from outside, so looking at a site under complaint never tells its author that somebody did. <b>List / Unlist</b> is the shop window: a listed site shows in the catalogue on the front page of every browser on this island, an unlisted one still opens by its exact name. <b>Feature</b> pins a listed site to the top of that catalogue, in its own section above recents — the network's own <span class="mono">home.rcq</span> is what it is for. <b>Freeze</b> is the hold for a complaint: reads answer “frozen”, uploads are refused, nothing is deleted, and it is reversible.</p></div></div>
      <div class="card pad">
        <p class="sub" id="sites-summary" style="margin:0 0 8px"></p>
        <table><thead><tr><th>Site</th><th>Catalogue line</th><th>Owner</th><th>Size</th><th>State</th><th>Updated</th><th></th></tr></thead>
          <tbody id="sites"></tbody></table>
      </div>
    </section>

    <!-- RELAYS (community circumvention pool) -->
    <section class="view" id="v-relays">
      <div class="head"><div><h1>Relays</h1><p>Advanced — only relevant if someone runs censorship-circumvention relays for <b>your</b> island. This lists relays registered with <b>your own</b> server’s broker (never another island’s). Most operators can ignore this tab; it stays empty until a relay self-registers.</p></div></div>
      <div class="card pad">
        <p class="sub" style="margin:0"><b>Tier</b> — <span class="mono">community</span> relays are handed to clients only after a health check confirms they work; <span class="mono">trusted</span> relays are always offered (use that for relays you run yourself). <b>Promote / Demote</b> moves a relay between those tiers. <b>Remove</b> just drops it from the pool — clients fall back to your other relays or a direct connection; nothing is deleted on the relay’s own host, and removing the last one simply means no circumvention relays are advertised.</p>
      </div>
      <div class="card pad">
        <p class="sub" id="relays-summary" style="margin:0 0 8px"></p>
        <table><thead><tr><th>Health</th><th>Endpoint</th><th>Tag</th><th>Tier</th><th>State</th><th>Last OK</th><th>Fails</th><th></th></tr></thead>
          <tbody id="relays"></tbody></table>
      </div>
    </section>

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
          <p style="margin:0 0 10px"><b>Your island already federates.</b> Anyone can reach a contact or join a group on your server using <span class="mono">uin@your-host</span> or a group link <span class="mono">your-host/g/&lt;id&gt;</span> — no central registry is involved, and you do not need to be in any catalogue for this to work.</p>
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

/* ---- brand logo + favicon (real RCQ mark, base64-inlined) ---- */
const LOGO = 'data:image/png;base64,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';
$('flower').innerHTML = '<img src="'+LOGO+'" alt="" width="28" height="28" style="border-radius:7px;display:block">';
(function(){ const l=document.createElement('link'); l.rel='icon'; l.type='image/png'; l.href=LOGO; document.head.appendChild(l); })();

/* ---- nav ---- */
const NAV = [
  ['overview','Overview','M3 12l9-8 9 8M5 10v9h5v-5h4v5h5v-9'],
  ['instruments','Instruments','M4 18a8 8 0 1116 0M12 18l4-6'],
  ['invites','Invites','M4 7h16v10H4zM4 7l8 6 8-6'],
  ['access','Access tokens','M6 10V7a6 6 0 1112 0v3M5 10h14v10H5zM12 14v3'],
  ['users','Users','M8 11a3 3 0 100-6 3 3 0 000 6zM2 20c0-3 3-5 6-5s6 2 6 5M16 7a3 3 0 110 6'],
  ['reports','Reports','M12 3l9 16H3zM12 10v4M12 17v.5','reports-badge'],
  ['news','News','M4 6h16v12H4zM4 6l8 6 8-6'],
  ['sites','Sites','M4 5h16v14H4zM4 9h16M8 9v10'],
  ['relays','Relays','M12 20v-7M8.5 13a5 5 0 017 0M6 10.5a9 9 0 0112 0'],
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
  if (v==='instruments') loadInstruments();
  if (v==='invites') loadInvites();
  if (v==='access') loadAccess();
  if (v==='reports') loadReports();
  if (v==='news') loadNews();
  if (v==='sites') loadSites();
  if (v==='relays') loadRelays();
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
  if (!r.ok) { const d=data&&data.detail; throw new Error((d&&(d.message||d.code||d))||('HTTP '+r.status)); }
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
    let online='—'; try{ const oc=await api('GET','/presence/online-count'); online=(oc&&typeof oc.online==='number')?oc.online:'—'; }catch(e){}
    const cells = [
      ['Users', s.total_users], ['Online now', online],
      ['New · 24h', s.new_users_24h], ['New · 7d', s.new_users_7d],
      ['Open reports', s.open_reports, s.open_reports>0],
    ];
    $('stats').innerHTML = cells.map(c => `<div class="stat${c[2]?' warn':''}"><div class="n">${c[1]}</div><div class="l">${c[0]}</div></div>`).join('');
    const badge = $('reports-badge'); const open=(s.open_reports||0);
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
/* ---- instruments ---- */
async function loadInstruments() {
  try {
    const m = await api('GET','/metrics?minutes=60');
    const series = m.series || [];
    // The last FULL minute: the one in progress is only partly counted and
    // always reads low, which looks like a sudden drop every refresh.
    const last = series.length > 1 ? series[series.length-2] : null;
    const peak = Math.max(0, ...series.map(s=>s.pool_peak_in_use||0));
    const atCeiling = series.reduce((a,s)=>a+(s.pool_at_ceiling||0),0);
    const errs = series.reduce((a,s)=>a+(s.errors||0),0);
    const churn = series.reduce((a,s)=>a+(s.sockets_opened||0),0);
    const busiest = Math.max(0, ...series.map(s=>s.busiest_account_chains||0));
    const ceiling = (m.pool && m.pool.ceiling) || 0;
    const groups = (m.paths||[]).find(p=>p.path==='/groups');
    const cells = [
      ['Requests / sec', last ? (last.requests/60).toFixed(1) : '—'],
      ['/groups typical', groups ? groups.mean_ms+' ms' : '—', groups && groups.mean_ms>1000],
      ['DB pool peak', ceiling ? peak+' / '+ceiling : String(peak), atCeiling>0 && errs>0],
      ['Sockets opened / h', churn],
      // Value and label this way round on purpose: "9 boot chains/min" as the
      // big number wrapped onto three lines and stopped reading as a number.
      ['Busiest account · boot chains/min', busiest, busiest>20],
    ];
    $('inst-stats').innerHTML = cells.map(c=>`<div class="stat${c[2]?' warn':''}"><div class="n">${c[1]}</div><div class="l">${c[0]}</div></div>`).join('');

    const max = Math.max(1, ...series.map(s=>s.requests||0));
    $('inst-chart').innerHTML = series.map(s=>{
      const t = new Date(s.minute*60000);
      const hhmm = String(t.getHours()).padStart(2,'0')+':'+String(t.getMinutes()).padStart(2,'0');
      return `<div class="bar" style="height:${Math.round((s.requests||0)/max*100)}%" title="${hhmm}: ${s.requests||0} requests, ${s.errors||0} 5xx"></div>`;
    }).join('');
    if (series.length) {
      const fmt = mn => { const t=new Date(mn*60000); return String(t.getHours()).padStart(2,'0')+':'+String(t.getMinutes()).padStart(2,'0'); };
      $('inst-chart-x').innerHTML = `<span>${fmt(series[0].minute)}</span><span>${fmt(series[series.length-1].minute)}</span>`;
    }

    const sb = m.slow_bodies || 0;
    const sbEl = $('inst-slowbodies');
    if (sb > 0) {
      sbEl.style.display = '';
      sbEl.innerHTML = `<b>Stalled uploads:</b> ${sb} request(s) whose client took over 5s to deliver its body (worst ${Math.round((m.slow_body_worst_ms||0)/1000)}s). Their wait is excluded from the rows above; the server did no work while waiting.`;
    } else { sbEl.style.display = 'none'; }
    const rows = m.paths || [];
    $('inst-paths').innerHTML = rows.length ? rows.map(p=>`<tr>
      <td class="mono">${p.path}</td>
      <td style="text-align:right">${p.per_min}</td>
      <td style="text-align:right">${p.mean_ms} ms</td>
      <td style="text-align:right${p.worst_ms>2000?';color:var(--amber)':''}">${p.worst_ms} ms</td>
      <td style="text-align:right${p.errors?';color:var(--red)':''}">${p.errors}</td></tr>`).join('')
      : '<tr><td colspan="5" class="empty">Nothing recorded yet.</td></tr>';
  } catch(e) {
    $('inst-stats').innerHTML = '<span class="err">'+e.message+'</span>';
  }
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

/* ---- invites ----
   The `code` field is the sha256 of the token, not the token: since
   2026-08-22 the island stores only the hash (app/models/invite.py), so a
   dump of the invites table no longer mints access to an invite-gated
   island. `join_url` therefore comes back ONLY in the mint response, and the
   list shows the hash as a row id with no way to re-copy the link. Same
   shape the access-tokens tab below has always had. */
async function loadInvites() {
  try {
    const rows = await api('GET','/invites');
    $('invites').innerHTML = rows.map(v=>`<tr>
      <td><span class="mono">${v.code.slice(0,10)}…</span> <span style="color:var(--dim)">shown once at creation</span></td>
      <td>${v.uin?'<span class="pill vanity">'+v.uin+'</span>':'<span style="color:var(--dim)">random</span>'}</td>
      <td>${v.used_count}/${v.max_uses}</td>
      <td>${v.label||''}</td>
      <td style="text-align:right"><button class="btn danger sm" onclick="revoke('${v.code}')">Revoke</button></td>
    </tr>`).join('') || '<tr><td colspan="5" class="empty">No invites yet.</td></tr>';
  } catch(e){ $('invites').innerHTML='<tr><td colspan="5" class="err">'+e.message+'</td></tr>'; }
}
async function mintInvite() {
  $('i_err').textContent=''; $('i_new').style.display='none';
  const body = { max_uses: parseInt($('i_uses').value)||1 };
  if ($('i_label').value.trim()) body.label=$('i_label').value.trim();
  if ($('i_uin').value.trim()) body.uin=parseInt($('i_uin').value);
  if ($('i_ttl').value.trim()) body.ttl_hours=parseInt($('i_ttl').value);
  try {
    const out = await api('POST','/invites',body);
    $('i_label').value='';$('i_uin').value='';
    const n=$('i_new'); n.style.display='block';
    n.innerHTML='<p class="sub">Copy this link now, it is shown only once. Send it to the person; they paste the code when signing up.</p>'+
      '<div class="row"><input class="mono" readonly value="'+out.join_url+'" style="flex:1" onclick="this.select()">'+
      `<button class="btn ghost" onclick="navigator.clipboard.writeText('${out.join_url}');this.textContent='copied ✓'">Copy</button></div>`;
    loadInvites();
  }
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
  if (body.kind==='standing' && $('a_max').value.trim()) body.max_uses=parseInt($('a_max').value);
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
      <td>${u.is_suspended?'<span class="pill red">suspended</span>':'<span style="color:var(--mut)">'+(u.status||'active')+'</span>'}</td>
      <td>${u.reports_against}</td>
      <td style="text-align:right"><button class="btn ${u.is_suspended?'ghost':'danger'} sm" onclick="ban(${u.uin},${!u.is_suspended})">${u.is_suspended?'Unban':'Ban'}</button></td>
    </tr>`).join('') || '<tr><td colspan="5" class="empty">No matches.</td></tr>';
  } catch(e){ $('users').innerHTML='<tr><td colspan="5" class="err">'+e.message+'</td></tr>'; }
}
async function ban(uin,suspended){ try{ await api('POST','/users/'+uin+'/ban',{suspended}); searchUsers(); }catch(e){ alert(e.message); } }

/* ---- reports (user + bug reports; auto crash dumps are a maintainer concern) ---- */
async function loadReports() {
  try {
    const r = await api('GET','/reports?status=open&kind=user');
    $('reports').innerHTML = (r.items||[]).map(rp=>`<tr>
      <td>${rp.id}</td>
      <td class="mono">${rp.target_uin}${rp.target_nickname?' <span style="color:var(--dim)">('+esc(rp.target_nickname)+')</span>':''}</td>
      <td style="white-space:normal;overflow-wrap:anywhere">${esc(rp.reason||'')}${rp.has_evidence?' <span class="pill" style="cursor:pointer" onclick="viewEvidence('+rp.id+')">evidence</span>':''}${rp.replied_at?' <span class="pill" title="'+esc(rp.reply_text||'')+'">answered</span>':''}</td><td><span class="pill">${esc(contextLabel(rp.context))}</span></td>
      <td style="text-align:right;white-space:nowrap"><button class="btn ghost sm" onclick="reply(${rp.id})">Reply</button> <button class="btn ghost sm" onclick="resolve(${rp.id},false)">Dismiss</button> ${isAbuse(rp)?'<button class="btn danger sm" onclick="resolve('+rp.id+',true)">Ban</button>':''}</td>
    </tr>`).join('') || '<tr><td colspan="5" class="empty">No open reports.</td></tr>';
  } catch(e){ $('reports').innerHTML='<tr><td colspan="5" class="err">'+e.message+'</td></tr>'; }
}
/* Ban belongs to a complaint ABOUT somebody. On a bug report — which is what
   nearly every row in this queue is — there is nobody to ban but the person who
   took the trouble to tell you something was broken, and the button sat right
   next to Dismiss. Crash dumps are worse still: the "target" there is whoever's
   phone crashed. */
function isAbuse(rp){ return (rp.context||'') !== 'bug_bounty' && !(rp.reason||'').includes('[CRASH]'); }
/* The wire values are for the code, not for a person reading a queue at 3am.
   ⚠ Object.create(null): with a plain literal, a report whose context is
   'constructor' or 'toString' looks the label up on Object.prototype and the
   queue renders a chunk of JS source. The context comes from a client, so it
   is whatever a client sends. */
const CONTEXT_LABELS = Object.assign(Object.create(null), {bug_bounty:'Bug report', contact:'From a chat', hood:'From the Hood', search:'From search', story:'From a story', message:'About a message', user:'About a user', premium_media:'Paid content'});
function contextLabel(c){ if(!c) return '—'; return CONTEXT_LABELS[c] || (c.startsWith('group:') ? 'In a group' : c); }
function esc(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;'); }
/* Answer the reporter. The text is stored on the report and the reporter reads
   it back over their own authenticated session; the push we send is only a
   doorbell and carries none of it. Replying does NOT resolve the report — you
   can answer first and decide the verdict after. */
async function reply(id){
  const text = prompt('Reply to the reporter. They read this in the app, under "My reports".');
  if(text===null) return;
  if(!text.trim()){ alert('Empty reply not sent.'); return; }
  try{ await api('POST','/reports/'+id+'/reply',{text}); loadReports(); }
  catch(e){ alert(e.message); }
}
/* Report evidence = DECRYPTED media the reporter consented to hand over.
   Fetched one report at a time (never inlined into the list) and every fetch
   is logged server-side with the admin username. Expires on its own; see
   services/evidence_sweep. */
async function viewEvidence(id){
  try{
    // Same-origin + Basic session the rest of the console rides on (see api()).
    const res = await fetch('/admin/reports/'+id+'/evidence', {credentials:'same-origin'});
    if(!res.ok){ alert(res.status===404?'Evidence is gone (expired or already swept).':'HTTP '+res.status); return; }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const w = window.open('', '_blank');
    if(!w){ URL.revokeObjectURL(url); alert('Popup blocked.'); return; }
    const tag = blob.type.startsWith('video/') ? 'video controls autoplay' : 'img';
    w.document.write('<title>report '+id+' evidence</title><body style="margin:0;background:#111;display:flex;align-items:center;justify-content:center;height:100vh"><'+tag+' src="'+url+'" style="max-width:100%;max-height:100%"></body>');
  }catch(e){ alert(e.message); }
}
async function resolve(id,ban_target){ try{ await api('POST','/reports/'+id+'/resolve',{action:ban_target?'banned':'dismissed',notes:'',ban_target}); loadReports(); loadStats(); }catch(e){ alert(e.message); } }

/* ---- server ---- */
async function loadServer() {
  try {
    const info = await serverInfo();
    const reg = info.capabilities.registration_policy;
    // Version, always — not only when there is bad news about it. The update
    // banner shows it when you are behind, which meant an operator who was up
    // to date had no way to answer "what am I running?" at the exact moment it
    // is asked: in a bug report. The console ships with the server, so this
    // number is the panel's version too; there is no second one.
    let ver = '<span style="color:var(--dim)">…</span>';
    try {
      const u = await api('GET','/update-check');
      if (u && u.disabled) {
        ver = `<span class="mono">${u.current}</span> &nbsp;<span style="color:var(--mut)">update check off</span>`;
      } else if (u && u.update_available) {
        ver = `<span class="mono">${u.current}</span> &nbsp;<span class="pill">${u.latest} available</span>`
            + ` &nbsp;<a href="${u.repo_url}" target="_blank" rel="noopener" style="color:var(--acc)">what changed</a>`;
      } else if (u) {
        ver = `<span class="mono">${u.current}</span> &nbsp;<span class="pill green">up to date</span>`;
      }
    } catch(e) { ver = '<span style="color:var(--dim)">unknown</span>'; }
    $('srv-kv').innerHTML = `
      <dt>Version</dt><dd>${ver}</dd>
      <dt>Name</dt><dd>${info.name||'—'}</dd>
      <dt>Host</dt><dd class="mono">${MOCK?'island.example':location.host}</dd>
      <dt>Registration</dt><dd>${reg==='invite'?'<span class="pill">invite-only</span> &nbsp;<span style="color:var(--mut)">new users need an invite code</span>':'<span class="pill green">open</span> &nbsp;<span style="color:var(--mut)">anyone can register</span>'}</dd>
      <dt>UIN shop</dt><dd>${info.capabilities.uin_shop?'enabled':'<span style="color:var(--dim)">off (self-host default)</span>'}</dd>
      <dt>Federation</dt><dd><span class="pill green">on</span> &nbsp;<span style="color:var(--mut)">reachable as <span class="mono">number@${MOCK?'island.example':location.host}</span></span></dd>`;
  } catch(e){ $('srv-kv').innerHTML='<dt class="err">'+e.message+'</dt><dd></dd>'; }
}

/* ---- utils ---- */
function timeago(v){
  /* Accepts an ISO string OR unix SECONDS. The relay list sends seconds, and
     Date.parse(1785000000) is NaN — which fell through to s=0 and printed
     "just now" for every relay the canary had ever seen, including ones dead
     since June. That single NaN is why the Relays tab was unreadable. */
  if(v==null||v==='') return '—';
  const ms = (typeof v==='number') ? v*1000 : (/^[0-9]+$/.test(String(v)) ? Number(v)*1000 : Date.parse(v));
  if(!ms || Number.isNaN(ms)) return '—';
  const s=(Date.now()-ms)/1000;
  if(s<0) return 'just now';
  if(s<60)return 'just now'; if(s<3600)return Math.floor(s/60)+'m'; if(s<86400)return Math.floor(s/3600)+'h'; return Math.floor(s/86400)+'d';
}
/* A relay is servable only while its last successful probe is fresh; the
   broker uses the same 45-minute window when it decides what to hand out. */
function relayLive(v){
  if(v==null||v==='') return false;
  const ms = (typeof v==='number') ? v*1000 : (/^[0-9]+$/.test(String(v)) ? Number(v)*1000 : Date.parse(v));
  return !!ms && !Number.isNaN(ms) && (Date.now()-ms) < 2700*1000;
}

/* ---- mock data for preview ---- */
/* ---- overview: DAU chart + online roster ---- */
async function loadDau() {
  try {
    const t = await api('GET','/timeseries/dau?days=30');
    const pts = t.points||[]; const max = Math.max(1, ...pts.map(p=>p.count));
    $('chart-dau').innerHTML = pts.map(p=>`<div class="bar" style="height:${Math.round(p.count/max*100)}%" title="${p.date}: ${p.count}"></div>`).join('');
    if (pts.length) $('chart-dau-x').innerHTML = `<span>${pts[0].date.slice(5)}</span><span>${pts[pts.length-1].date.slice(5)}</span>`;
  } catch(e){ $('chart-dau').innerHTML=''; }
}
async function loadOnline() {
  try {
    const rows = await api('GET','/presence/online');
    $('online').innerHTML = (rows&&rows.length)
      ? '<table><thead><tr><th>UIN</th><th>Nickname</th><th>Status</th><th>Last seen</th></tr></thead><tbody>'+rows.map(u=>`<tr>
          <td class="mono">${u.uin}</td><td>${escAttr(u.nickname||'')}</td><td>${u.status||''}</td>
          <td class="mono" style="color:var(--dim)">${u.last_seen?timeago(u.last_seen):'—'}</td></tr>`).join('')+'</tbody></table>'
      : '<div class="empty">Nobody online right now.</div>';
  } catch(e){ $('online').innerHTML='<div class="empty">'+e.message+'</div>'; }
}

/* ---- news / announcements ---- */
async function loadNews() {
  try {
    const r = await api('GET','/news');
    const items = (r&&r.items)||[];
    $('news').innerHTML = items.length ? items.map(p=>`<tr>
      <td class="mono" style="color:var(--dim);white-space:nowrap">${timeago(p.published_at)}</td>
      <td>${escAttr((p.body||'').slice(0,160))}${(p.body||'').length>160?'…':''}</td>
      <td>${(p.attachments&&p.attachments.length)||0}</td>
      <td style="text-align:right"><button class="btn danger sm" onclick="deleteNews(${p.id})">Delete</button></td>
    </tr>`).join('') : '<tr><td colspan="4" class="empty">No announcements yet.</td></tr>';
  } catch(e){ $('news').innerHTML='<tr><td colspan="4" class="err">'+e.message+'</td></tr>'; }
}
async function uploadNewsMedia(file) {
  if (MOCK) return {media_id:'mock-'+Math.random().toString(36).slice(2,10), mime:file.type||'image/png', kind:'image'};
  const fd = new FormData(); fd.append('blob', file);
  const r = await fetch('/admin/news/upload', {method:'POST', body:fd, credentials:'same-origin'});
  if (!r.ok) throw new Error('upload failed ('+r.status+')');
  return r.json();
}
async function publishNews() {
  $('n_err').textContent='';
  const body = $('n_body').value.trim();
  if (!body) { $('n_err').textContent='Write something first.'; return; }
  try {
    const atts = []; const files = $('n_files').files||[];
    for (let i=0;i<files.length;i++){ const u = await uploadNewsMedia(files[i]); atts.push({media_id:u.media_id, mime:u.mime}); }
    const payload = { body, attachments: atts };
    if ($('n_author').value.trim()) payload.author_label=$('n_author').value.trim();
    await api('POST','/news',payload);
    $('n_body').value=''; $('n_author').value=''; $('n_files').value='';
    loadNews();
  } catch(e){ $('n_err').textContent='Could not publish: '+e.message; }
}
async function deleteNews(id){ if(!confirm('Delete this announcement?'))return; try{ await api('DELETE','/news/'+id); loadNews(); }catch(e){ alert(e.message); } }

/* ---- sites (.rcq bundles; the only bytes on the island an operator can read) ---- */
async function loadSites() {
  try {
    const rows = (await api('GET','/sites'))||[];
    const listed = rows.filter(s=>s.listed&&!s.frozen).length;
    const featured = rows.filter(s=>s.featured).length;
    $('sites-summary').innerHTML = rows.length
      ? `<b>${rows.length}</b> hosted · <b>${listed}</b> in the catalogue · <b>${featured}</b> featured` : '';
    $('sites').innerHTML = rows.length ? rows.map(s=>{
      const n = escAttr(s.name);
      const state = s.frozen ? '<span class="pill red">frozen</span>'
        : s.listed ? '<span class="pill green">in catalogue</span>'+(s.featured?' <span class="pill vanity">featured</span>':'')
        : '<span class="pill">by name only</span>';
      /* Feature needs a listed site: the island answers 409 otherwise, and
         listing an owner's unlisted site is a decision of its own (the List
         button), never something Feature does on the side. */
      const canFeature = s.listed && !s.frozen;
      /* ⚠⚠ The name is TEXT, not a link to the bundle. A raw /sites/... page
         in the operator's own tab can navigate itself out of the island (a
         meta refresh, a plain link) whatever headers it was served with, and
         that hands a third party the operator's address and the moment a
         human looked at the complaint. View renders it in a locked frame
         instead (siteRender). */
      return `<tr>
      <td class="mono">${n}.rcq</td>
      <td>${s.title?escAttr(s.title):'<span style="color:var(--dim)">—</span>'}</td>
      <td class="mono">#${s.owner_uin}</td>
      <td class="mono" style="color:var(--dim)">${fmtBytes(s.size_bytes||0)}</td>
      <td>${state}</td>
      <td class="mono" style="color:var(--dim)">${timeago(s.updated_at)}</td>
      <td style="text-align:right;white-space:nowrap">
        <button class="btn ghost sm" onclick="openViewer('${n}')">View</button>
        <button class="btn ghost sm" ${s.frozen?'disabled title="A frozen site is out of the catalogue already"':''} onclick="siteListed('${n}',${!s.listed})">${s.listed?'Unlist':'List'}</button>
        <button class="btn ghost sm" ${canFeature?'':'disabled title="Only a site in the catalogue can be featured"'} onclick="siteFeatured('${n}',${!s.featured})">${s.featured?'Unfeature':'Feature'}</button>
        <button class="btn danger sm" onclick="siteFrozen('${n}',${!s.frozen})">${s.frozen?'Unfreeze':'Freeze'}</button>
      </td></tr>`;}).join('') : '<tr><td colspan="7" class="empty">Nobody has published a site here yet.</td></tr>';
  } catch(e){ $('sites').innerHTML='<tr><td colspan="7" class="err">'+e.message+'</td></tr>'; }
}
async function siteListed(name, on){ try{ await api('POST','/sites/'+encodeURIComponent(name)+'/listed?listed='+on); loadSites(); }catch(e){ alert(e.message); } }
async function siteFeatured(name, on){ try{ await api('POST','/sites/'+encodeURIComponent(name)+'/featured',{featured:on}); loadSites(); }catch(e){ alert(e.message); } }
async function siteFrozen(name, on){ if(on&&!confirm('Freeze '+name+'.rcq? Readers get “frozen”, uploads are refused; nothing is deleted.'))return; try{ await api('POST','/sites/'+encodeURIComponent(name)+'/freeze?frozen='+on); loadSites(); }catch(e){ alert(e.message); } }

/* ---- site viewer ----
   ⚠⚠ A bundle is never opened raw. The serve route's policy stops scripts,
   outside images, styles and forms, but no header stops a top-level document
   from navigating ITSELF: a <meta refresh> or a plain link in a site under
   complaint would carry the operator's browser, address and the moment a
   human looked at it, straight to a third party - the one reader a spammer
   most wants to identify. So the bytes are fetched, put through the same
   rules as the app's reader (web-chat src/lib/sites.ts, kept in step by
   hand), and written into a locked frame with no origin, no scripts and
   nothing left in it that could ask the network for anything.
   Regexes below carry doubled backslashes: this JS lives in a plain Python
   string, and one backslash is Python's. */
const SITE_TAGS = new Set(['html','head','body','title','style','meta',
  'div','span','p','br','hr','section','article','main','aside','nav',
  'header','footer','figure','figcaption','blockquote','pre','code','kbd','samp',
  'h1','h2','h3','h4','h5','h6','ul','ol','li','dl','dt','dd',
  'table','thead','tbody','tfoot','tr','th','td','caption','colgroup','col',
  'a','img','strong','b','em','i','u','s','small','sub','sup','mark',
  'time','abbr','cite','q','ruby','rt','rp','wbr','details','summary']);
/* Everything not named here goes, which covers on*, href, ping, srcset,
   formaction, http-equiv and whatever is invented next. */
const SITE_ATTRS = new Set(['class','id','title','lang','dir','alt','width','height',
  'colspan','rowspan','headers','scope','span','datetime','cite','open',
  'start','reversed','value','charset']);
const SITE_IMAGES = {png:'image/png', jpg:'image/jpeg', jpeg:'image/jpeg', gif:'image/gif', webp:'image/webp', svg:'image/svg+xml'};
function siteHas(m, path){ return Object.prototype.hasOwnProperty.call(m.files||{}, path); }
/* `../a/b.png` against the page's own path, inside the bundle only. */
function siteResolve(from, ref) {
  if (/^[a-z]+:/i.test(ref) || ref.startsWith('//') || ref.startsWith('#')) return null;
  const out = ref.startsWith('/') ? [] : from.split('/').slice(0,-1);
  for (const seg of ref.replace(/^[/]/,'').split('/')) {
    if (!seg || seg==='.') continue;
    if (seg==='..') out.pop(); else out.push(seg);
  }
  return out.join('/') || null;
}
/* Author CSS stays, minus anything that fetches; same passes, same order as
   the reader's cleanCss, each one there because a conformance case walked
   through the previous version. Escapes are DECODED, not deleted: an escaped
   url( is url( to the browser and invisible to a scanner. */
function siteCss(css) {
  return css
    .replace(/[/][*][^]*?([*][/]|$)/g, '')
    .replace(/\\\\([0-9a-fA-F]{1,6})[ \\t\\n\\r\\f]?|\\\\(.)/g, (m, hex, ch) => {
      if (!hex) return ch;
      const cp = parseInt(hex, 16);
      return cp > 0x10FFFF ? '' : String.fromCodePoint(cp);
    })
    .replace(/<\\s*[/]\\s*style/gi, '')
    .replace(/@import[^;{]*(;|(?=[{])|$)/gi, '')
    .replace(/@font-face\\s*[{][^}]*[}]/gi, '')
    .replace(/(-\\w+-)?image-set\\s*[(][^)]*[)]/gi, 'none')
    .replace(/url[(]\\s*(?:'\\s*data:|"\\s*data:|data:)[^)]*[)]|url[(][^)]*[)]/gi,
             (m) => (/url[(]\\s*['"]?\\s*data:/i.test(m) ? m : 'none'));
}
async function siteManifest(name) {
  if (MOCK) return Object.assign({}, MOCK_BUNDLE.manifest, {name});
  const r = await fetch('/sites/'+encodeURIComponent(name)+'/manifest.json', {credentials:'omit', referrerPolicy:'no-referrer', cache:'reload'});
  if (r.status===410) throw new Error('frozen');
  if (!r.ok) throw new Error('missing');
  return r.json();
}
/* One file of the bundle: text, or an image as a data: URI so the frame's
   policy can stay `img-src data:` and the page never touches the network. */
async function siteFile(name, m, path, type) {
  let bytes;
  if (MOCK) {
    if (!siteHas(MOCK_BUNDLE, path)) throw new Error('missing');
    bytes = new TextEncoder().encode(MOCK_BUNDLE.files[path]);
  } else {
    const url = '/sites/'+encodeURIComponent(name)+'/'+path.split('/').map(encodeURIComponent).join('/')+'?v='+encodeURIComponent(m.version);
    const r = await fetch(url, {credentials:'omit', referrerPolicy:'no-referrer', cache:'reload'});
    if (r.status===410) throw new Error('frozen');
    if (!r.ok) throw new Error('missing');
    bytes = new Uint8Array(await r.arrayBuffer());
  }
  if (!type) return new TextDecoder().decode(bytes);
  let bin=''; for (const b of bytes) bin += String.fromCharCode(b);
  return 'data:'+type+';base64,'+btoa(bin);
}
async function siteRender(name, m, path) {
  const doc = new DOMParser().parseFromString(await siteFile(name, m, path), 'text/html');
  doc.querySelectorAll('frameset, frame, noframes').forEach(el=>el.remove());
  /* A stylesheet <link> becomes a <style>, which the walk below then treats
     like any author style block. */
  for (const el of Array.from(doc.querySelectorAll('link'))) {
    const rel = (el.getAttribute('rel')||'').toLowerCase();
    const href = siteResolve(path, el.getAttribute('href')||'');
    if (rel!=='stylesheet' || !href || !siteHas(m, href)) { el.remove(); continue; }
    try { const st = doc.createElement('style'); st.textContent = siteCss(await siteFile(name, m, href)); el.replaceWith(st); }
    catch(e){ el.remove(); }
  }
  /* Removed WITH their children: the text inside a script element is code. */
  doc.querySelectorAll('script, iframe, object, embed, form, video, audio, source, track, base, svg, math, canvas, template, noscript, portal').forEach(el=>el.remove());
  const walker = doc.createTreeWalker(doc, NodeFilter.SHOW_COMMENT); const comments=[];
  while (walker.nextNode()) comments.push(walker.currentNode);
  comments.forEach(c=>{ if (c.parentNode) c.parentNode.removeChild(c); });
  for (const img of Array.from(doc.querySelectorAll('img'))) {
    const src = siteResolve(path, img.getAttribute('src')||'');
    const type = src && SITE_IMAGES[(src.split('.').pop()||'').toLowerCase()];
    if (!src || !type || !siteHas(m, src)) { img.remove(); continue; }
    try { img.setAttribute('src', await siteFile(name, m, src, type)); } catch(e){ img.remove(); }
  }
  /* Every link is inert text once the walk strips href; the title keeps
     where it pointed, which is what an operator reviewing a complaint
     actually wants to know. */
  for (const a of Array.from(doc.querySelectorAll('a'))) a.setAttribute('title', a.getAttribute('href')||'');
  for (const el of Array.from(doc.querySelectorAll('*'))) {
    const tag = el.tagName.toLowerCase();
    if (!SITE_TAGS.has(tag)) { el.replaceWith(...Array.from(el.childNodes)); continue; }
    for (const attr of Array.from(el.attributes)) {
      const n = attr.name.toLowerCase();
      const keep = SITE_ATTRS.has(n)
        || (tag==='img' && n==='src' && attr.value.startsWith('data:'))
        || (n==='style' && !/url\\s*[(]|@import/i.test(attr.value));
      if (!keep) el.removeAttribute(attr.name);
    }
    if (tag==='style') el.textContent = siteCss(el.textContent||'');
  }
  /* Our own policy last, so it is not one of the attributes just stripped. */
  const meta = doc.createElement('meta');
  meta.setAttribute('http-equiv','Content-Security-Policy');
  meta.setAttribute('content', "default-src 'none'; img-src data:; style-src 'unsafe-inline'; font-src 'none'");
  doc.head.prepend(meta);
  return '<!doctype html>'+doc.documentElement.outerHTML;
}
let viewerManifest = null;
function viewerSay(text) {
  $('v_frame').srcdoc = '<p style="font:13px -apple-system,sans-serif;color:#9aa1ab;padding:40px;text-align:center">'+escAttr(text)+'</p>';
}
async function showSitePage(name, path) {
  Array.from($('v_pages').children).forEach(b=>b.classList.toggle('on', b.dataset.page===path));
  viewerSay('Loading '+path+'…');
  try { $('v_frame').srcdoc = await siteRender(name, viewerManifest, path); }
  catch(e){ viewerSay(e.message==='frozen' ? 'Frozen: the island does not serve this site while it is held.' : e.message==='missing' ? 'The island has no '+path+' for this site.' : 'Could not reach the island ('+e.message+').'); }
}
async function openViewer(name) {
  $('v_addr').textContent = name+'.rcq';
  $('v_pages').innerHTML = '';
  $('viewer').classList.add('on');
  viewerSay('Loading…');
  try {
    viewerManifest = await siteManifest(name);
    /* index.html first, the rest alphabetically: the page list in our own
       chrome is the only door between pages, as in the reader. */
    const pages = Object.keys(viewerManifest.files||{}).filter(f=>f.toLowerCase().endsWith('.html'))
      .sort((a,b)=> a==='index.html' ? -1 : b==='index.html' ? 1 : a.localeCompare(b));
    if (pages.length > 1) pages.forEach(p=>{
      const b = document.createElement('button'); b.className='btn ghost sm'; b.dataset.page=p; b.textContent=p;
      b.onclick = () => showSitePage(name, p); $('v_pages').appendChild(b);
    });
    await showSitePage(name, pages.includes('index.html') ? 'index.html' : pages[0] || 'index.html');
  } catch(e){ viewerSay(e.message==='frozen' ? 'Frozen: the island does not serve this site while it is held.' : 'Could not load the site ('+e.message+').'); }
}
function closeViewer(){ $('viewer').classList.remove('on'); $('v_frame').srcdoc=''; viewerManifest=null; }
document.addEventListener('keydown', e=>{ if (e.key==='Escape' && $('viewer').classList.contains('on')) closeViewer(); });

/* ---- relays (broker pool — lives under /broker/admin, not /admin) ---- */
async function rawApi(method, path, body) {
  if (MOCK) return mock(method, path, body);
  const opt = { method, headers:{}, credentials:'same-origin' };
  if (body !== undefined) { opt.headers['Content-Type']='application/json'; opt.body=JSON.stringify(body); }
  const r = await fetch(path, opt);
  if (r.status===204) return null;
  const txt = await r.text(); let data=null; try{ data=txt?JSON.parse(txt):null; }catch(e){}
  if (!r.ok) { const d=data&&data.detail; throw new Error((d&&(d.code||d))||('HTTP '+r.status)); }
  return data;
}
async function loadRelays() {
  try {
    const r = await rawApi('GET','/broker/admin/list');
    const rows = (r&&r.relays)||[];
    /* Live first, then by freshness. Without an order the list came back in
       whatever order Postgres felt like, which for a pool that is mostly dead
       means the one working relay hides in the middle. */
    rows.sort((a,b)=>(relayLive(b.last_ok)-relayLive(a.last_ok)) || ((b.last_ok||0)-(a.last_ok||0)));
    const live = rows.filter(x=>relayLive(x.last_ok)).length;
    const dead = rows.length - live;
    $('relays-summary').innerHTML = rows.length
      ? `<b>${live}</b> serving · <b>${dead}</b> not answering${dead?' · <button class="btn ghost sm" onclick="pruneDeadRelays()">Remove dead</button>':''}`
      : '';
    $('relays').innerHTML = rows.length ? rows.map(x=>{
      const alive = relayLive(x.last_ok);
      const d = x.descriptor||{};
      const ep = d.server ? (d.server+':'+(d.port||'')) : '—';
      return `<tr>
      <td>${alive?'<span class="pill green">serving</span>':'<span class="pill red">no answer</span>'}</td>
      <td class="mono" style="color:var(--dim)">${escAttr(ep)}</td>
      <td class="mono">${escAttr(x.tag)}</td>
      <td><span class="pill ${x.tier==='trusted'?'green':''}">${x.tier}</span></td>
      <td>${x.enabled?'<span class="pill green">on</span>':'<span class="pill red">off</span>'}</td>
      <td class="mono" style="color:var(--dim)">${timeago(x.last_ok)}</td>
      <td>${x.fail_count||0}</td>
      <td style="text-align:right;white-space:nowrap">
        <button class="btn ghost sm" onclick="setRelay('${escAttr(x.tag)}',{enabled:${!x.enabled}})">${x.enabled?'Disable':'Enable'}</button>
        <button class="btn ghost sm" onclick="setRelay('${escAttr(x.tag)}',{tier:'${x.tier==='trusted'?'community':'trusted'}'})">${x.tier==='trusted'?'Demote':'Promote'}</button>
        <button class="btn danger sm" onclick="removeRelay('${escAttr(x.tag)}')">Remove</button>
      </td></tr>`;}).join('') : '<tr><td colspan="8" class="empty">No relays registered. Community relays self-register via the bootstrap script.</td></tr>';
  } catch(e){ $('relays').innerHTML='<tr><td colspan="8" class="err">'+e.message+' — the broker may be disabled on this island.</td></tr>'; }
}
/* Dead rows never disappear on their own: a relay that moves to a new IP
   registers a NEW tag and the old one stays forever. Seventeen of them had
   piled up by August, all last seen in June, and every one of them still ate a
   canary probe every ten minutes. */
async function pruneDeadRelays(){
  const r = await rawApi('GET','/broker/admin/list');
  const dead = ((r&&r.relays)||[]).filter(x=>!relayLive(x.last_ok));
  if(!dead.length) return;
  if(!confirm('Remove '+dead.length+' relay(s) that are not answering?')) return;
  for(const x of dead){ try{ await rawApi('DELETE','/broker/admin/'+encodeURIComponent(x.tag)); }catch(e){} }
  loadRelays();
}
async function setRelay(tag, patch){ try{ await rawApi('POST','/broker/admin/set', Object.assign({tag}, patch)); loadRelays(); }catch(e){ alert(e.message); } }
async function removeRelay(tag){ if(!confirm('Remove relay '+tag+'?'))return; try{ await rawApi('DELETE','/broker/admin/'+encodeURIComponent(tag)); loadRelays(); }catch(e){ alert(e.message); } }

/* ---- features (operator toggles) ---- */
const FGROUPS = { features:'Features', limits:'Limits & policy', branding:'Branding' };
function escAttr(s){ return String(s==null?'':s).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;'); }
async function loadFeatures(){
  try { const r = await api('GET','/settings'); renderFeatures((r&&r.settings)||[]); }
  catch(e){ $('features').innerHTML='<div class="card pad"><span class="err">'+e.message+' — check ADMIN_USERNAME / ADMIN_PASSWORD</span></div>'; }
}
function renderFeatures(list){
  const groups = {}; list.forEach(s=>{ (groups[s.group]=groups[s.group]||[]).push(s); });
  ISLAND_NAME = (list.find(s=>s.key==='island_name')||{}).value || '';
  $('features').innerHTML = Object.keys(FGROUPS).filter(g=>groups[g]).map(g=>`
    <div class="card pad"><div class="ftitle">${FGROUPS[g]}</div>
      ${g==='branding'?'<div id="logorow"></div>':''}
      ${groups[g].map((s,i)=>frow(s,i===0&&g!=='branding')).join('')}</div>`).join('')
    || '<div class="card pad"><div class="empty">No settings.</div></div>';
  if ($('logorow')) loadLogo();
}

/* ---- the island's logo ----
 *
 * The one branding setting that is a picture rather than a string, and the one
 * that is NOT in /admin/settings: that endpoint stores strings in a
 * VARCHAR(2048) and truncates to fit, and a truncated data URI is an image
 * that will not open. Its own endpoints, its own single-row table.
 *
 * Everything here exists so nobody learns a rule by having an upload refused:
 * the accepted types and the ceiling are printed next to the button BEFORE the
 * file dialog opens, and the browser resizes the picture down to LOGO_EDGE on
 * the way out so an ordinary file never meets the ceiling at all. */
const LOGO_EDGE = 256;
let ISLAND_NAME = '';
let ISLAND_LOGO = null;

function fmtBytes(n){ return n>=1024 ? Math.round(n/1024)+' KB' : n+' bytes'; }

/* The lettered tile every client falls back to with no logo. Shown rather than
 * an empty box so the operator sees what members see today.
 * ⚠ FNV-1a over the host, matching iOS IslandAvatarView.tint(for:) byte for
 * byte: any other hash would tint this preview differently from the phones and
 * quietly make it a lie. */
function tileTint(host){
  let h = 2166136261;
  for (const b of new TextEncoder().encode(String(host||'').toLowerCase())) {
    h = Math.imul(h ^ b, 16777619) >>> 0;
  }
  return 'hsl('+(h%360)+' 46% 62%)';
}
function tileInitial(name, host){
  const src = String(name||host||'').trim();
  const ch = [...src].find(c=>/\\p{L}|\\p{N}/u.test(c));
  return ch ? ch.toUpperCase() : '#';
}

async function loadLogo(){
  if (MOCK) { ISLAND_LOGO = MOCK_LOGO; renderLogo(null); return; }
  try { ISLAND_LOGO = await api('GET','/server/logo'); renderLogo(null); }
  catch(e){ renderLogo(e.message); }
}

function renderLogo(err){
  const el = $('logorow'); if (!el) return;
  const st = ISLAND_LOGO || {has_logo:false, version:'', max_bytes:65536, mimes:['image/png','image/jpeg','image/webp','image/gif']};
  const types = st.mimes.map(m=>m.replace('image/','').toUpperCase()).join(', ');
  const tile = '<span class="logotile" id="logotile" style="background:'+tileTint(location.host)+'">'
    + escAttr(tileInitial(ISLAND_NAME, location.host)) + '</span>';
  // The preview is the PUBLIC url, the very one the phones build, so what the
  // operator sees here cannot drift from what members see.
  const shot = st.has_logo
    ? '<img class="logoimg" id="logoimg" alt="" src="/server/logo?v='+encodeURIComponent(st.version)+'">'
    : tile;
  el.innerHTML = ''
    + '<div class="frow first"><div class="finfo">'
    +   '<div class="flabel">Island logo'+(st.has_logo?' <span class="pill green">custom</span>':'')+'</div>'
    +   '<div class="fhelp">Your island&rsquo;s picture, shown next to its name wherever a client names it: '
    +     'the account switcher, the confirm before somebody joins, and the island card in Settings. '
    +     'With no logo, every client draws the lettered tile shown here.</div>'
    // ⚠ The rules, BEFORE the picker. Nobody should learn a limit by having a
    // file refused after they chose it.
    +   '<div class="fhelp">'+types+' &middot; up to '+fmtBytes(st.max_bytes)+' &middot; square works best. '
    +     'Anything larger is resized to '+LOGO_EDGE+'&times;'+LOGO_EDGE+' in your browser before it is sent '
    +     '(animated GIFs are sent as they are, so they have to be under the limit already).</div>'
    +   (err?'<div class="fhelp err">'+escAttr(err)+'</div>':'')
    + '</div><div class="fctl">'
    +   shot
    +   '<input type="file" id="logofile" accept="'+escAttr(st.mimes.join(','))+'" style="display:none">'
    +   '<button class="btn sm" id="logopick">'+(st.has_logo?'Replace':'Upload')+'</button>'
    +   (st.has_logo?'<button class="btn sm ghost" id="logodrop">Remove</button>':'')
    + '</div></div>';
  // Handlers bound here rather than inline: an inline onerror carrying the
  // tile markup has to be quoted twice over, and the picture that fails to
  // load is exactly the case that must not itself be broken.
  const img = $('logoimg');
  // A logo the browser cannot draw falls back to the SAME tile the clients
  // draw, never to a broken-image glyph and never to an empty box.
  if (img) img.onerror = () => { img.outerHTML = tile; };
  $('logofile').onchange = function(){ pickLogo(this); };
  $('logopick').onclick = () => $('logofile').click();
  if ($('logodrop')) $('logodrop').onclick = removeLogo;
}

/* True when any pixel of the drawn mark is not fully opaque. Read off the
 * CANVAS rather than guessed from the file type: a PNG is often flat, and a
 * WEBP or a GIF can carry a cut-out just as well. The source is a data: URI,
 * so the canvas is never tainted and getImageData is allowed; if a browser
 * refuses anyway, the answer is "transparent", which only ever costs pixels. */
function hasAlpha(ctx, w, h){
  try {
    const d = ctx.getImageData(0, 0, w, h).data;
    for (let i = 3; i < d.length; i += 4) if (d[i] < 255) return true;
    return false;
  } catch (e) { return true; }
}

/* Read the file as a data URI, downscaled to LOGO_EDGE.
 * GIF is passed through untouched: a canvas resize keeps only the first frame,
 * and an operator who picked an animated mark would get a still one back with
 * nothing saying why. It is therefore the one format that can arrive over the
 * ceiling, and it is refused with a sentence that says what to do. */
function prepareLogo(file, maxBytes){
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onerror = () => reject(new Error('Could not read that file.'));
    r.onload = () => {
      const raw = String(r.result);
      if (file.type === 'image/gif') {
        if (raw.length*0.75 > maxBytes) return reject(new Error(
          'That GIF is about '+fmtBytes(Math.round(raw.length*0.75))+'; the limit is '+fmtBytes(maxBytes)+
          '. Animated logos are uploaded as they are (resizing one would leave only its first frame), '+
          'so it has to be made smaller first.'));
        return resolve(raw);
      }
      const img = new Image();
      img.onerror = () => reject(new Error('That file is not an image the browser can open.'));
      img.onload = () => {
        // ⚠ A mark WITH transparency is never flattened onto white. The old
        // order here was PNG at 256, then JPEG on a white ground, and that is
        // exactly how the flagship's own logo became a white tile: a 256px PNG
        // of it lands over the ceiling, and the JPEG that replaced it cannot
        // carry an alpha channel at all. The operator uploaded a cut-out and
        // got back a slab, with nothing on the screen saying so.
        //
        // So a transparent mark pays in PIXELS instead: it steps down the edge
        // until the PNG fits, because a smaller sharp mark beats a big one on
        // a white square. Only a mark that is opaque to begin with, where the
        // white ground changes nothing, may fall back to JPEG.
        let transparent = null;
        for (const edge of [LOGO_EDGE, 192, 160, 128, 96, 64]) {
          const scale = Math.min(1, edge/Math.max(img.width, img.height));
          const w = Math.max(1, Math.round(img.width*scale)), h = Math.max(1, Math.round(img.height*scale));
          const cv = document.createElement('canvas'); cv.width=w; cv.height=h;
          const ctx = cv.getContext('2d');
          if (!ctx) return reject(new Error('This browser cannot resize the picture.'));
          ctx.drawImage(img, 0, 0, w, h);
          if (transparent === null) transparent = hasAlpha(ctx, w, h);
          const png = cv.toDataURL('image/png');
          if (png.length*0.75 <= maxBytes) return resolve(png);
          if (transparent) continue;  // shrink further rather than lose the cut-out
          // Opaque mark: a photographic one compresses badly as PNG, and the
          // white ground it gets here is the ground it already had.
          ctx.globalCompositeOperation = 'destination-over';
          ctx.fillStyle = '#ffffff'; ctx.fillRect(0,0,w,h);
          for (const q of [0.9, 0.75, 0.6]) {
            const jpg = cv.toDataURL('image/jpeg', q);
            if (jpg.length*0.75 <= maxBytes) return resolve(jpg);
          }
        }
        reject(new Error('That picture is still over '+fmtBytes(maxBytes)+' at 64\u00d764'+
          (transparent ? ', and it has transparency, so it cannot be flattened onto white to shrink it further. ' : '. ')+
          'Try a simpler mark, or one with fewer colours.'));
      };
      img.src = raw;
    };
    r.readAsDataURL(file);
  });
}

async function pickLogo(input){
  const file = input.files && input.files[0];
  input.value = '';  // so the same file twice in a row still fires a change
  if (!file) return;
  const max = (ISLAND_LOGO && ISLAND_LOGO.max_bytes) || 65536;
  try {
    const uri = await prepareLogo(file, max);
    ISLAND_LOGO = MOCK ? Object.assign(MOCK_LOGO, {has_logo:true, version:String(Date.now())})
                : await api('PUT','/server/logo', {data_uri: uri});
    renderLogo(null);
  } catch(e){ renderLogo(e.message); }
}

async function removeLogo(){
  try {
    ISLAND_LOGO = MOCK ? Object.assign(MOCK_LOGO, {has_logo:false, version:''})
                : await api('DELETE','/server/logo');
    renderLogo(null);
  } catch(e){ renderLogo(e.message); }
}

let MOCK_LOGO = {has_logo:false, version:'', max_bytes:65536, mimes:['image/png','image/jpeg','image/webp','image/gif']};
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
  {key:'random_enabled',type:'bool',group:'features',label:'Random Chat',help:'Anonymous roulette-style chat.',value:true,default:true,overridden:false,min:null,max:null,choices:null},
  {key:'registration_policy',type:'str',group:'limits',label:'Registration',help:'Who may create an account on this island.',value:'open',default:'open',overridden:false,min:null,max:null,choices:['open','invite']},
  {key:'max_accounts_per_device',type:'int',group:'limits',label:'Max accounts / device',help:'How many accounts one device may hold.',value:5,default:5,overridden:false,min:1,max:50,choices:null},
  {key:'island_name',type:'str',group:'branding',label:'Island name',help:'Display name clients read from /server/info.',value:'Example Island',default:'RCQ Backend',overridden:true,min:null,max:null,choices:null},
  {key:'welcome_text',type:'str',group:'branding',label:'Welcome / rules',help:'Optional welcome or rules text shown in the app.',value:'',default:'',overridden:false,min:null,max:null,choices:null},
];

const MOCK_SITES = [
  {name:'home', owner_uin:1000, version:4, title:'What this network is', size_bytes:18432, listed:true, show_owner:true, featured:true, frozen:false, updated_at:new Date(Date.now()-7200e3).toISOString()},
  {name:'blog', owner_uin:524060806, version:2, title:'dev notes', size_bytes:5120, listed:true, show_owner:false, featured:false, frozen:false, updated_at:new Date(Date.now()-600e3).toISOString()},
  {name:'drafts', owner_uin:710335446, version:1, title:null, size_bytes:2048, listed:false, show_owner:false, featured:false, frozen:false, updated_at:new Date(Date.now()-86400e3).toISOString()},
  {name:'spam', owner_uin:901003980, version:1, title:'cheap pills', size_bytes:900, listed:false, show_owner:false, featured:false, frozen:true, updated_at:new Date(Date.now()-3*86400e3).toISOString()},
];
/* A deliberately hostile bundle for the design preview: a meta refresh, an
   outward link, a script, a fetching stylesheet. The viewer must show the
   prose and none of the rest. (The script tag is split so the HTML parser
   does not read it as the end of THIS script.) */
const MOCK_BUNDLE = {
  manifest: {v:1, version:4, key:'mock', files:{'index.html':'', 'en.html':'', 'style.css':''}},
  files: {
    'index.html': '<!doctype html><html><head><meta charset="utf-8"><title>home</title>'
      + '<meta http-equiv="refresh" content="0;url=https://tracker.example/?home">'
      + '<link rel="stylesheet" href="style.css"><scr'+'ipt>document.title="pwned"</scr'+'ipt></head>'
      + '<body><h1>What this network is</h1><p><a href="en.html">English</a> · <a href="zh.html">中文</a> · <a href="https://tracker.example/">a link out</a></p>'
      + '<p>Messages, calls and pages that stay inside the network. This paragraph is what the operator sees; the redirect, the script and the outward link above are not.</p>'
      + '<p style="background:url(https://tracker.example/px.png)">An inline style that tried to fetch.</p></body></html>',
    'en.html': '<!doctype html><html><head><meta charset="utf-8"></head><body><h1>What this network is (EN)</h1><p>The second page of the bundle.</p></body></html>',
    'style.css': 'body{font-family:-apple-system,sans-serif;max-width:640px;margin:40px auto;color:#1c1e22} h1{color:#16a34a} @import url(https://tracker.example/x.css); body{background-image:url(https://tracker.example/pixel.png)}',
  },
};
function mock(method, path, body) {
  if (path==='/sites') return MOCK_SITES;
  if (path.startsWith('/sites/') && method==='POST') {
    /* No backslashes: this JS lives inside a plain Python string. */
    const m = path.match(/^[/]sites[/]([^/]+)[/](listed|freeze|featured)(?:[?][a-z]+=(true|false))?$/);
    const s = m && MOCK_SITES.find(x=>x.name===decodeURIComponent(m[1]));
    if (!s) throw new Error('no_site');
    const on = body ? !!body.featured : m[3]==='true';
    if (m[2]==='freeze') { s.frozen=on; if(on){ s.listed=false; s.featured=false; } }
    if (m[2]==='listed') { if(on&&s.frozen) throw new Error('frozen'); s.listed=on; if(!on) s.featured=false; }
    if (m[2]==='featured') { if(on&&s.frozen) throw new Error('frozen'); if(on&&!s.listed) throw new Error('not_listed'); s.featured=on; }
    return s;
  }
  if (path==='/settings') {
    if (method==='PATCH' && body) Object.keys(body).forEach(k=>{ const s=MOCK_SETTINGS.find(x=>x.key===k); if(s){ s.value=body[k]; s.overridden=true; } });
    return { settings: MOCK_SETTINGS };
  }
  if (path.startsWith('/timeseries/dau')) return {points:Array.from({length:30},(_,i)=>{const d=new Date(Date.UTC(2026,4,14+i));return {date:d.toISOString().slice(0,10), count:Math.round(20+28*Math.abs(Math.sin(i/4)))}})};
  if (path === '/update-check') return {current:'2026.08.07', latest:'2026.08.07', update_available:false, repo_url:'https://github.com/rcq-messenger/rcq-server-ref'};
  if (path.startsWith('/metrics')) {
    const now = Math.floor(Date.now()/60000);
    return {
      minutes:60,
      series:Array.from({length:60},(_,i)=>({minute:now-59+i, requests:Math.round(38+26*Math.sin(i/6)), errors:i%17===0?1:0,
        accounts:11+(i%5), boot_chains:13+(i%7), sockets_opened:8+(i%4), sockets_closed:8+(i%4),
        pool_peak_in_use:2+(i%3), pool_at_ceiling:0, busiest_account_chains:i%11===0?9:2})),
      paths:[
        {path:'/messages/queue', calls:900, errors:0, mean_ms:44.2, worst_ms:820.1, per_min:15},
        {path:'/contacts', calls:340, errors:0, mean_ms:161.5, worst_ms:2470.9, per_min:5.7},
        {path:'/groups', calls:120, errors:0, mean_ms:283.5, worst_ms:1210.2, per_min:2},
      ],
      pool:{configured:5, in_use:2, ceiling:10},
    };
  }
  if (path==='/presence/online') return [
    {uin:524060806,nickname:'dev',status:'online',last_seen:new Date(Date.now()-60e3).toISOString()},
    {uin:710335446,nickname:'nosferatu',status:'away',last_seen:new Date(Date.now()-300e3).toISOString()},
  ];
  if (path==='/news') {
    if (method==='POST') return {id:Math.floor(Math.random()*9000), body:(body&&body.body)||'', attachments:(body&&body.attachments)||[], author_label:(body&&body.author_label)||'Example Island', published_at:new Date().toISOString()};
    return {items:[
      {id:3, body:'Scheduled maintenance tonight 02:00–02:30 UTC. Expect a brief blip.', attachments:[], author_label:'Admin', published_at:new Date(Date.now()-3600e3).toISOString()},
      {id:2, body:'New build is out — bug fixes and faster chat scrolling.', attachments:[{media_id:'x',mime:'image/png',kind:'image'}], author_label:'Example Island', published_at:new Date(Date.now()-86400e3).toISOString()},
    ], latest_id:3};
  }
  if (path.startsWith('/news/') && method==='DELETE') return null;
  if (path==='/broker/admin/list') return {relays:[
    {tag:'do-fra', tier:'trusted', enabled:true, last_ok:new Date(Date.now()-120e3).toISOString(), fail_count:0, operator_key:'a1b2c3d4e5f6…'},
    {tag:'community-7', tier:'community', enabled:false, last_ok:null, fail_count:3, operator_key:'99887766…'},
  ]};
  if (path.startsWith('/broker/admin/set')) return {ok:true};
  if (path.startsWith('/broker/admin/') && method==='DELETE') return {ok:true};
  if (path==='/stats') return {total_users:1284, suspended_users:7, new_users_24h:23, new_users_7d:141, open_reports:3, open_crashes:1, resolved_reports_7d:12};
  if (path==='/presence/online-count') return {online:48};
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
  if (path==='/invites' && method==='POST') return {code:'9f2c'+'0'.repeat(60),uin:body.uin||null,used_count:0,max_uses:body.max_uses||1,label:body.label||null,raw_code:'demo_'+Math.random().toString(36).slice(2,18),join_url:'rcq://server/island.example?invite=demo'};
  if (path==='/invites') return [
    {code:'a3f19c22b4'+'0'.repeat(54),uin:777777,used_count:0,max_uses:1,label:'Acme HR (vanity)',raw_code:null,join_url:null},
    {code:'7d0e5581aa'+'0'.repeat(54),uin:null,used_count:3,max_uses:25,label:'Team launch',raw_code:null,join_url:null},
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
    // ⚠ One line that WRAPS, and a command that exists. The bar used to run off
    // the right edge on anything narrower than a desktop (founder, with a
    // screenshot), and it told operators to `git pull` by hand — the updater
    // that dumps the database first, rebuilds and health-checks has been there
    // since 2026-08-16.
    bar.innerHTML = '🔔 Доступно обновление RCQ-сервера: <b>'+u.latest+'</b> (у вас '+u.current+'). '
      + 'Обновить: <code style="background:rgba(0,0,0,.25);padding:1px 5px;border-radius:4px">sudo bash deploy/rcq-update.sh</code> '
      + '(снимет дамп базы, соберёт и проверит здоровье). '
      + '<a href="'+u.repo_url+'" target="_blank" rel="noopener" style="color:#fff;text-decoration:underline">Что изменилось</a>';
    bar.style.display='block';
    document.body.style.paddingTop='46px';
  } catch(e) {}
}

/* ---- boot ---- */
loadStats(); loadChart(); loadDau(); loadActivity(); loadOnline(); checkUpdate();
</script>
</body>
</html>"""
