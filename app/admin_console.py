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

English, Russian and Chinese (Simplified), picked in the rail and remembered in
localStorage; a first visit follows `navigator.language` and falls back to
English. English is the DEFAULT and is not a translation: it stays in the markup
and in the EN table, and the other two are overlays over it, so a string added
later with no translation renders in English rather than as an empty box.

Two things an operator sees stay in English, because this page does not write
them: the help paragraph under each setting on the Features tab (the island
sends it, services/server_settings.py) and the one-line summaries in Recent
activity (the island composes them, routers/admin.py, GET /admin/activity).
Setting LABELS are translated here by key; the help paragraphs are not, and
that is deliberate: they carry dated warnings about what a toggle does to
federation, they are rewritten whenever the behaviour changes, and a copy of one
in this file would go stale silently. A stale warning is worse than an English
one. The Features tab says which half is which, in the reader's language.
"""

ADMIN_CONSOLE_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title data-i18n="app.title">RCQ Server Admin</title>
<style>
  :root {
    /* ⚠ These are the PANEL'S tokens, value for value (web-admin
       tailwind.config.cjs + src/index.css). The panel's light theme was itself
       a redesign to match this console (12.06.2026) and the two then drifted
       apart again; the founder asked for one look, so the console now takes
       the panel's numbers rather than the other way round. The `ink` scale
       there is deliberately inverted - high rungs are surfaces, low rungs are
       text - and the names below say which rung each one is. */
    --bg:#ffffff; --shell:#f6f7f8; --card:#ffffff; --line:#e4e7eb; --line-2:#f3f4f6;
    --ink:#0c0d0e; --fg:#0c0d0e; --fg-2:#4b5563; --mut:#6b7280; --dim:#9aa1ab;
    /* Neutral control fill, ink-700 with its ink-600 hover. */
    --btn:#eceef1; --btn-hover:#e4e7eb;
    --acc:#16a34a; --acc-dim:#15803d; --acc-soft:rgba(22,163,74,.10); --acc-line:#bbf7d0;
    /* Status colours are DARKENED for a light surface, exactly as the panel
       darkens rose/amber/emerald for the same reason. */
    --red:#dc2626; --red-soft:rgba(220,38,38,.10); --amber:#b45309; --green:#047857;
    --flower:#ef3e36;
    --radius:12px; --radius-sm:6px; --shadow:0 1px 2px rgba(12,13,14,.05), 0 4px 16px rgba(12,13,14,.05);
  }
  * { box-sizing:border-box; }
  html,body { height:100%; }
  body { margin:0; background:var(--shell); color:var(--fg);
    font:14px/20px -apple-system,BlinkMacSystemFont,"Inter","SF Pro Text","Segoe UI",Roboto,system-ui,sans-serif;
    /* Inter and SF Pro Text are named but never FETCHED: the page loads zero
       external resources and must keep doing so, so these are used only when
       the reader already has them, exactly as the panel does it. */
    font-feature-settings:'cv11','ss01';
    -webkit-font-smoothing:antialiased; -moz-osx-font-smoothing:grayscale; }
  a { color:var(--acc); text-decoration:none; }
  .mono { font:12px/16px ui-monospace,SFMono-Regular,Menlo,monospace; }

  /* shell */
  .layout { display:grid; grid-template-columns:240px 1fr; min-height:100vh; }
  aside { background:var(--bg); border-right:1px solid var(--line); padding:18px 14px; display:flex; flex-direction:column; gap:4px; position:sticky; top:0; height:100vh; }
  .brand { display:flex; align-items:center; gap:10px; padding:6px 8px 16px; }
  .brand .name { font-weight:600; font-size:16px; line-height:1.25; color:var(--ink); letter-spacing:-.01em; }
  .brand .host { font:11px/1.3 ui-monospace,monospace; color:var(--dim); }
  nav.side { display:flex; flex-direction:column; gap:2px; }
  .navlink { display:flex; align-items:center; gap:12px; padding:8px 12px; border-radius:var(--radius-sm); color:var(--fg-2); font-weight:500; cursor:pointer; transition:background .12s,color .12s; }
  .navlink:hover { background:var(--line-2); color:var(--fg); }
  .navlink.active { background:var(--acc-soft); color:var(--acc); }
  .navlink svg { width:16px; height:16px; flex:none; stroke-width:2.4; }
  .navlink .badge { margin-left:auto; min-width:18px; height:18px; padding:0 6px; border-radius:999px; background:rgba(244,63,94,.15); color:var(--red); font-size:10px; font-weight:500; display:none; align-items:center; justify-content:center; }
  .navlink .badge.on { display:inline-flex; }
  /* The language picker lives at the foot of the rail: it is chosen once and
     then never touched, while every other line in the rail is something the
     operator came here to click.
     ⚠ The auto margin that used to push the footnote down moves HERE. Two
     auto margins in one flex column SPLIT the free space between them, which
     parks the picker halfway up an empty rail. */
  aside .langbox { margin-top:auto; padding:12px 8px 0; }
  aside .langbox select { width:100%; color:var(--fg-2); }
  aside .foot { padding:10px 8px 0; color:var(--dim); font-size:11px; line-height:1.5; }

  /* ⚠ width:100% is load-bearing. `main` is a GRID ITEM, and an auto inline
     margin on a grid item cancels the stretch and sizes it to its content:
     without this the whole console shrank to about a third of the window and
     sat in the middle of it. With an explicit width the column fills the area
     until the cap binds, and only then centres, which is what the panel's
     `mx-auto max-w-6xl` does. */
  /* ⚠⚠ min-width:0 is the other half of that sentence, and without it the
     whole page scrolled sideways. A grid item's automatic minimum size is its
     MIN-CONTENT: width:100% was only a ceiling, and the widest table row was
     the floor, so `main` grew past its own column and took the window with it.
     This was never a translation bug, it was just never measured: in English
     the Sites tab hung 208px off the edge of a 1024px window and every tab hung
     off a phone (measured 13.09.2026). With the floor gone main is exactly its
     column, and a table too wide for it scrolls inside its own card. */
  main { padding:32px 32px 64px; width:100%; min-width:0; max-width:1216px; margin-inline:auto; }
  .view { display:none; }
  .view.active { display:block; animation:fade .18s ease; }
  @keyframes fade { from { opacity:0; transform:translateY(4px); } to { opacity:1; transform:none; } }
  .head { display:flex; align-items:flex-end; justify-content:space-between; gap:16px; margin-bottom:22px; }
  .head h1 { font-size:24px; line-height:32px; font-weight:600; letter-spacing:-.02em; color:var(--ink); margin:0; }
  .head p { margin:4px 0 0; color:var(--mut); font-size:14px; line-height:20px; }

  /* cards */
  .card { background:var(--card); border:1px solid var(--line); border-radius:var(--radius); box-shadow:var(--shadow); }
  .card.pad { padding:20px; }
  .card + .card, .stack > * + * { margin-top:16px; }
  .card h3 { font-size:16px; line-height:24px; font-weight:600; color:var(--ink); margin:0 0 2px; }
  .card .sub { color:var(--mut); font-size:12px; line-height:16px; margin:0 0 14px; }

  /* stats */
  .stats { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:16px; }
  /* ⚠ column-reverse, and it is not a trick: the panel's KpiCard writes the
     label first and the number under it, and the markup here is the other way
     round. Reversing in CSS matches the panel without touching the script that
     builds these tiles. */
  .stat { background:var(--card); border:1px solid var(--line); border-radius:var(--radius); padding:20px; box-shadow:var(--shadow);
    display:flex; flex-direction:column-reverse; gap:6px; align-items:flex-start; }
  .stat .n { font-size:30px; font-weight:600; letter-spacing:0; color:var(--ink); line-height:1; }
  .stat .l { color:var(--mut); font-size:11px; text-transform:uppercase; letter-spacing:.05em; margin-top:0; }
  .stat .n .dot { display:inline-block; width:7px; height:7px; border-radius:50%; background:var(--acc); margin-right:7px; vertical-align:middle; }
  .stat.warn .n { color:var(--amber); }

  /* chart */
  .chart { display:flex; align-items:flex-end; gap:3px; height:84px; margin-top:6px; }
  .chart .bar { flex:1; background:var(--acc-soft); border:1px solid var(--acc-line); border-bottom:0; border-radius:4px 4px 0 0; min-height:2px; position:relative; transition:background .12s; }
  .chart .bar:hover { background:var(--acc-line); }
  .chart-x { display:flex; justify-content:space-between; color:var(--mut); font-size:11px; margin-top:6px; }

  /* table */
  table { width:100%; border-collapse:collapse; font-size:14px; line-height:20px; }
  th,td { text-align:left; padding:12px 16px; border-bottom:1px solid var(--line-2); vertical-align:middle; }
  /* ⚠ NOT uppercase, and that is the panel: its table heads are plain 14px
     medium in muted ink over a full-strength rule (NumbersPanel.tsx:159-164).
     The small-caps head here was the console's own idea. */
  /* keep-all, for the Chinese: without it a column head breaks between any two
     characters, and 更新时间 came out as 更新时 / 间. English and Russian heads
     still wrap at their spaces, which is what keeps the columns narrow. */
  th { color:var(--mut); font-weight:500; font-size:14px; border-bottom-color:var(--line); word-break:keep-all; }
  tr:last-child td { border-bottom:0; }
  tbody tr:hover { background:var(--line-2); }
  td.mono { color:var(--fg); }

  /* controls */
  input,select,textarea { background:var(--bg); border:1px solid var(--line); color:var(--ink); border-radius:var(--radius-sm); padding:8px 14px; font-size:14px; line-height:20px; outline:none; transition:border .12s,box-shadow .12s; font-family:inherit; }
  /* The panel's field is a 1px inset ring that TURNS accent on focus, with no
     halo around it. */
  input:focus,select:focus,textarea:focus { border-color:var(--acc); box-shadow:0 0 0 1px var(--acc); }
  input::placeholder,textarea::placeholder { color:var(--mut); }
  .row { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
  /* A transparent border in the base rule, so a filled button and an outlined
     one are the same height. */
  button { font:inherit; font-size:14px; line-height:20px; font-weight:500; border:1px solid transparent; border-radius:var(--radius-sm); padding:8px 14px; cursor:pointer; transition:background .12s,opacity .12s,border-color .12s; }
  .btn { background:var(--acc); color:#fff; box-shadow:0 1px 2px rgba(0,0,0,.05); }
  .btn:hover { background:var(--acc-dim); }
  .btn.ghost { background:var(--btn); border-color:transparent; color:var(--ink); }
  .btn.ghost:hover { background:var(--btn-hover); }
  .btn.danger { background:rgba(220,38,38,.12); border-color:transparent; color:var(--red); }
  .btn.danger:hover { background:rgba(220,38,38,.22); }
  .btn.sm { padding:6px 12px; font-size:13px; }
  .btn:disabled { opacity:.4; cursor:not-allowed; }
  /* features tab rows */
  .frow { display:flex; align-items:flex-start; gap:14px; padding:12px 0; border-top:1px solid var(--line-2); }
  .frow.first { border-top:none; padding-top:2px; }
  /* ⚠⚠ The control column MUST be allowed to shrink and wrap. It was
     `flex:none`, which is fine for a field and a button and fatal for the
     structured editors (prices, wallets, badges): one long help line inside
     them gave the column its full max-content width, the label column beside
     it collapsed to one word per line, and the row ran off the card and off
     the window. The editors shipped on 03-05.09 with NO styles of their own
     while the console itself was dead, so nobody saw it (founder, 08.09). */
  .frow .finfo { flex:1 1 280px; min-width:0; }
  .frow .flabel { font-weight:500; font-size:14px; line-height:20px; display:flex; align-items:center; gap:8px; }
  .frow .fhelp { color:var(--mut); font-size:12px; line-height:16px; margin-top:2px; }
  .frow .fctl { flex:0 1 auto; min-width:0; max-width:min(64%,760px); display:flex; flex-wrap:wrap; gap:8px; align-items:center; justify-content:flex-end; }
  /* The structured editors on the Features tab. */
  .editor { display:flex; flex-direction:column; gap:8px; min-width:0; width:100%; }
  .editor .erow { display:flex; align-items:center; gap:8px; min-width:0; }
  .editor .erow label { flex:none; min-width:96px; color:var(--mut); font-size:13px; }
  .editor .erow input { flex:1 1 auto; min-width:0; }
  .editor .erow input[type=number] { flex:0 0 auto; }
  .editor .ehint { color:var(--mut); font-size:12px; }
  .editor .ehelp { color:var(--mut); font-size:12px; line-height:16px; white-space:normal; }
  .editor .brow { display:flex; align-items:center; gap:8px; flex-wrap:wrap; min-width:0; }
  .editor .brow input[type=color] { flex:none; width:36px; height:36px; padding:2px; }
  .editor > button { align-self:flex-start; }
  /* The island's logo preview, and the lettered tile a client draws when there
     is none. Rounded square, not a circle: a person is a circle and a group is
     a circle, and an island is neither (same shape iOS IslandAvatarView draws). */
  .logoimg, .logotile { width:44px; height:44px; border-radius:12px; flex:none; }
  .logoimg { object-fit:cover; background:var(--line-2); }
  .logotile { display:flex; align-items:center; justify-content:center;
    color:#fff; font-weight:700; font-size:20px; line-height:1; }
  .ftitle { font-size:11px; text-transform:uppercase; letter-spacing:.05em; color:var(--mut); margin:0 0 8px; font-weight:500; }

  .seg { display:inline-flex; background:var(--line-2); border-radius:8px; padding:3px; gap:2px; }
  .seg button { background:transparent; color:var(--mut); padding:6px 14px; border-radius:var(--radius-sm); }
  .seg button.on { background:var(--bg); color:var(--ink); box-shadow:var(--shadow); }

  /* Filled, not outlined: the panel's pills carry their meaning in the fill
     (src/index.css, .pill and friends). */
  /* nowrap: a pill is one word to read, and a two-line pill in a table cell
     reads as two states. Russian has the long ones ("не отвечает"), which is
     where it showed. */
  .pill { display:inline-flex; align-items:center; gap:6px; padding:2px 10px; border-radius:999px; font-size:11px; font-weight:500; border:0; background:var(--btn); color:#374151; white-space:nowrap; }
  .pill.green { color:var(--green); background:rgba(16,185,129,.10); }
  .pill.red { color:var(--red); background:var(--red-soft); }
  .pill.vanity { color:var(--acc); background:var(--acc-soft); }

  /* ⚠ The action column WRAPS. It was `white-space:nowrap`, which is right
     until the words get longer: four buttons that may not break set a floor
     under the whole table, and the table then pushed the card into a sideways
     scroll (Sites in Russian at 1280px, and Sites in English at 1024px, which
     had been true since the tab shipped). Wrapped, the buttons stack in the
     last column and every other column keeps its width. */
  td.acts { text-align:right; white-space:normal; }
  td.acts button { margin:1px 0; }

  .err { color:var(--red); font-size:14px; line-height:20px; margin-top:8px; }
  .empty { color:var(--mut); padding:18px 4px; font-size:14px; line-height:20px; }
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
    aside { position:fixed; z-index:40; width:240px; left:0; top:0; transform:translateX(-100%); transition:transform .2s; box-shadow:var(--shadow); }
    aside.open { transform:none; }
    .menubtn { display:inline-flex; }
    main { padding:20px 16px 56px; }
    .scrim { display:none; position:fixed; inset:0; background:rgba(12,13,14,.25); z-index:30; }
    .scrim.on { display:block; }
  }
  /* A dense table SCROLLS INSIDE ITS CARD, at every width. A table whose last
     column is four buttons cannot be made narrower than those buttons, so past
     some width the overflow has to go somewhere, and inside the card is the
     only place where it costs nothing: the headings, the help text and the rail
     all stay where they are. This was a phone-only rule (max-width:640px) and
     is now unconditional, together with min-width:0 on main above. Russian
     labels run about a fifth longer than English, which is what pushed the
     Sites tab 141px off a 1280px window and got the pair measured. */
  .card.pad { overflow-x:auto; -webkit-overflow-scrolling:touch; }
  /* On a phone the same table also crushed its other columns into tall thin
     strips, so there it additionally keeps a floor under its own width. */
  @media (max-width:640px) {
    table { min-width:520px; }
    th, td { white-space:nowrap; }
    td:nth-child(3) { white-space:normal; min-width:200px; }  /* the reason/long cell wraps within its own width */
  }
  /* iOS zooms the whole page when a focused field's text is under 16px and
     leaves the reader scrolled sideways in a layout that fitted a moment ago.
     There is no opt-out that does not also kill pinch zoom, so the field grows
     instead - the same trade the panel makes in src/index.css. */
  @media (max-width:1023px) {
    input,select,textarea { font-size:16px; }
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
      <span class="vnote" data-i18n="vw.note">Locked frame, same rules as the app's reader: links do nothing, nothing loads from outside.</span>
      <button class="btn ghost sm" data-i18n="common.close" onclick="closeViewer()">Close</button>
    </div>
    <iframe id="v_frame" sandbox referrerpolicy="no-referrer" title="Site under review" data-i18n-title="vw.frame_title"></iframe>
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
    <!-- The three names are endonyms and are never translated: somebody looking
         for their own language looks for the word they call it by. -->
    <div class="langbox">
      <select id="langpick" title="Language" data-i18n-title="shell.lang" onchange="setLang(this.value)">
        <option value="en">English</option><option value="ru">Русский</option><option value="zh">中文</option>
      </select>
    </div>
    <div class="foot" data-i18n="shell.foot">Self-hosted · runs entirely on your server.<br>No dependency on rcq.app.</div>
  </aside>
  <div class="scrim" id="scrim" onclick="closeSide()"></div>

  <main>
    <button class="btn ghost sm menubtn" style="margin-bottom:14px" data-i18n="shell.menu" onclick="openSide()">☰ Menu</button>

    <!-- OVERVIEW -->
    <section class="view active" id="v-overview">
      <div class="head"><div><h1 data-i18n="ov.h1">Overview</h1><p data-i18n="ov.sub">Your server at a glance.</p></div></div>
      <div class="stats" id="stats"><span class="empty" data-i18n="common.loading">Loading…</span></div>
      <div class="card pad" style="margin-top:16px">
        <h3 data-i18n="ov.signups.h">New users · last 30 days</h3>
        <p class="sub" data-i18n="ov.signups.sub">Signups per day.</p>
        <div class="chart" id="chart"></div>
        <div class="chart-x" id="chart-x"></div>
      </div>
      <div class="card pad" style="margin-top:16px">
        <h3 data-i18n="ov.dau.h">Active users · last 30 days</h3>
        <p class="sub" data-i18n="ov.dau.sub">Distinct users active per day.</p>
        <div class="chart" id="chart-dau"></div>
        <div class="chart-x" id="chart-dau-x"></div>
      </div>
      <div class="card pad" style="margin-top:16px">
        <h3 data-i18n="ov.online.h">Online now</h3>
        <p class="sub" data-i18n="ov.online.sub">Users connected to your server right now.</p>
        <div id="online"></div>
      </div>
      <div class="card pad" style="margin-top:16px">
        <h3 data-i18n="ov.activity.h">Recent activity</h3>
        <p class="sub" data-i18n="ov.activity.sub">Latest moderation actions.</p>
        <div id="activity"></div>
      </div>
    </section>

    <!-- INSTRUMENTS -->
    <section class="view" id="v-instruments">
      <div class="head"><div><h1 data-i18n="ins.h1">Instruments</h1><p data-i18n="ins.sub">What your server is doing to itself, last hour. Counted inside the process, so on a multi-worker install these are <b>one worker&rsquo;s</b> numbers, and they reset whenever the server restarts. Read the shape, not the absolute.</p></div></div>
      <div class="stats" id="inst-stats"><span class="empty" data-i18n="common.loading">Loading…</span></div>
      <div class="card pad" style="margin-top:16px">
        <h3 data-i18n="ins.req.h">Requests · last hour</h3>
        <p class="sub" data-i18n="ins.req.sub">One bar per minute. Hover a bar for the count.</p>
        <div class="chart" id="inst-chart"></div>
        <div class="chart-x" id="inst-chart-x"></div>
      </div>
      <div class="card pad" style="margin-top:16px">
        <h3 data-i18n="ins.time.h">Where the time goes</h3>
        <p class="sub" data-i18n="ins.time.sub">Sorted by total time spent, not by how often it is called: the endpoint worth fixing is the one the server spends its life in. &ldquo;Worst&rdquo; is the slowest single call, which an average hides. The clock counts <b>server work only</b>: the time a client spends sending its request body is measured separately, so a phone dying mid-upload no longer paints an endpoint red.</p>
        <p class="sub" id="inst-slowbodies" style="display:none"></p>
        <table><thead><tr><th data-i18n="ins.th.path">Path</th><th style="text-align:right" data-i18n="ins.th.calls">Calls/min</th><th style="text-align:right" data-i18n="ins.th.typical">Typical</th><th style="text-align:right" data-i18n="ins.th.worst">Worst</th><th style="text-align:right">5xx</th></tr></thead>
          <tbody id="inst-paths"></tbody></table>
      </div>
    </section>

    <!-- INVITES -->
    <section class="view" id="v-invites">
      <div class="head"><div><h1 data-i18n="inv.h1">Invites &amp; UINs</h1><p data-i18n="inv.sub">Join codes for an <b>invite-only</b> server. If you set Registration to “invite” (Features tab), new users must enter one of these codes to sign up — otherwise this tab is optional. You can also pre-assign a specific UIN to someone.</p></div></div>
      <div class="card pad">
        <div class="row">
          <input id="i_label" placeholder="Label (e.g. Acme HR)" data-i18n-ph="inv.ph.label" style="flex:1;min-width:160px">
          <input id="i_uin" type="number" placeholder="UIN (optional)" data-i18n-ph="inv.ph.uin" style="width:170px">
          <input id="i_uses" type="number" value="1" min="1" title="Max uses" data-i18n-title="inv.title.uses" style="width:84px">
          <input id="i_ttl" type="number" placeholder="TTL hrs" data-i18n-ph="inv.ph.ttl" title="Expires after N hours" data-i18n-title="inv.title.ttl" style="width:96px">
          <button class="btn" data-i18n="common.create" onclick="mintInvite()">Create</button>
        </div>
        <p class="sub" style="margin:10px 0 0" data-i18n="inv.help"><b>Label</b> is just a note for you. <b>UIN</b>: leave blank for a random number, or set one to reserve a specific (vanity) number for the holder. <b>Max uses</b>: how many people may register with this code (use 1 for a single person). <b>TTL hrs</b>: auto-expire after N hours (blank = never). After Create, copy the code straight away: this island keeps only a hash of it and cannot show it to you again.</p>
        <div class="err" id="i_err"></div>
        <div id="i_new" style="display:none;margin-top:12px"></div>
      </div>
      <div class="card pad">
        <table><thead><tr><th data-i18n="inv.th.code">Code (hash)</th><th data-i18n="inv.th.uin">UIN</th><th data-i18n="inv.th.uses">Uses</th><th data-i18n="inv.th.label">Label</th><th></th></tr></thead>
          <tbody id="invites"></tbody></table>
      </div>
    </section>

    <!-- ACCESS TOKENS (closed/private island gate) -->
    <section class="view" id="v-access">
      <div class="head"><div><h1 data-i18n="acc.h1">Access tokens</h1><p data-i18n="acc.sub">Only for a <b>closed (private) island</b> — one that runs the masquerade Caddyfile so the server looks like an ordinary website and refuses anyone without a valid token. These are the per-person, revocable keys you hand out. <b>If you haven’t set up the masquerade Caddyfile, ignore this tab.</b></p></div></div>
      <div class="card pad">
        <div class="row">
          <input id="a_label" placeholder="Label (e.g. Alice)" data-i18n-ph="acc.ph.label" style="flex:1;min-width:160px">
          <select id="a_kind" style="width:150px" onchange="$('a_max').style.display=this.value==='standing'?'':'none'"><option value="invite" data-i18n="acc.kind.invite">One-time invite</option><option value="standing" data-i18n="acc.kind.standing">Standing</option></select>
          <input id="a_max" type="number" min="1" placeholder="Max uses (∞ if blank)" data-i18n-ph="acc.ph.max" title="Standing token: how many times it may be used" data-i18n-title="acc.title.max" style="width:170px;display:none">
          <input id="a_ttl" type="number" placeholder="Expires (days)" data-i18n-ph="acc.ph.ttl" title="Expires after N days" data-i18n-title="acc.title.ttl" style="width:130px">
          <button class="btn" data-i18n="common.create" onclick="createAccess()">Create</button>
        </div>
        <p class="sub" style="margin:10px 0 0" data-i18n="acc.help">A one-time invite is redeemed by the first device that uses it (a re-posted invite then stops working). A standing token is multi-use. The full token is shown ONCE on creation — copy it then.</p>
        <div class="err" id="a_err"></div>
        <div id="a_new" style="display:none;margin-top:10px"></div>
      </div>
      <div class="card pad">
        <table><thead><tr><th data-i18n="acc.th.label">Label</th><th data-i18n="acc.th.kind">Kind</th><th data-i18n="acc.th.uses">Uses</th><th data-i18n="acc.th.last">Last used</th><th></th></tr></thead>
          <tbody id="access"></tbody></table>
      </div>
    </section>

    <!-- USERS -->
    <section class="view" id="v-users">
      <div class="head"><div><h1 data-i18n="usr.h1">Users &amp; groups</h1><p data-i18n="usr.sub">Search by number, nickname or group name. Suspend abusers, give a badge.</p></div></div>
      <div class="card pad">
        <div class="row">
          <input id="u_q" placeholder="Search by UIN, nickname or group name" data-i18n-ph="usr.ph.q" style="flex:1" onkeydown="if(event.key==='Enter')searchUsers()">
          <button class="btn ghost" data-i18n="usr.search" onclick="searchUsers()">Search</button>
        </div>
        <p class="hint" style="margin:8px 0 0" data-i18n="usr.hint">A badge is your island vouching for an account in front of everyone on it. It shows next to the name in every client. Nothing outside this island can grant one, and nothing outside it will believe yours.</p>
      </div>
      <div class="card pad">
        <table><thead><tr><th data-i18n="usr.th.uin">UIN</th><th data-i18n="usr.th.nick">Nickname</th><th data-i18n="usr.th.status">Status</th><th data-i18n="usr.th.reports">Reports</th><th data-i18n="usr.th.badge">Badge</th><th></th></tr></thead>
          <tbody id="users"><tr><td colspan="6" class="empty" data-i18n="usr.empty.start">Search to list users.</td></tr></tbody></table>
      </div>
      <div class="card pad">
        <table><thead><tr><th data-i18n="usr.th.group">Group</th><th data-i18n="usr.th.owner">Owner</th><th data-i18n="usr.th.members">Members</th><th data-i18n="usr.th.badge">Badge</th></tr></thead>
          <tbody id="ugroups"><tr><td colspan="4" class="empty" data-i18n="usr.groups.start">Groups matching the search appear here.</td></tr></tbody></table>
      </div>
    </section>

    <!-- REPORTS -->
    <section class="view" id="v-reports">
      <div class="head">
        <div><h1 data-i18n="rep.h1">Reports</h1><p data-i18n="rep.sub">What your users sent you: abuse reports about other members, and bug reports about the island itself. Answer, then dismiss or ban. Your answer is delivered to the reporter in the app, so it is worth writing one even when you dismiss.</p></div>
      </div>
      <div class="card pad">
        <table><thead><tr><th>#</th><th data-i18n="rep.th.target">Target</th><th data-i18n="rep.th.reason">Reason</th><th data-i18n="rep.th.context">Context</th><th></th></tr></thead>
          <tbody id="reports"></tbody></table>
      </div>
    </section>

    <!-- SERVER -->
    <!-- NEWS / ANNOUNCEMENTS -->
    <section class="view" id="v-news">
      <div class="head"><div><h1 data-i18n="news.h1">News</h1><p data-i18n="news.sub">Broadcast an announcement to every user's in-app news feed — patch notes, planned downtime, rules.</p></div></div>
      <div class="card pad">
        <textarea id="n_body" rows="4" placeholder="Write an announcement… (up to 4000 chars)" data-i18n-ph="news.ph.body" style="width:100%;box-sizing:border-box;resize:vertical"></textarea>
        <div class="row" style="margin-top:10px">
          <input id="n_author" placeholder="Author (empty = this island's name)" data-i18n-ph="news.ph.author" style="flex:1;min-width:150px">
          <input id="n_files" type="file" multiple accept="image/*,video/*" title="Optional image/video attachments" data-i18n-title="news.title.files" style="flex:1;min-width:150px">
          <button class="btn" data-i18n="news.publish" onclick="publishNews()">Publish</button>
        </div>
        <p class="sub" style="margin:10px 0 0" data-i18n="news.help">Posts appear in every user's News feed, signed with the author you typed, or with this island's name when the field is empty. Attachments are optional (images / video).</p>
        <div class="err" id="n_err"></div>
      </div>
      <div class="card pad">
        <table><thead><tr><th data-i18n="news.th.posted">Posted</th><th data-i18n="news.th.body">Body</th><th data-i18n="news.th.media">Media</th><th></th></tr></thead>
          <tbody id="news"></tbody></table>
      </div>
    </section>

    <!-- SITES (.rcq bundles this island hosts) -->
    <section class="view" id="v-sites">
      <div class="head"><div><h1 data-i18n="sit.h1">Sites</h1><p data-i18n="sit.sub">The <b>.rcq</b> pages this island hosts — the one kind of content here you can actually read, because it is public by definition. <b>View</b> shows a site here, in a locked frame and through the same sanitiser as the app's reader: its links do nothing and nothing in it loads from outside, so looking at a site under complaint never tells its author that somebody did. <b>List / Unlist</b> is the shop window: a listed site shows in the catalogue on the front page of every browser on this island, an unlisted one still opens by its exact name. <b>Feature</b> pins a listed site to the top of that catalogue, in its own section above recents — the network's own <span class="mono">home.rcq</span> is what it is for. <b>Freeze</b> is the hold for a complaint: reads answer “frozen”, uploads are refused, nothing is deleted, and it is reversible.</p></div></div>
      <div class="card pad">
        <p class="sub" id="sites-summary" style="margin:0 0 8px"></p>
        <table><thead><tr><th data-i18n="sit.th.site">Site</th><th data-i18n="sit.th.line">Catalogue line</th><th data-i18n="sit.th.owner">Owner</th><th data-i18n="sit.th.size">Size</th><th data-i18n="sit.th.state">State</th><th data-i18n="sit.th.updated">Updated</th><th></th></tr></thead>
          <tbody id="sites"></tbody></table>
      </div>
    </section>

    <!-- RELAYS (community circumvention pool) -->
    <section class="view" id="v-relays">
      <div class="head"><div><h1 data-i18n="rel.h1">Relays</h1><p data-i18n="rel.sub">Advanced — only relevant if someone runs censorship-circumvention relays for <b>your</b> island. This lists relays registered with <b>your own</b> server’s broker (never another island’s). Most operators can ignore this tab; it stays empty until a relay self-registers.</p></div></div>
      <div class="card pad">
        <p class="sub" style="margin:0" data-i18n="rel.help"><b>Tier</b> — <span class="mono">community</span> relays are handed to clients only after a health check confirms they work; <span class="mono">trusted</span> relays are always offered (use that for relays you run yourself). <b>Promote / Demote</b> moves a relay between those tiers. <b>Remove</b> just drops it from the pool — clients fall back to your other relays or a direct connection; nothing is deleted on the relay’s own host, and removing the last one simply means no circumvention relays are advertised.</p>
      </div>
      <div class="card pad">
        <p class="sub" id="relays-summary" style="margin:0 0 8px"></p>
        <table><thead><tr><th data-i18n="rel.th.health">Health</th><th data-i18n="rel.th.endpoint">Endpoint</th><th data-i18n="rel.th.tag">Tag</th><th data-i18n="rel.th.tier">Tier</th><th data-i18n="rel.th.state">State</th><th data-i18n="rel.th.lastok">Last OK</th><th data-i18n="rel.th.fails">Fails</th><th></th></tr></thead>
          <tbody id="relays"></tbody></table>
      </div>
    </section>

    <!-- FEATURES (operator toggles) -->
    <section class="view" id="v-features">
      <div class="head"><div><h1 data-i18n="fea.h1">Features</h1><p data-i18n="fea.sub">Turn optional features on or off, and set limits &amp; branding for your island. Changes apply live — no restart.</p></div></div>
      <!-- Only the languages that need it fill this in: the label of every
           setting is translated, the help under it is the island's own English.
           applyI18n hides the line when the string is empty. -->
      <p class="sub" id="fea-note" style="margin:-12px 0 16px" hidden></p>
      <div id="features"><div class="card pad"><div class="empty" data-i18n="common.loading">Loading…</div></div></div>
    </section>

    <section class="view" id="v-server">
      <div class="head"><div><h1 data-i18n="srv.h1">Server &amp; federation</h1><p data-i18n="srv.sub">How your island is configured and how it joins the wider RCQ network.</p></div></div>
      <div class="card pad">
        <h3 data-i18n="srv.this.h">This island</h3>
        <p class="sub" data-i18n="srv.this.sub">Read from your live configuration.</p>
        <dl class="kv" id="srv-kv"><dt data-i18n="common.loading">Loading…</dt><dd></dd></dl>
      </div>
      <div class="card pad">
        <h3 data-i18n="srv.join.h">Joining the public network</h3>
        <p class="sub" data-i18n="srv.join.sub">What makes your server reachable by people on other islands.</p>
        <div class="note" id="fed-note">
          <p style="margin:0 0 10px" data-i18n="srv.note1"><b>Your island already federates.</b> Anyone can reach a contact or join a group on your server using <span class="mono">uin@your-host</span> or a group link <span class="mono">your-host/g/&lt;id&gt;</span> — no central registry is involved, and you do not need to be in any catalogue for this to work.</p>
          <p style="margin:0 0 10px" data-i18n="srv.note2">The <b>public catalogue</b> (the <a href="https://rcq.app/servers" target="_blank">rcq.app/servers</a> list + the in-app auto-backup picker) is <b>only for discovery</b>: it lets strangers find your island and lets the app offer it as a backup. Listing is optional and is a maintainer-reviewed pull request to the <span class="mono">rcq-servers</span> repo.</p>
          <p style="margin:0" data-i18n="srv.note3"><b>To join a group on another island:</b> open that group's invite link (it must carry the host, e.g. <span class="mono">rcq.app/g/42@island.example</span>) in the app and confirm — your client guest-registers you there automatically. If the target island has <b>invite-only</b> registration, you need one of its invite codes first.</p>
        </div>
      </div>
    </section>
  </main>
</div>

<script>
const $ = (id) => document.getElementById(id);
const MOCK = location.protocol === 'file:' || location.search.includes('mock');

/* ---- languages ----
 *
 * English, Russian and Chinese in one file, no build step.
 *
 * English is NOT a translation. It stays where it always was: in the markup,
 * with `data-i18n="<id>"` on the element that owns the text, and in EN below for
 * the strings this script builds itself. `i18nCapture()` reads the markup's
 * English into EN_BASE at boot, so no sentence is written twice and switching
 * back to English restores the exact bytes that shipped. A page whose script
 * dies half way therefore still reads as English, which is the state the
 * console was in for three days in September and the reason the parse test
 * exists.
 *
 * A translation is an OVERLAY, and that is what decides how a MISSING string
 * behaves. t() looks in the chosen language, then in English, then says so out
 * loud: a string somebody adds next month with no Russian for it renders in
 * English, and an id that is misspelt renders as the id in brackets, warns on
 * the console and, in the preview, paints the bar at the top of the page. What
 * cannot happen is an empty box, which is the one failure an operator cannot
 * report and nobody can debug from a screenshot.
 *
 * Placeholders are {name}. Word order is not ours to keep: Chinese puts the
 * address in "reachable as {addr}" before the verb.
 *
 * Not translated, on purpose: UINs, hostnames, chain and token names, setting
 * keys, relay tags, badge kinds, endpoint paths, HTTP status codes, tier names
 * (`community` / `trusted`) and the shell commands in the update bar. They are
 * identifiers an operator types, greps or pastes, and a translated identifier
 * is a support ticket.
 *
 * The Features tab is half ours: the label of each setting is translated here
 * by its key (`set.<key>`), and the help paragraph under it comes from the
 * island itself (services/server_settings.py) and stays in the server's
 * English. That is deliberate. Those paragraphs carry dated warnings about what
 * a toggle does to federation, they are rewritten whenever the behaviour
 * changes, and a copy of one in this file would go stale silently the first
 * time somebody edits the original. A stale warning is worse than an English
 * one, so the tab says which half is which instead (fea.note). The summaries in
 * Recent activity are English for the same reason: the island writes them.
 *
 * Values are written with innerHTML: they carry <b> and <span class="mono"> on
 * purpose and every one of them is a literal in this file. Nothing from the
 * island, from a member or from a URL ever reaches t().
 */
const LANGS = ['en', 'ru', 'zh'];
const LOCALES = {en:'en-US', ru:'ru-RU', zh:'zh-CN'};
const LANG_KEY = 'rcq.admin.lang';

/* First visit: follow the browser, fall back to English. `navigator.language`
   is a tag like "ru-RU" or "zh-Hans-CN", so match on the primary subtag only;
   every Chinese variant gets Simplified because that is the only one here. */
function langFromBrowser(){
  const tag = String((navigator.languages && navigator.languages[0]) || navigator.language || '').toLowerCase();
  const primary = tag.split('-')[0];
  return LANGS.indexOf(primary) >= 0 ? primary : 'en';
}
function storedLang(){
  /* localStorage throws outright in a file:// page in some browsers, and this
     page is opened as a file on purpose (the design preview). A language
     picker is not worth a dead console. */
  try { const v = localStorage.getItem(LANG_KEY); return LANGS.indexOf(v) >= 0 ? v : null; } catch(e){ return null; }
}
let LANG = storedLang() || langFromBrowser();

const EN_BASE = Object.create(null);   /* English, read off the markup at boot */
const I18N_MISSING = [];

function i18nMissing(id){
  if (I18N_MISSING.indexOf(id) >= 0) return;
  I18N_MISSING.push(id);
  console.warn('admin console: no string for "' + id + '"');
  if (!MOCK) return;
  /* The preview is how this file is reviewed, so a missing id is not allowed to
     be quiet there. The update bar is unused off a live backend. */
  const bar = $('updbar');
  bar.textContent = 'i18n: no string for ' + I18N_MISSING.join(', ');
  bar.style.display = 'block';
  document.body.style.paddingTop = '46px';
}
function i18nFill(s, vars){
  return s.replace(/[{]([a-z0-9_]+)[}]/gi, (m, k) =>
    Object.prototype.hasOwnProperty.call(vars, k) ? String(vars[k]) : m);
}
function t(id, vars){
  const d = I18N[LANG];
  let s;
  if (d && Object.prototype.hasOwnProperty.call(d, id)) s = d[id];
  else if (Object.prototype.hasOwnProperty.call(EN, id)) s = EN[id];
  else if (Object.prototype.hasOwnProperty.call(EN_BASE, id)) s = EN_BASE[id];
  if (s === undefined) { i18nMissing(id); return '⟦' + id + '⟧'; }
  return vars ? i18nFill(s, vars) : s;
}
/* A translation that MAY be absent, for the strings the island sends us in its
   own English (the Features tab). No marker and no warning: English is the
   answer, not a bug. */
function tOpt(id){
  const d = I18N[LANG];
  return (d && Object.prototype.hasOwnProperty.call(d, id)) ? d[id] : null;
}
/* Numbers the operator reads as quantities. 1284 is "1,284" in English and
   "1 284" in Russian, and a wrong thousands separator is how a dashboard stops
   being trusted. Byte sizes and prices go through fmtBytes and the price
   editor; ms figures stay bare next to their unit. */
function num(n){
  try { return new Intl.NumberFormat(LOCALES[LANG] || 'en-US').format(n); }
  catch(e){ return String(n); }
}

function i18nCapture(){
  document.querySelectorAll('[data-i18n]').forEach(el => { EN_BASE[el.dataset.i18n] = el.innerHTML; });
  document.querySelectorAll('[data-i18n-ph]').forEach(el => { EN_BASE[el.dataset.i18nPh] = el.placeholder; });
  document.querySelectorAll('[data-i18n-title]').forEach(el => { EN_BASE[el.dataset.i18nTitle] = el.title; });
}
function applyI18n(){
  document.documentElement.lang = LANG;
  document.querySelectorAll('[data-i18n]').forEach(el => { el.innerHTML = t(el.dataset.i18n); });
  document.querySelectorAll('[data-i18n-ph]').forEach(el => { el.placeholder = t(el.dataset.i18nPh); });
  document.querySelectorAll('[data-i18n-title]').forEach(el => { el.title = t(el.dataset.i18nTitle); });
  document.title = t('app.title');
  /* Two nodes are not plain text: the nav is built from NAV, and the note on
     the Features tab exists only in the languages that need it. */
  renderNav();
  const note = $('fea-note');
  if (note) { const s = t('fea.note'); note.innerHTML = s; note.hidden = !s; }
  const pick = $('langpick');
  if (pick) pick.value = LANG;
}
function setLang(v){
  LANG = LANGS.indexOf(v) >= 0 ? v : 'en';
  try { localStorage.setItem(LANG_KEY, LANG); } catch(e){}
  applyI18n();
  /* Everything the island already answered is on the screen in the old
     language. Ask again rather than leave half a page behind. */
  loadStats(); loadChart(); loadDau(); loadActivity(); loadOnline();
  if (LOADERS[cur]) LOADERS[cur]();
  if (cur === 'users' && $('u_q').value.trim()) searchUsers();
}

/* The strings this script builds itself. Everything the markup already carries
   is captured from it (EN_BASE) instead of being written a second time here. */
/* i18n:EN */
const EN = {
  'nav.overview': 'Overview',
  'nav.instruments': 'Instruments',
  'nav.invites': 'Invites',
  'nav.access': 'Access tokens',
  'nav.users': 'Users',
  'nav.reports': 'Reports',
  'nav.news': 'News',
  'nav.sites': 'Sites',
  'nav.relays': 'Relays',
  'nav.features': 'Features',
  'nav.server': 'Server',

  'common.copy': 'Copy',
  'common.copied': 'copied ✓',
  'common.revoke': 'Revoke',
  'common.save': 'Save',
  'common.delete': 'Delete',
  'common.remove': 'Remove',
  'common.unknown': 'unknown',
  'err.create': 'Could not create: {err}',

  'ov.stat.users': 'Users',
  'ov.stat.online': 'Online now',
  'ov.stat.new24': 'New · 24h',
  'ov.stat.new7': 'New · 7d',
  'ov.stat.reports': 'Open reports',
  'ov.err_auth': '{err} — check ADMIN_USERNAME / ADMIN_PASSWORD',
  'ov.activity.empty': 'No moderation actions yet.',
  'ov.th.lastseen': 'Last seen',
  'ov.nobody_online': 'Nobody online right now.',

  'ins.stat.rps': 'Requests / sec',
  'ins.stat.groups': '/groups typical',
  'ins.stat.pool': 'DB pool peak',
  'ins.stat.sockets': 'Sockets opened / h',
  'ins.stat.busiest': 'Busiest account · boot chains/min',
  'ins.bar.title': '{time}: {requests} requests, {errors} 5xx',
  'ins.empty': 'Nothing recorded yet.',
  'ins.slowbodies': '<b>Stalled uploads:</b> {n} request(s) whose client took over 5s to deliver its body (worst {worst}s). Their wait is excluded from the rows above; the server did no work while waiting.',
  'unit.ms': 'ms',

  'inv.shown_once': 'shown once at creation',
  'inv.random': 'random',
  'inv.empty': 'No invites yet.',
  'inv.copy_now': 'Copy this link now, it is shown only once. Send it to the person; they paste the code when signing up.',

  'acc.device': '(device)',
  'acc.revoked': 'revoked',
  'acc.empty': 'No access tokens yet.',
  'acc.copy_now': 'Copy this token now — it is shown only once. Give it to the person (and have them paste it in the app under Add account / Add contact).',

  'usr.nobadge': 'no badge',
  'usr.suspended': 'suspended',
  'usr.st.active': 'active',
  'usr.st.online': 'online',
  'usr.st.offline': 'offline',
  'usr.st.away': 'away',
  'usr.ban': 'Ban',
  'usr.unban': 'Unban',
  'usr.closed': 'closed',
  'usr.group_n': 'Group {id}',
  'usr.empty.none': 'No matches.',
  'usr.groups.none': 'No groups match.',

  'rep.evidence': 'evidence',
  'rep.answered': 'answered',
  'rep.reply': 'Reply',
  'rep.dismiss': 'Dismiss',
  'rep.freeze_site': 'Freeze site',
  'rep.ban': 'Ban',
  'rep.empty': 'No open reports.',
  'rep.ctx.bug': 'Bug report',
  'rep.ctx.contact': 'From a chat',
  'rep.ctx.hood': 'From the Hood',
  'rep.ctx.search': 'From search',
  'rep.ctx.story': 'From a story',
  'rep.ctx.message': 'About a message',
  'rep.ctx.user': 'About a user',
  'rep.ctx.premium': 'Paid content',
  'rep.ctx.random': 'Random chat',
  'rep.ctx.profile': 'From a profile',
  'rep.ctx.chat': 'From a chat',
  'rep.ctx.group': 'In a group',
  'rep.ctx.about_group': 'About a group',
  'rep.ctx.about_site': 'About a site',
  'rep.freeze_confirm': 'Freeze site "{name}"? It stops being served and drops out of the catalogue.',
  'rep.frozen_ok': 'Frozen: {name}',
  'rep.reply_prompt': 'Reply to the reporter. They read this in the app, under "My reports".',
  'rep.reply_empty': 'Empty reply not sent.',
  'rep.ev.gone': 'Evidence is gone (expired or already swept).',
  'rep.ev.popup': 'Popup blocked.',
  'rep.ev.title': 'report {id} evidence',

  'news.empty': 'No announcements yet.',
  'news.need_body': 'Write something first.',
  'news.err_publish': 'Could not publish: {err}',
  'news.del_confirm': 'Delete this announcement?',
  'news.upload_failed': 'upload failed ({status})',

  'sit.summary': '<b>{n}</b> hosted · <b>{listed}</b> in the catalogue · <b>{featured}</b> featured',
  'sit.frozen': 'frozen',
  'sit.in_cat': 'in catalogue',
  'sit.featured': 'featured',
  'sit.byname': 'by name only',
  'sit.view': 'View',
  'sit.list': 'List',
  'sit.unlist': 'Unlist',
  'sit.feature': 'Feature',
  'sit.unfeature': 'Unfeature',
  'sit.freeze': 'Freeze',
  'sit.unfreeze': 'Unfreeze',
  'sit.t.frozen_listed': 'A frozen site is out of the catalogue already',
  'sit.t.needs_listed': 'Only a site in the catalogue can be featured',
  'sit.empty': 'Nobody has published a site here yet.',
  'sit.freeze_confirm': 'Freeze {name}.rcq? Readers get “frozen”, uploads are refused; nothing is deleted.',

  'vw.loading': 'Loading…',
  'vw.loading_page': 'Loading {path}…',
  'vw.frozen': 'Frozen: the island does not serve this site while it is held.',
  'vw.missing': 'The island has no {path} for this site.',
  'vw.unreachable': 'Could not reach the island ({err}).',
  'vw.failed': 'Could not load the site ({err}).',

  'rel.summary': '<b>{live}</b> serving · <b>{dead}</b> not answering',
  'rel.prune': 'Remove dead',
  'rel.serving': 'serving',
  'rel.noanswer': 'no answer',
  'rel.on': 'on',
  'rel.off': 'off',
  'rel.enable': 'Enable',
  'rel.disable': 'Disable',
  'rel.promote': 'Promote',
  'rel.demote': 'Demote',
  'rel.empty': 'No relays registered. Community relays self-register via the bootstrap script.',
  'rel.err_broker': '{err} — the broker may be disabled on this island.',
  'rel.prune_confirm': 'Remove {n} relay(s) that are not answering?',
  'rel.remove_confirm': 'Remove relay {tag}?',
  'rel.pool': 'pool {pool}',
  'rel.tenant': 'tenant',
  'rel.paid_hint': 'Served only to keys of this pool or tenant, never in the public answer',
  'rel.remove_paid_confirm': 'Remove relay {tag}? It serves paying customers ({who}) and they lose this node at once.',

  'fea.note': '',
  'fea.g.features': 'Features',
  'fea.g.limits': 'Limits & policy',
  'fea.g.numbers': 'Selling numbers',
  'fea.g.branding': 'Branding',
  'fea.none': 'No settings.',
  'fea.on': 'On',
  'fea.off': 'Off',
  'fea.ph.none': '(none)',
  'fea.custom': 'custom',
  'fea.badjson': 'This value is not valid JSON, so the fields cannot be shown. Fix or clear it here.',
  'fea.err_save': 'Could not save: {err}',
  'fea.need_number': 'Enter a number.',

  'logo.label': 'Island logo',
  'logo.custom': 'custom',
  'logo.help1': "Your island's picture, shown next to its name wherever a client names it: the account switcher, the confirm before somebody joins, and the island card in Settings. With no logo, every client draws the lettered tile shown here.",
  'logo.help2': '{types} · up to {max} · square works best. Anything larger is resized to {edge}×{edge} in your browser before it is sent (animated GIFs are sent as they are, so they have to be under the limit already).',
  'logo.upload': 'Upload',
  'logo.replace': 'Replace',
  'logo.err_read': 'Could not read that file.',
  'logo.err_gif': 'That GIF is about {size}; the limit is {max}. Animated logos are uploaded as they are (resizing one would leave only its first frame), so it has to be made smaller first.',
  'logo.err_notimage': 'That file is not an image the browser can open.',
  'logo.err_canvas': 'This browser cannot resize the picture.',
  'logo.err_big': 'That picture is still over {max} at 64×64. Try a simpler mark, or one with fewer colours.',
  'logo.err_big_alpha': 'That picture is still over {max} at 64×64, and it has transparency, so it cannot be flattened onto white to shrink it further. Try a simpler mark, or one with fewer colours.',

  'ed.wallets.save': 'Save wallets',
  'ed.wallets.help': 'Leave a chain empty and it is not offered at checkout.',
  'ed.prices.digits': '{n} digits',
  'ed.prices.notsold': 'not sold',
  'ed.prices.save': 'Save prices',
  'ed.prices.help': 'A length you leave blank is one you do not sell. Shorter numbers (six digits and under) are scarce stock: they are only ever handed over against a paid voucher, never given away.',
  'ed.prices.bad': '{n} digits: enter a price like 4.99, or leave it blank.',
  'ed.badges.add': 'Add a kind',
  'ed.badges.save': 'Save badges',
  'ed.badges.help': 'Leave a row blank and the apps use their own translated wording for that mark. The kind is the slug the island stores on an account (a-z, digits, - and _).',
  'ed.badges.ph.kind': 'kind',
  'ed.badges.ph.label': 'name shown to people',
  'ed.badges.ph.desc': 'one sentence: what this mark means',
  'ed.badges.color': 'colour',
  'ed.badges.bad_kind': '"{kind}" is not a kind: a-z, digits, - and _, up to 16 characters.',

  'srv.kv.version': 'Version',
  'srv.kv.name': 'Name',
  'srv.kv.host': 'Host',
  'srv.kv.reg': 'Registration',
  'srv.kv.shop': 'UIN shop',
  'srv.kv.fed': 'Federation',
  'srv.upd.off': 'update check off',
  'srv.upd.avail': '{latest} available',
  'srv.upd.changed': 'what changed',
  'srv.upd.nocheck': 'could not check',
  'srv.upd.nocheck_help': 'this island could not reach the release list; check again later or {link}',
  'srv.upd.look': 'look yourself',
  'srv.upd.uptodate': 'up to date',
  'srv.reg.invite': 'invite-only',
  'srv.reg.invite_help': 'new users need an invite code',
  'srv.reg.open': 'open',
  'srv.reg.open_help': 'anyone can register',
  'srv.shop.on': 'enabled',
  'srv.shop.off': 'off (self-host default)',
  'srv.fed.on': 'on',
  'srv.fed.reach': 'reachable as {addr}',

  'ago.now': 'just now',
  'ago.m': '{n}m',
  'ago.h': '{n}h',
  'ago.d': '{n}d',
  'bytes.kb': '{n} KB',
  'bytes.b': '{n} bytes',

  'upd.bar': '🔔 A new RCQ server release is out: <b>{latest}</b> (you are on {current}). To update: {cmd} (dumps the database first, rebuilds, then health-checks). Daily, on its own: {timer}. {link}',
  'upd.link': 'What changed',
};
/* /i18n:EN */

/* The overlays. English is deliberately EMPTY here: it is the markup plus
   EN above, and a copy of either would be a second place to edit. */
const I18N = {
  en: {},

/* i18n:RU */
  ru: {
  'app.title': 'RCQ: администрирование сервера',
  'shell.foot': 'Свой сервер, всё работает у вас.<br>Никакой зависимости от rcq.app.',
  'shell.menu': '☰ Меню',
  'shell.lang': 'Язык',
  'common.loading': 'Загрузка…',
  'common.create': 'Создать',
  'common.close': 'Закрыть',
  'common.copy': 'Скопировать',
  'common.copied': 'скопировано ✓',
  'common.revoke': 'Отозвать',
  'common.save': 'Сохранить',
  'common.delete': 'Удалить',
  'common.remove': 'Убрать',
  'common.unknown': 'неизвестно',
  'err.create': 'Не удалось создать: {err}',

  'nav.overview': 'Обзор',
  'nav.instruments': 'Приборы',
  'nav.invites': 'Приглашения',
  'nav.access': 'Ключи доступа',
  'nav.users': 'Пользователи',
  'nav.reports': 'Жалобы',
  'nav.news': 'Новости',
  'nav.sites': 'Сайты',
  'nav.relays': 'Релеи',
  'nav.features': 'Настройки',
  'nav.server': 'Сервер',

  'vw.note': 'Запертая рамка, те же правила, что в читалке приложения: ссылки не работают, снаружи ничего не подгружается.',
  'vw.frame_title': 'Сайт на разборе',
  'vw.loading': 'Загрузка…',
  'vw.loading_page': 'Загрузка {path}…',
  'vw.frozen': 'Заморожен: пока сайт на паузе, остров его не отдаёт.',
  'vw.missing': 'У острова нет {path} для этого сайта.',
  'vw.unreachable': 'Не удалось дотянуться до острова ({err}).',
  'vw.failed': 'Не удалось загрузить сайт ({err}).',

  'ov.h1': 'Обзор',
  'ov.sub': 'Ваш сервер коротко.',
  'ov.signups.h': 'Новые люди · 30 дней',
  'ov.signups.sub': 'Регистраций в день.',
  'ov.dau.h': 'Активные · 30 дней',
  'ov.dau.sub': 'Сколько разных людей заходили каждый день.',
  'ov.online.h': 'Сейчас в сети',
  'ov.online.sub': 'Кто подключён к вашему серверу прямо сейчас.',
  'ov.activity.h': 'Последние действия',
  'ov.activity.sub': 'Что делала модерация.',
  'ov.stat.users': 'Пользователи',
  'ov.stat.online': 'Сейчас в сети',
  'ov.stat.new24': 'Новые · 24 ч',
  'ov.stat.new7': 'Новые · 7 дней',
  'ov.stat.reports': 'Открытые жалобы',
  'ov.err_auth': '{err}. Проверьте ADMIN_USERNAME / ADMIN_PASSWORD',
  'ov.activity.empty': 'Модерация пока ничего не делала.',
  'ov.th.lastseen': 'Был в сети',
  'ov.nobody_online': 'Сейчас в сети никого.',

  'ins.h1': 'Приборы',
  'ins.sub': 'Что сервер делает сам с собой за последний час. Счётчики живут внутри процесса: если воркеров несколько, это цифры <b>одного воркера</b>, и они обнуляются при каждом перезапуске. Смотрите на форму, а не на абсолютные числа.',
  'ins.req.h': 'Запросы · за час',
  'ins.req.sub': 'Один столбик это минута. Наведите на столбик, чтобы увидеть число.',
  'ins.time.h': 'Куда уходит время',
  'ins.time.sub': 'Отсортировано по суммарному времени, а не по числу вызовов: чинить стоит тот путь, в котором сервер живёт. «Худший» это самый медленный один вызов, среднее его прячет. Часы считают <b>только работу сервера</b>: время, которое клиент тратит на отправку тела запроса, меряется отдельно, поэтому телефон, умерший посреди загрузки, больше не красит путь красным.',
  'ins.th.path': 'Путь',
  'ins.th.calls': 'Вызовов/мин',
  'ins.th.typical': 'Типично',
  'ins.th.worst': 'Худший',
  'ins.stat.rps': 'Запросов/с',
  'ins.stat.groups': '/groups типично',
  'ins.stat.pool': 'Пик пула БД',
  'ins.stat.sockets': 'Сокетов открыто/ч',
  'ins.stat.busiest': 'Активнее всех · цепочек/мин',
  'ins.bar.title': '{time}: запросов {requests}, 5xx {errors}',
  'ins.empty': 'Пока ничего не записано.',
  'ins.slowbodies': '<b>Застрявшие загрузки:</b> запросов {n}, у которых клиент отдавал тело дольше 5 с (худший {worst} с). Это ожидание не входит в строки выше: сервер в это время не работал.',
  'unit.ms': 'мс',

  'inv.h1': 'Приглашения и номера',
  'inv.sub': 'Коды входа для сервера <b>по приглашениям</b>. Если поставить регистрацию «invite» (вкладка «Настройки»), новым людям придётся ввести один из этих кодов, иначе вкладка не нужна. Ещё здесь можно заранее закрепить за человеком конкретный номер.',
  'inv.ph.label': 'Пометка (например, отдел кадров)',
  'inv.ph.uin': 'Номер, если нужен',
  'inv.title.uses': 'Сколько раз можно использовать',
  'inv.ph.ttl': 'Часы',
  'inv.title.ttl': 'Истекает через N часов',
  'inv.help': '<b>Пометка</b> нужна только вам. <b>Номер</b>: пусто это случайный номер, а можно закрепить за человеком конкретный, красивый. <b>Сколько раз</b>: сколько людей может зарегистрироваться по этому коду (1 для одного человека). <b>Часы</b>: код сам истечёт через N часов (пусто это никогда). Сразу после создания скопируйте код: остров хранит только его отпечаток и второй раз показать не сможет.',
  'inv.th.code': 'Код (отпечаток)',
  'inv.th.uin': 'Номер',
  'inv.th.uses': 'Использован',
  'inv.th.label': 'Пометка',
  'inv.shown_once': 'показан один раз при создании',
  'inv.random': 'случайный',
  'inv.empty': 'Приглашений пока нет.',
  'inv.copy_now': 'Скопируйте ссылку сейчас, она показывается один раз. Отправьте её человеку: он вставит код при регистрации.',

  'acc.h1': 'Ключи доступа',
  'acc.sub': 'Только для <b>закрытого (частного) острова</b>: такого, где Caddyfile маскирует сервер под обычный сайт и не пускает никого без действующего ключа. Здесь вы выдаёте эти ключи, по одному на человека, и любой можно отозвать. <b>Если маскирующий Caddyfile не настроен, вкладка вам не нужна.</b>',
  'acc.ph.label': 'Пометка (например, Алиса)',
  'acc.kind.invite': 'Разовое приглашение',
  'acc.kind.standing': 'Постоянный',
  'acc.ph.max': 'Сколько раз',
  'acc.title.max': 'Постоянный ключ: сколько раз им можно воспользоваться (пусто = без предела)',
  'acc.ph.ttl': 'Срок (дней)',
  'acc.title.ttl': 'Истекает через N дней',
  'acc.help': 'Разовое приглашение забирает первое устройство, которое им воспользуется: пересланный код после этого не работает. Постоянный ключ можно использовать много раз. Целиком ключ показывается ОДИН раз, при создании: тогда и копируйте.',
  'acc.th.label': 'Пометка',
  'acc.th.kind': 'Вид',
  'acc.th.uses': 'Использован',
  'acc.th.last': 'Последний раз',
  'acc.device': '(устройство)',
  'acc.revoked': 'отозван',
  'acc.empty': 'Ключей пока нет.',
  'acc.copy_now': 'Скопируйте ключ сейчас, он показывается один раз. Отдайте его человеку: он вставит ключ в приложении, когда будет добавлять аккаунт или контакт.',

  'usr.h1': 'Пользователи и группы',
  'usr.sub': 'Поиск по номеру, имени или названию группы. Заблокировать нарушителя, выдать знак.',
  'usr.ph.q': 'Номер, имя или название группы',
  'usr.search': 'Найти',
  'usr.hint': 'Знак это ваш остров, который ручается за аккаунт перед всеми, кто на острове есть. Он стоит рядом с именем во всех клиентах. Выдать его снаружи нельзя, и за пределами острова вашему знаку никто не поверит.',
  'usr.th.uin': 'Номер',
  'usr.th.nick': 'Имя',
  'usr.th.status': 'Состояние',
  'usr.th.reports': 'Жалоб',
  'usr.th.badge': 'Знак',
  'usr.empty.start': 'Найдите кого-нибудь, и он появится здесь.',
  'usr.th.group': 'Группа',
  'usr.th.owner': 'Владелец',
  'usr.th.members': 'Участников',
  'usr.groups.start': 'Здесь появятся группы, подходящие под поиск.',
  'usr.nobadge': 'без знака',
  'usr.suspended': 'заблокирован',
  'usr.st.active': 'активен',
  'usr.st.online': 'в сети',
  'usr.st.offline': 'не в сети',
  'usr.st.away': 'отошёл',
  'usr.ban': 'Заблокировать',
  'usr.unban': 'Разблокировать',
  'usr.closed': 'закрытая',
  'usr.group_n': 'Группа {id}',
  'usr.empty.none': 'Никого не нашлось.',
  'usr.groups.none': 'Групп не нашлось.',

  'rep.h1': 'Жалобы',
  'rep.sub': 'Что вам написали люди: жалобы на других и сообщения о поломках самого острова. Ответьте, потом отклоните или заблокируйте. Ответ приходит человеку в приложение, так что писать его стоит даже когда вы отклоняете.',
  'rep.th.target': 'На кого',
  'rep.th.reason': 'Причина',
  'rep.th.context': 'Откуда',
  'rep.evidence': 'доказательство',
  'rep.answered': 'отвечено',
  'rep.reply': 'Ответить',
  'rep.dismiss': 'Отклонить',
  'rep.freeze_site': 'Заморозить сайт',
  'rep.ban': 'Заблокировать',
  'rep.empty': 'Открытых жалоб нет.',
  'rep.ctx.bug': 'Поломка',
  'rep.ctx.contact': 'Из переписки',
  'rep.ctx.hood': 'Из Округи',
  'rep.ctx.search': 'Из поиска',
  'rep.ctx.story': 'Из истории',
  'rep.ctx.message': 'О сообщении',
  'rep.ctx.user': 'О человеке',
  'rep.ctx.premium': 'Платный контент',
  'rep.ctx.random': 'Случайный чат',
  'rep.ctx.profile': 'Из профиля',
  'rep.ctx.chat': 'Из чата',
  'rep.ctx.group': 'В группе',
  'rep.ctx.about_group': 'О группе',
  'rep.ctx.about_site': 'О сайте',
  'rep.freeze_confirm': 'Заморозить сайт «{name}»? Он перестанет открываться и уйдёт из каталога.',
  'rep.frozen_ok': 'Заморожен: {name}',
  'rep.reply_prompt': 'Ответ человеку. Он прочитает его в приложении, в разделе «Мои жалобы».',
  'rep.reply_empty': 'Пустой ответ не отправлен.',
  'rep.ev.gone': 'Доказательства больше нет: истекло или уже вычищено.',
  'rep.ev.popup': 'Браузер заблокировал окно.',
  'rep.ev.title': 'жалоба {id}: доказательство',

  'news.h1': 'Новости',
  'news.sub': 'Объявление в новостную ленту каждому, у кого есть приложение: патч-ноуты, плановые работы, правила.',
  'news.ph.body': 'Текст объявления… (до 4000 знаков)',
  'news.ph.author': 'Автор (пусто = имя острова)',
  'news.title.files': 'Картинки или видео, если нужно',
  'news.publish': 'Опубликовать',
  'news.help': 'Запись появится в новостях у всех и будет подписана автором, которого вы указали, а если поле пустое, именем острова. Вложения по желанию: картинки или видео.',
  'news.th.posted': 'Когда',
  'news.th.body': 'Текст',
  'news.th.media': 'Вложения',
  'news.empty': 'Объявлений пока нет.',
  'news.need_body': 'Сначала напишите текст.',
  'news.err_publish': 'Не удалось опубликовать: {err}',
  'news.del_confirm': 'Удалить это объявление?',
  'news.upload_failed': 'не удалось загрузить ({status})',

  'sit.h1': 'Сайты',
  'sit.sub': 'Страницы <b>.rcq</b>, которые держит этот остров: единственное здешнее содержимое, которое вы действительно можете прочитать, потому что оно публично по определению. <b>Посмотреть</b> открывает сайт прямо здесь, в запертой рамке и через тот же фильтр, что и читалка приложения: ссылки в нём не работают и снаружи ничего не подгружается, поэтому автор сайта, на который пожаловались, не узнает, что его смотрели. <b>В каталог / Из каталога</b> это витрина: сайт из каталога виден на первой странице у каждого браузера на этом острове, сайт без каталога всё равно открывается по точному имени. <b>Наверх</b> закрепляет сайт из каталога над недавними, в отдельном разделе: для этого и нужен <span class="mono">home.rcq</span> самой сети. <b>Заморозка</b> это пауза на время разбора жалобы: на чтение отвечает «заморожен», загрузки не принимаются, ничего не удаляется, и всё обратимо.',
  'sit.th.site': 'Сайт',
  'sit.th.line': 'Строка в каталоге',
  'sit.th.owner': 'Владелец',
  'sit.th.size': 'Размер',
  'sit.th.state': 'Состояние',
  'sit.th.updated': 'Обновлён',
  'sit.summary': '<b>{n}</b> на острове · <b>{listed}</b> в каталоге · <b>{featured}</b> закреплено',
  'sit.frozen': 'заморожен',
  'sit.in_cat': 'в каталоге',
  'sit.featured': 'закреплён',
  'sit.byname': 'только по имени',
  'sit.view': 'Посмотреть',
  'sit.list': 'В каталог',
  'sit.unlist': 'Из каталога',
  'sit.feature': 'Наверх',
  'sit.unfeature': 'Убрать сверху',
  'sit.freeze': 'Заморозить',
  'sit.unfreeze': 'Разморозить',
  'sit.t.frozen_listed': 'Замороженный сайт и так вне каталога',
  'sit.t.needs_listed': 'Закрепить можно только сайт из каталога',
  'sit.empty': 'Здесь ещё никто не опубликовал сайт.',
  'sit.freeze_confirm': 'Заморозить {name}.rcq? Читателям ответят «заморожен», загрузки не примут, ничего не удалится.',

  'rel.h1': 'Релеи',
  'rel.sub': 'Для продвинутых: нужно, только если кто-то держит релеи обхода блокировок для <b>вашего</b> острова. Здесь релеи, зарегистрированные у брокера <b>вашего собственного</b> сервера, и никогда чужого. Большинству операторов вкладка не нужна: она пустая, пока релей не зарегистрируется сам.',
  'rel.help': '<b>Уровень</b>: релеи <span class="mono">community</span> попадают к клиентам только после проверки, что они работают, а релеи <span class="mono">trusted</span> выдаются всегда, ставьте его тем, что держите сами. <b>Повысить / Понизить</b> переводит релей между уровнями. <b>Убрать</b> просто выкидывает его из пула: клиенты уйдут на другие ваши релеи или на прямое соединение, на самой машине релея ничего не удаляется, а если убрать последний, релеи обхода просто перестанут рекламироваться.',
  'rel.th.health': 'Проверка',
  'rel.th.endpoint': 'Адрес',
  'rel.th.tag': 'Метка',
  'rel.th.tier': 'Уровень',
  'rel.th.state': 'Состояние',
  'rel.th.lastok': 'Последний ответ',
  'rel.th.fails': 'Сбоев',
  'rel.summary': '<b>{live}</b> работает · <b>{dead}</b> не отвечает',
  'rel.prune': 'Убрать мёртвые',
  'rel.serving': 'работает',
  'rel.noanswer': 'не отвечает',
  'rel.on': 'вкл',
  'rel.off': 'выкл',
  'rel.enable': 'Включить',
  'rel.disable': 'Выключить',
  'rel.promote': 'Повысить',
  'rel.demote': 'Понизить',
  'rel.empty': 'Релеев нет. Общественные релеи регистрируются сами, через скрипт установки.',
  'rel.err_broker': '{err}. Возможно, брокер на этом острове выключен.',
  'rel.prune_confirm': 'Убрать релеи, которые не отвечают ({n})?',
  'rel.remove_confirm': 'Убрать релей {tag}?',
  'rel.pool': 'пул {pool}',
  'rel.tenant': 'арендатор',
  'rel.paid_hint': 'Выдаётся только ключам этого пула или арендатора, в публичный ответ не попадает',
  'rel.remove_paid_confirm': 'Убрать релей {tag}? Он обслуживает платящих ({who}), и они сразу лишатся этого узла.',

  'fea.h1': 'Настройки',
  'fea.sub': 'Включайте и выключайте необязательные функции, задавайте лимиты и оформление острова. Изменения применяются сразу, перезапуск не нужен.',
  'fea.note': 'Названия настроек переведены. Пояснения под ними приходят от сервера и пока только по-английски: их правят вместе с поведением, и устаревший перевод предупреждения хуже, чем предупреждение по-английски.',
  'fea.g.features': 'Функции',
  'fea.g.limits': 'Лимиты и правила',
  'fea.g.numbers': 'Продажа номеров',
  'fea.g.branding': 'Оформление',
  'fea.none': 'Настроек нет.',
  'fea.on': 'Вкл',
  'fea.off': 'Выкл',
  'fea.ph.none': '(пусто)',
  'fea.custom': 'изменено',
  'fea.badjson': 'Это значение не является корректным JSON, поэтому поля показать нельзя. Исправьте или очистите его здесь.',
  'fea.err_save': 'Не удалось сохранить: {err}',
  'fea.need_number': 'Введите число.',

  'logo.label': 'Логотип острова',
  'logo.custom': 'свой',
  'logo.help1': 'Картинка вашего острова. Она стоит рядом с его именем везде, где клиент называет остров: переключатель аккаунтов, подтверждение перед входом, карточка острова в настройках. Без логотипа все клиенты рисуют плитку с буквой, такую же, как здесь.',
  'logo.help2': '{types} · до {max} · лучше всего квадрат. Всё, что больше, браузер уменьшит до {edge}×{edge} перед отправкой (анимированные GIF уходят как есть, поэтому они должны укладываться в предел сразу).',
  'logo.upload': 'Загрузить',
  'logo.replace': 'Заменить',
  'logo.err_read': 'Не удалось прочитать этот файл.',
  'logo.err_gif': 'Этот GIF весит около {size}, предел {max}. Анимированные логотипы уходят как есть (при уменьшении остался бы только первый кадр), так что сначала сделайте его меньше.',
  'logo.err_notimage': 'Браузер не может открыть этот файл как картинку.',
  'logo.err_canvas': 'Этот браузер не умеет уменьшать картинку.',
  'logo.err_big': 'Картинка всё ещё больше {max} даже в 64×64. Попробуйте знак попроще или с меньшим числом цветов.',
  'logo.err_big_alpha': 'Картинка всё ещё больше {max} даже в 64×64, и в ней есть прозрачность, поэтому положить её на белый фон, чтобы сжать сильнее, нельзя. Попробуйте знак попроще или с меньшим числом цветов.',

  'ed.wallets.save': 'Сохранить кошельки',
  'ed.wallets.help': 'Пустая сеть просто не предлагается при оплате.',
  'ed.prices.digits': '{n} цифр',
  'ed.prices.notsold': 'не продаю',
  'ed.prices.save': 'Сохранить цены',
  'ed.prices.help': 'Пустая длина это длина, которую вы не продаёте. Короткие номера (шесть цифр и меньше) это редкий запас: их отдают только по оплаченному ваучеру и никогда даром.',
  'ed.prices.bad': '{n} цифр: введите цену вида 4.99 или оставьте поле пустым.',
  'ed.badges.add': 'Добавить вид',
  'ed.badges.save': 'Сохранить знаки',
  'ed.badges.help': 'Оставьте строку пустой, и приложения возьмут для этого знака свои переведённые слова. Вид это слаг, который остров хранит у аккаунта (a-z, цифры, дефис и подчёркивание).',
  'ed.badges.ph.kind': 'вид',
  'ed.badges.ph.label': 'как его видят люди',
  'ed.badges.ph.desc': 'что означает этот знак',
  'ed.badges.color': 'цвет',
  'ed.badges.bad_kind': '«{kind}» не годится как вид: a-z, цифры, дефис и подчёркивание, до 16 знаков.',

  'srv.h1': 'Сервер и федерация',
  'srv.sub': 'Как настроен ваш остров и как он включён в общую сеть RCQ.',
  'srv.this.h': 'Этот остров',
  'srv.this.sub': 'Прочитано из вашей рабочей конфигурации.',
  'srv.join.h': 'Вход в общую сеть',
  'srv.join.sub': 'Что делает ваш сервер доступным для людей с других островов.',
  'srv.note1': '<b>Ваш остров уже федеративен.</b> Любой может написать контакту или войти в группу на вашем сервере через <span class="mono">uin@your-host</span> или ссылку на группу <span class="mono">your-host/g/&lt;id&gt;</span>. Никакого центрального реестра тут нет, и быть в каком-либо каталоге для этого не нужно.',
  'srv.note2': '<b>Публичный каталог</b> (список <a href="https://rcq.app/servers" target="_blank">rcq.app/servers</a> и выбор автобэкапа в приложении) нужен <b>только для того, чтобы вас нашли</b>: по нему незнакомые люди находят ваш остров, а приложение может предложить его как место для бэкапа. Попасть в список необязательно, это pull request в репозиторий <span class="mono">rcq-servers</span>, который смотрят мейнтейнеры.',
  'srv.note3': '<b>Чтобы войти в группу на другом острове:</b> откройте в приложении ссылку-приглашение этой группы (в ней должен быть хост, например <span class="mono">rcq.app/g/42@island.example</span>) и подтвердите. Клиент сам зарегистрирует вас там гостем. Если на том острове регистрация <b>по приглашениям</b>, сначала нужен его код.',
  'srv.kv.version': 'Версия',
  'srv.kv.name': 'Имя',
  'srv.kv.host': 'Хост',
  'srv.kv.reg': 'Регистрация',
  'srv.kv.shop': 'Магазин номеров',
  'srv.kv.fed': 'Федерация',
  'srv.upd.off': 'проверка обновлений выключена',
  'srv.upd.avail': 'есть {latest}',
  'srv.upd.changed': 'что изменилось',
  'srv.upd.nocheck': 'не удалось проверить',
  'srv.upd.nocheck_help': 'остров не смог получить список релизов, попробуйте позже или {link}',
  'srv.upd.look': 'посмотрите сами',
  'srv.upd.uptodate': 'актуальная',
  'srv.reg.invite': 'по приглашениям',
  'srv.reg.invite_help': 'новым нужен код приглашения',
  'srv.reg.open': 'открытая',
  'srv.reg.open_help': 'зарегистрироваться может любой',
  'srv.shop.on': 'включён',
  'srv.shop.off': 'выключен (по умолчанию на своём сервере)',
  'srv.fed.on': 'вкл',
  'srv.fed.reach': 'доступен как {addr}',

  'ago.now': 'только что',
  'ago.m': '{n} м',
  'ago.h': '{n} ч',
  'ago.d': '{n} д',
  'bytes.kb': '{n} КБ',
  'bytes.b': '{n} байт',

  'upd.bar': '🔔 Вышел новый релиз сервера RCQ: <b>{latest}</b> (у вас {current}). Обновиться: {cmd} (сначала дамп базы, потом пересборка и проверка здоровья). Каждый день само: {timer}. {link}',
  'upd.link': 'Что изменилось',

  /* Названия настроек с вкладки «Настройки». Пояснения под ними остаются
     английскими: они приходят от сервера, см. комментарий выше. */
  'set.random_enabled': 'Случайный чат',
  'set.reports_enabled': 'Жалобы',
  'set.entry_price_cents': 'Цена входа',
  'set.entry_url': 'Где покупают вход',
  'set.closed_island': 'Закрытый остров',
  'set.federation_refuse_strangers': 'Совсем не принимать чужих',
  'set.reissue_require_proof': 'Смена ключей только с подписью старым ключом',
  'set.registration_policy': 'Регистрация',
  'set.resident_invites_total': 'Сколько приглашений раздаёт резидент',
  'set.resident_invites_period_days': 'Дней между приглашениями',
  'set.resident_invites_ttl_days': 'Сколько дней живёт неиспользованное приглашение',
  'set.free_invites_total': 'Бесплатные приглашения тем, кто был здесь до платного входа',
  'set.free_invites_before': 'Бесплатные приглашения: зарегистрирован до',
  'set.free_invites_min_age_days': 'Бесплатные приглашения: минимальный возраст аккаунта',
  'set.island_host': 'Собственный адрес острова',
  'set.max_accounts_per_device': 'Сколько аккаунтов держит приложение',
  'set.uin_shop_enabled': 'Продавать номера',
  'set.uin_prices': 'Ваши цены',
  'set.uin_till_url': 'Ваша касса',
  'set.uin_resale_enabled': 'Разрешить перепродажу номеров',
  'set.uin_payout_addresses': 'Ваши кошельки',
  'set.uin_voucher_pubkey': 'Открытый ключ вашей кассы',
  'set.badge_labels': 'Названия и описания знаков',
  'set.island_name': 'Имя острова',
  'set.welcome_text': 'Приветствие и правила',
  'set.terms_url': 'Ваша страница условий и возвратов',
  },
/* /i18n:RU */

/* i18n:ZH */
  zh: {
  'app.title': 'RCQ 服务器管理',
  'shell.foot': '自建服务器，完全运行在你自己的机器上。<br>不依赖 rcq.app。',
  'shell.menu': '☰ 菜单',
  'shell.lang': '语言',
  'common.loading': '加载中…',
  'common.create': '创建',
  'common.close': '关闭',
  'common.copy': '复制',
  'common.copied': '已复制 ✓',
  'common.revoke': '吊销',
  'common.save': '保存',
  'common.delete': '删除',
  'common.remove': '移除',
  'common.unknown': '未知',
  'err.create': '创建失败：{err}',

  'nav.overview': '概览',
  'nav.instruments': '仪表',
  'nav.invites': '邀请',
  'nav.access': '访问密钥',
  'nav.users': '用户',
  'nav.reports': '举报',
  'nav.news': '新闻',
  'nav.sites': '站点',
  'nav.relays': '中继',
  'nav.features': '设置',
  'nav.server': '服务器',

  'vw.note': '锁住的框架，规则和应用里的阅读器一样：链接不起作用，不从外部加载任何东西。',
  'vw.frame_title': '正在查看的站点',
  'vw.loading': '加载中…',
  'vw.loading_page': '正在加载 {path}…',
  'vw.frozen': '已冻结：站点被暂停期间，岛屿不会提供它。',
  'vw.missing': '岛屿上没有这个站点的 {path}。',
  'vw.unreachable': '连不到岛屿（{err}）。',
  'vw.failed': '无法加载站点（{err}）。',

  'ov.h1': '概览',
  'ov.sub': '你的服务器一眼看完。',
  'ov.signups.h': '新用户 · 最近 30 天',
  'ov.signups.sub': '每天的注册数。',
  'ov.dau.h': '活跃用户 · 最近 30 天',
  'ov.dau.sub': '每天有多少不同的人在用。',
  'ov.online.h': '当前在线',
  'ov.online.sub': '此刻连着你服务器的人。',
  'ov.activity.h': '最近的操作',
  'ov.activity.sub': '管理做过的事。',
  'ov.stat.users': '用户',
  'ov.stat.online': '当前在线',
  'ov.stat.new24': '新增 · 24 小时',
  'ov.stat.new7': '新增 · 7 天',
  'ov.stat.reports': '待处理举报',
  'ov.err_auth': '{err}。请检查 ADMIN_USERNAME / ADMIN_PASSWORD',
  'ov.activity.empty': '还没有管理操作。',
  'ov.th.lastseen': '最后在线',
  'ov.nobody_online': '现在没有人在线。',

  'ins.h1': '仪表',
  'ins.sub': '过去一小时里服务器对自己做了什么。计数在进程里，所以多 worker 的部署下这是<b>一个 worker</b> 的数字，服务器一重启就归零。看形状，不要看绝对值。',
  'ins.req.h': '请求 · 最近一小时',
  'ins.req.sub': '一根柱子是一分钟。把鼠标放上去看数量。',
  'ins.time.h': '时间花在哪里',
  'ins.time.sub': '按总耗时排序，不按调用次数：值得修的是服务器把时间耗在里面的那个路径。「最差」是最慢的那一次调用，平均值会把它藏起来。计时只算<b>服务器自己的工作</b>：客户端发送请求体的时间单独计量，所以上传到一半断掉的手机，不会再把一个路径染红。',
  'ins.th.path': '路径',
  'ins.th.calls': '次/分',
  'ins.th.typical': '典型',
  'ins.th.worst': '最差',
  'ins.stat.rps': '请求/秒',
  'ins.stat.groups': '/groups 典型',
  'ins.stat.pool': '数据库连接池峰值',
  'ins.stat.sockets': '每小时新开连接',
  'ins.stat.busiest': '最忙的账号 · 启动链/分',
  'ins.bar.title': '{time}：{requests} 个请求，{errors} 个 5xx',
  'ins.empty': '还没有记录。',
  'ins.slowbodies': '<b>卡住的上传：</b>有 {n} 个请求的客户端花了 5 秒以上才把请求体发完（最差 {worst} 秒）。这段等待不计入上面的行：服务器等的时候没有干活。',
  'unit.ms': '毫秒',

  'inv.h1': '邀请与号码',
  'inv.sub': '<b>仅限邀请</b>的服务器用的加入码。如果在「设置」里把注册改成「invite」，新用户必须输入其中一个码才能注册；否则这个标签页可以不用。也可以在这里给某人预留一个指定号码。',
  'inv.ph.label': '备注（例如：人事部）',
  'inv.ph.uin': '号码（可选）',
  'inv.title.uses': '最多可用次数',
  'inv.ph.ttl': '有效小时',
  'inv.title.ttl': 'N 小时后过期',
  'inv.help': '<b>备注</b>只给你自己看。<b>号码</b>：留空就是随机号码，也可以为持有者预留一个指定的靓号。<b>最多可用次数</b>：这个码能让多少人注册（一个人就填 1）。<b>有效小时</b>：N 小时后自动过期（留空就是永不过期）。创建之后马上复制：岛屿只保存它的哈希，没法再给你看第二次。',
  'inv.th.code': '码（哈希）',
  'inv.th.uin': '号码',
  'inv.th.uses': '已用',
  'inv.th.label': '备注',
  'inv.shown_once': '创建时只显示一次',
  'inv.random': '随机',
  'inv.empty': '还没有邀请。',
  'inv.copy_now': '现在就复制这个链接，它只显示一次。把它发给对方，他们注册时粘贴这个码。',

  'acc.h1': '访问密钥',
  'acc.sub': '只用于<b>封闭（私有）岛屿</b>：这种岛屿用伪装的 Caddyfile，让服务器看起来像一个普通网站，并拒绝任何没有有效密钥的人。你在这里发放的就是那种一人一把、随时可以吊销的密钥。<b>如果你没有配置伪装用的 Caddyfile，可以不管这个标签页。</b>',
  'acc.ph.label': '备注（例如：Alice）',
  'acc.kind.invite': '一次性邀请',
  'acc.kind.standing': '长期',
  'acc.ph.max': '次数（留空不限）',
  'acc.title.max': '长期密钥：可以用多少次（留空不限）',
  'acc.ph.ttl': '有效天数',
  'acc.title.ttl': 'N 天后过期',
  'acc.help': '一次性邀请由第一个用它的设备兑换，之后被转发出去的那份就不管用了。长期密钥可以反复使用。完整密钥只在创建时显示一次，那时就复制下来。',
  'acc.th.label': '备注',
  'acc.th.kind': '类型',
  'acc.th.uses': '已用',
  'acc.th.last': '最近使用',
  'acc.device': '（设备）',
  'acc.revoked': '已吊销',
  'acc.empty': '还没有访问密钥。',
  'acc.copy_now': '现在就复制这个密钥，它只显示一次。交给对方，让他们在应用里添加账号或添加联系人时粘贴。',

  'usr.h1': '用户与群组',
  'usr.sub': '按号码、昵称或群组名搜索。封禁滥用者，授予标记。',
  'usr.ph.q': '号码、昵称或群组名',
  'usr.search': '搜索',
  'usr.hint': '标记是你的岛屿在岛上所有人面前为一个账号作保。它显示在每个客户端的名字旁边。岛外没人能授予，岛外也没人会认你的。',
  'usr.th.uin': '号码',
  'usr.th.nick': '昵称',
  'usr.th.status': '状态',
  'usr.th.reports': '举报数',
  'usr.th.badge': '标记',
  'usr.empty.start': '搜索之后，用户会出现在这里。',
  'usr.th.group': '群组',
  'usr.th.owner': '群主',
  'usr.th.members': '成员',
  'usr.groups.start': '符合搜索的群组会出现在这里。',
  'usr.nobadge': '无标记',
  'usr.suspended': '已封禁',
  'usr.st.active': '正常',
  'usr.st.online': '在线',
  'usr.st.offline': '离线',
  'usr.st.away': '离开',
  'usr.ban': '封禁',
  'usr.unban': '解封',
  'usr.closed': '封闭',
  'usr.group_n': '群组 {id}',
  'usr.empty.none': '没有匹配。',
  'usr.groups.none': '没有匹配的群组。',

  'rep.h1': '举报',
  'rep.sub': '用户发给你的东西：对其他成员的举报，以及关于岛屿本身的故障反馈。先回复，再驳回或封禁。你的回复会在应用里送到举报人手上，所以就算要驳回，也值得写一句。',
  'rep.th.target': '对象',
  'rep.th.reason': '原因',
  'rep.th.context': '来源',
  'rep.evidence': '证据',
  'rep.answered': '已回复',
  'rep.reply': '回复',
  'rep.dismiss': '驳回',
  'rep.freeze_site': '冻结站点',
  'rep.ban': '封禁',
  'rep.empty': '没有待处理的举报。',
  'rep.ctx.bug': '故障反馈',
  'rep.ctx.contact': '来自会话',
  'rep.ctx.hood': '来自 Hood',
  'rep.ctx.search': '来自搜索',
  'rep.ctx.story': '来自动态',
  'rep.ctx.message': '关于一条消息',
  'rep.ctx.user': '关于一个人',
  'rep.ctx.premium': '付费内容',
  'rep.ctx.random': '随机聊天',
  'rep.ctx.profile': '来自个人资料',
  'rep.ctx.chat': '来自聊天',
  'rep.ctx.group': '在群组里',
  'rep.ctx.about_group': '关于一个群组',
  'rep.ctx.about_site': '关于一个站点',
  'rep.freeze_confirm': '冻结站点「{name}」？它会停止提供，并从目录里消失。',
  'rep.frozen_ok': '已冻结：{name}',
  'rep.reply_prompt': '回复举报人。他们会在应用的「我的举报」里读到。',
  'rep.reply_empty': '空的回复没有发送。',
  'rep.ev.gone': '证据已经没有了：过期或者已经被清理。',
  'rep.ev.popup': '浏览器拦截了弹出窗口。',
  'rep.ev.title': '举报 {id} 的证据',

  'news.h1': '新闻',
  'news.sub': '给每个人的应用内新闻发一条公告：更新说明、计划维护、规则。',
  'news.ph.body': '写一条公告……（最多 4000 字）',
  'news.ph.author': '作者（留空则用岛屿名称）',
  'news.title.files': '可选的图片或视频附件',
  'news.publish': '发布',
  'news.help': '帖子会出现在每个人的新闻里，署名用你填的作者；这一栏留空就用岛屿的名称。附件可选：图片或视频。',
  'news.th.posted': '时间',
  'news.th.body': '内容',
  'news.th.media': '附件',
  'news.empty': '还没有公告。',
  'news.need_body': '先写点内容。',
  'news.err_publish': '发布失败：{err}',
  'news.del_confirm': '删除这条公告？',
  'news.upload_failed': '上传失败（{status}）',

  'sit.h1': '站点',
  'sit.sub': '这座岛屿托管的 <b>.rcq</b> 页面：这里唯一你真的能读的内容，因为它本来就是公开的。<b>查看</b>就在这里打开站点，用锁住的框架，并经过与应用阅读器相同的清洗：里面的链接不起作用，也不会从外部加载任何东西，所以看一个被投诉的站点，不会让它的作者知道有人看过。<b>加入目录 / 移出目录</b>是橱窗：在目录里的站点会出现在这座岛上每个浏览器的首页，不在目录里的站点仍然可以用准确的名字打开。<b>置顶</b>把目录里的站点钉在最近访问之上的独立区块里，网络自己的 <span class="mono">home.rcq</span> 就是为它准备的。<b>冻结</b>是处理投诉期间的暂停：读取会得到「已冻结」，上传被拒绝，什么都不会删除，而且可以撤销。',
  'sit.th.site': '站点',
  'sit.th.line': '目录里的一行',
  'sit.th.owner': '所有者',
  'sit.th.size': '大小',
  'sit.th.state': '状态',
  'sit.th.updated': '更新时间',
  'sit.summary': '托管 <b>{n}</b> 个 · 目录里 <b>{listed}</b> 个 · 置顶 <b>{featured}</b> 个',
  'sit.frozen': '已冻结',
  'sit.in_cat': '在目录里',
  'sit.featured': '已置顶',
  'sit.byname': '仅按名字',
  'sit.view': '查看',
  'sit.list': '加入目录',
  'sit.unlist': '移出目录',
  'sit.feature': '置顶',
  'sit.unfeature': '取消置顶',
  'sit.freeze': '冻结',
  'sit.unfreeze': '解冻',
  'sit.t.frozen_listed': '冻结的站点本来就不在目录里',
  'sit.t.needs_listed': '只有目录里的站点才能置顶',
  'sit.empty': '还没有人在这里发布站点。',
  'sit.freeze_confirm': '冻结 {name}.rcq？读者会得到「已冻结」，上传会被拒绝，什么都不会删除。',

  'rel.h1': '中继',
  'rel.sub': '进阶功能：只有当有人为<b>你的</b>岛屿运行反封锁中继时才用得上。这里列的是注册在<b>你自己</b>服务器的 broker 上的中继，绝不会是别的岛屿的。大多数运营者可以不管这个标签页：在有中继自己注册之前，它一直是空的。',
  'rel.help': '<b>等级</b>：<span class="mono">community</span> 中继要先通过健康检查、确认可用，才会发给客户端；<span class="mono">trusted</span> 中继总是会被提供，自己运行的中继就用这一级。<b>提升 / 降级</b>在两级之间移动中继。<b>移除</b>只是把它从池子里去掉：客户端会退回到你的其他中继或直连，中继自己那台机器上什么都不会删，移除最后一个也只是不再广告任何反封锁中继。',
  'rel.th.health': '健康',
  'rel.th.endpoint': '地址',
  'rel.th.tag': '标签',
  'rel.th.tier': '等级',
  'rel.th.state': '状态',
  'rel.th.lastok': '最近正常',
  'rel.th.fails': '失败',
  'rel.summary': '<b>{live}</b> 个在服务 · <b>{dead}</b> 个没有应答',
  'rel.prune': '移除失效的',
  'rel.serving': '在服务',
  'rel.noanswer': '没有应答',
  'rel.on': '开',
  'rel.off': '关',
  'rel.enable': '启用',
  'rel.disable': '停用',
  'rel.promote': '提升',
  'rel.demote': '降级',
  'rel.empty': '没有注册的中继。社区中继通过引导脚本自己注册。',
  'rel.err_broker': '{err}。这座岛屿上的 broker 可能是关闭的。',
  'rel.prune_confirm': '移除 {n} 个没有应答的中继？',
  'rel.remove_confirm': '移除中继 {tag}？',
  'rel.pool': '池 {pool}',
  'rel.tenant': '租户',
  'rel.paid_hint': '只提供给该池或租户的密钥，从不出现在公开列表中',
  'rel.remove_paid_confirm': '移除中继 {tag}？它为付费用户服务（{who}），他们会立即失去这个节点。',

  'fea.h1': '设置',
  'fea.sub': '打开或关闭可选功能，设定岛屿的限制和外观。改动立即生效，不用重启。',
  'fea.note': '设置的名称已经翻译。下面的说明来自服务器，目前只有英文：它们随行为一起改动，而一段过时的警告比一段英文的警告更糟。',
  'fea.g.features': '功能',
  'fea.g.limits': '限制与规则',
  'fea.g.numbers': '售卖号码',
  'fea.g.branding': '外观',
  'fea.none': '没有设置。',
  'fea.on': '开',
  'fea.off': '关',
  'fea.ph.none': '（空）',
  'fea.custom': '已修改',
  'fea.badjson': '这个值不是有效的 JSON，所以没法显示字段。在这里把它改好或清空。',
  'fea.err_save': '保存失败：{err}',
  'fea.need_number': '请输入数字。',

  'logo.label': '岛屿标识',
  'logo.custom': '自定义',
  'logo.help1': '你岛屿的图片。凡是客户端写出岛屿名字的地方，它都在名字旁边：账号切换器、加入前的确认、设置里的岛屿卡片。没有标识时，每个客户端都会画这里这种字母方块。',
  'logo.help2': '{types} · 最大 {max} · 方形最合适。更大的图片会先在你的浏览器里缩到 {edge}×{edge} 再发送（动画 GIF 原样发送，所以它本身就得在限制之内）。',
  'logo.upload': '上传',
  'logo.replace': '替换',
  'logo.err_read': '读不出这个文件。',
  'logo.err_gif': '这个 GIF 大约 {size}，上限是 {max}。动画标识按原样上传（缩放只会剩下第一帧），所以要先把它做小。',
  'logo.err_notimage': '浏览器打不开这个文件，它不是图片。',
  'logo.err_canvas': '这个浏览器没法缩放图片。',
  'logo.err_big': '这张图片缩到 64×64 仍然超过 {max}。换一个更简单、颜色更少的标记。',
  'logo.err_big_alpha': '这张图片缩到 64×64 仍然超过 {max}，而且它带透明，没法压在白底上再缩小。换一个更简单、颜色更少的标记。',

  'ed.wallets.save': '保存钱包',
  'ed.wallets.help': '留空的链不会出现在结账页。',
  'ed.prices.digits': '{n} 位',
  'ed.prices.notsold': '不售卖',
  'ed.prices.save': '保存价格',
  'ed.prices.help': '留空的长度就是你不卖的长度。短号码（六位及以下）是稀缺库存：只凭已付款的凭证交付，从不白送。',
  'ed.prices.bad': '{n} 位：填一个像 4.99 这样的价格，或者留空。',
  'ed.badges.add': '添加一种',
  'ed.badges.save': '保存标记',
  'ed.badges.help': '把一行留空，应用就会用它自己翻译好的说法。kind 是岛屿存在账号上的标识串（a-z、数字、- 和 _）。',
  'ed.badges.ph.kind': 'kind',
  'ed.badges.ph.label': '显示给人看的名字',
  'ed.badges.ph.desc': '一句话：这个标记是什么意思',
  'ed.badges.color': '颜色',
  'ed.badges.bad_kind': '「{kind}」不是合法的 kind：a-z、数字、- 和 _，最多 16 个字符。',

  'srv.h1': '服务器与联邦',
  'srv.sub': '你的岛屿是怎么配置的，以及它怎样接入更大的 RCQ 网络。',
  'srv.this.h': '这座岛屿',
  'srv.this.sub': '读自你当前运行的配置。',
  'srv.join.h': '接入公共网络',
  'srv.join.sub': '是什么让其他岛屿上的人能连到你的服务器。',
  'srv.note1': '<b>你的岛屿已经在联邦里了。</b>任何人都可以用 <span class="mono">uin@your-host</span>，或者群组链接 <span class="mono">your-host/g/&lt;id&gt;</span>，联系你服务器上的联系人或加入群组。这里没有任何中心注册表，也不需要出现在任何目录里。',
  'srv.note2': '<b>公共目录</b>（<a href="https://rcq.app/servers" target="_blank">rcq.app/servers</a> 列表，加上应用内的自动备份选择器）<b>只是为了被发现</b>：陌生人可以借它找到你的岛屿，应用也可以把它作为备份的去处推荐。上榜是可选的，做法是给 <span class="mono">rcq-servers</span> 仓库提一个 pull request，由维护者审阅。',
  'srv.note3': '<b>要加入另一座岛屿上的群组：</b>在应用里打开那个群组的邀请链接（链接里必须带主机名，例如 <span class="mono">rcq.app/g/42@island.example</span>）并确认，客户端会自动以访客身份在那里帮你注册。如果目标岛屿的注册是<b>仅限邀请</b>，那你得先拿到它的邀请码。',
  'srv.kv.version': '版本',
  'srv.kv.name': '名称',
  'srv.kv.host': '主机',
  'srv.kv.reg': '注册',
  'srv.kv.shop': '号码商店',
  'srv.kv.fed': '联邦',
  'srv.upd.off': '更新检查已关闭',
  'srv.upd.avail': '有 {latest}',
  'srv.upd.changed': '改了什么',
  'srv.upd.nocheck': '没能检查',
  'srv.upd.nocheck_help': '这座岛屿连不到发布列表，稍后再试，或者{link}',
  'srv.upd.look': '自己去看',
  'srv.upd.uptodate': '已是最新',
  'srv.reg.invite': '仅限邀请',
  'srv.reg.invite_help': '新用户需要邀请码',
  'srv.reg.open': '开放',
  'srv.reg.open_help': '任何人都可以注册',
  'srv.shop.on': '已开启',
  'srv.shop.off': '关闭（自建的默认值）',
  'srv.fed.on': '开',
  'srv.fed.reach': '可以用 {addr} 联系到',

  'ago.now': '刚刚',
  'ago.m': '{n} 分',
  'ago.h': '{n} 小时',
  'ago.d': '{n} 天',
  'bytes.kb': '{n} KB',
  'bytes.b': '{n} 字节',

  'upd.bar': '🔔 RCQ 服务器有新版本：<b>{latest}</b>（你现在是 {current}）。更新：{cmd}（先导出数据库，再重建，然后做健康检查）。每天自动：{timer}。{link}',
  'upd.link': '改了什么',

  /* 「设置」标签页里各项设置的名称。名称下面的说明来自服务器，仍然是英文，
     原因见上面的注释。 */
  'set.random_enabled': '随机聊天',
  'set.reports_enabled': '举报',
  'set.entry_price_cents': '入岛价格',
  'set.entry_url': '在哪里购买入岛',
  'set.closed_island': '封闭岛屿',
  'set.federation_refuse_strangers': '完全拒绝陌生人',
  'set.reissue_require_proof': '更换密钥须由旧密钥签名',
  'set.registration_policy': '注册',
  'set.resident_invites_total': '一个居民能发出的邀请数',
  'set.resident_invites_period_days': '两次邀请之间的天数',
  'set.resident_invites_ttl_days': '未使用的邀请能存活多少天',
  'set.free_invites_total': '给付费入岛之前就在这里的账号的免费邀请',
  'set.free_invites_before': '免费邀请：注册早于',
  'set.free_invites_min_age_days': '免费邀请：账号最小年龄',
  'set.island_host': '这座岛屿自己的地址',
  'set.max_accounts_per_device': '应用会保存多少个账号',
  'set.uin_shop_enabled': '售卖号码',
  'set.uin_prices': '你的价格',
  'set.uin_till_url': '你的收银台',
  'set.uin_resale_enabled': '允许转卖号码',
  'set.uin_payout_addresses': '你的钱包',
  'set.uin_voucher_pubkey': '你收银台的公钥',
  'set.badge_labels': '标记的名称和说明',
  'set.island_name': '岛屿名称',
  'set.welcome_text': '欢迎语和规则',
  'set.terms_url': '你的条款与退款页面',
  },
/* /i18n:ZH */
};

/* ---- brand logo + favicon (real RCQ mark, base64-inlined) ---- */
const LOGO = 'data:image/png;base64,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';
$('flower').innerHTML = '<img src="'+LOGO+'" alt="" width="28" height="28" style="border-radius:7px;display:block">';
(function(){ const l=document.createElement('link'); l.rel='icon'; l.type='image/png'; l.href=LOGO; document.head.appendChild(l); })();

/* ---- nav ---- */
/* ⚠ The second column is a string ID, not a label. The rail is rebuilt whenever
   the language changes (renderNav, from applyI18n), and a label written in here
   would survive the switch. */
const NAV = [
  ['overview','nav.overview','M3 12l9-8 9 8M5 10v9h5v-5h4v5h5v-9'],
  ['instruments','nav.instruments','M4 18a8 8 0 1116 0M12 18l4-6'],
  ['invites','nav.invites','M4 7h16v10H4zM4 7l8 6 8-6'],
  ['access','nav.access','M6 10V7a6 6 0 1112 0v3M5 10h14v10H5zM12 14v3'],
  ['users','nav.users','M8 11a3 3 0 100-6 3 3 0 000 6zM2 20c0-3 3-5 6-5s6 2 6 5M16 7a3 3 0 110 6'],
  ['reports','nav.reports','M12 3l9 16H3zM12 10v4M12 17v.5','reports-badge'],
  ['news','nav.news','M4 6h16v12H4zM4 6l8 6 8-6'],
  ['sites','nav.sites','M4 5h16v14H4zM4 9h16M8 9v10'],
  ['relays','nav.relays','M12 20v-7M8.5 13a5 5 0 017 0M6 10.5a9 9 0 0112 0'],
  ['features','nav.features','M4 6h16M4 12h16M4 18h16M8 6v0M16 12v0M10 18v0'],
  ['server','nav.server','M4 5h16v5H4zM4 14h16v5H4zM7 7.5h.5M7 16.5h.5'],
];
/* The loader each tab needs, in one place: go() uses it to open a tab and
   setLang() uses it to ask the island again in the new language. */
const LOADERS = { instruments:loadInstruments, invites:loadInvites, access:loadAccess,
  reports:loadReports, news:loadNews, sites:loadSites, relays:loadRelays,
  features:loadFeatures, server:loadServer };
let cur = 'overview';
/* The open-reports count is kept here because renderNav throws the badge away
   with the rest of the rail, and a language switch must not cost a /stats call
   just to paint the number back. */
let openReports = 0;
function reportsBadge(){
  const b = $('reports-badge'); if (!b) return;
  b.textContent = openReports ? num(openReports) : '';
  b.classList.toggle('on', openReports > 0);
}
function renderNav(){
  $('nav').innerHTML = NAV.map(n => `<div class="navlink${n[0]===cur?' active':''}" data-v="${n[0]}" onclick="go('${n[0]}')">
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="${n[2]}"/></svg>
  <span>${t(n[1])}</span>${n[3]?`<span class="badge" id="${n[3]}"></span>`:''}</div>`).join('');
  reportsBadge();
}
function go(v) {
  cur = v;
  document.querySelectorAll('.navlink').forEach(e => e.classList.toggle('active', e.dataset.v===v));
  document.querySelectorAll('.view').forEach(e => e.classList.toggle('active', e.id==='v-'+v));
  closeSide();
  if (LOADERS[v]) LOADERS[v]();
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
      ['ov.stat.users', s.total_users], ['ov.stat.online', online],
      ['ov.stat.new24', s.new_users_24h], ['ov.stat.new7', s.new_users_7d],
      ['ov.stat.reports', s.open_reports, s.open_reports>0],
    ];
    $('stats').innerHTML = cells.map(c => `<div class="stat${c[2]?' warn':''}"><div class="n">${typeof c[1]==='number'?num(c[1]):c[1]}</div><div class="l">${t(c[0])}</div></div>`).join('');
    openReports = s.open_reports||0; reportsBadge();
  } catch (e) { $('stats').innerHTML = '<span class="err">'+t('ov.err_auth',{err:e.message})+'</span>'; }
}
async function loadChart() {
  try {
    const ts = await api('GET','/timeseries/signups?days=30');
    const pts = ts.points||[]; const max = Math.max(1, ...pts.map(p=>p.count));
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
      ['ins.stat.rps', last ? (last.requests/60).toFixed(1) : '—'],
      ['ins.stat.groups', groups ? groups.mean_ms+' '+t('unit.ms') : '—', groups && groups.mean_ms>1000],
      ['ins.stat.pool', ceiling ? peak+' / '+ceiling : String(peak), atCeiling>0 && errs>0],
      ['ins.stat.sockets', num(churn)],
      // Value and label this way round on purpose: "9 boot chains/min" as the
      // big number wrapped onto three lines and stopped reading as a number.
      ['ins.stat.busiest', num(busiest), busiest>20],
    ];
    $('inst-stats').innerHTML = cells.map(c=>`<div class="stat${c[2]?' warn':''}"><div class="n">${c[1]}</div><div class="l">${t(c[0])}</div></div>`).join('');

    const max = Math.max(1, ...series.map(s=>s.requests||0));
    $('inst-chart').innerHTML = series.map(s=>{
      const d = new Date(s.minute*60000);
      const hhmm = String(d.getHours()).padStart(2,'0')+':'+String(d.getMinutes()).padStart(2,'0');
      return `<div class="bar" style="height:${Math.round((s.requests||0)/max*100)}%" title="${escAttr(t('ins.bar.title',{time:hhmm, requests:s.requests||0, errors:s.errors||0}))}"></div>`;
    }).join('');
    if (series.length) {
      const fmt = mn => { const d=new Date(mn*60000); return String(d.getHours()).padStart(2,'0')+':'+String(d.getMinutes()).padStart(2,'0'); };
      $('inst-chart-x').innerHTML = `<span>${fmt(series[0].minute)}</span><span>${fmt(series[series.length-1].minute)}</span>`;
    }

    const sb = m.slow_bodies || 0;
    const sbEl = $('inst-slowbodies');
    if (sb > 0) {
      sbEl.style.display = '';
      sbEl.innerHTML = t('ins.slowbodies', {n:sb, worst:Math.round((m.slow_body_worst_ms||0)/1000)});
    } else { sbEl.style.display = 'none'; }
    const rows = m.paths || [];
    $('inst-paths').innerHTML = rows.length ? rows.map(p=>`<tr>
      <td class="mono">${p.path}</td>
      <td style="text-align:right">${p.per_min}</td>
      <td style="text-align:right">${p.mean_ms} ${t('unit.ms')}</td>
      <td style="text-align:right${p.worst_ms>2000?';color:var(--amber)':''}">${p.worst_ms} ${t('unit.ms')}</td>
      <td style="text-align:right${p.errors?';color:var(--red)':''}">${p.errors}</td></tr>`).join('')
      : `<tr><td colspan="5" class="empty">${t('ins.empty')}</td></tr>`;
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
      : '<div class="empty">'+t('ov.activity.empty')+'</div>';
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
      <td><span class="mono">${v.code.slice(0,10)}…</span> <span style="color:var(--dim)">${t('inv.shown_once')}</span></td>
      <td>${v.uin?'<span class="pill vanity">'+v.uin+'</span>':'<span style="color:var(--dim)">'+t('inv.random')+'</span>'}</td>
      <td>${v.used_count}/${v.max_uses}</td>
      <td>${v.label||''}</td>
      <td style="text-align:right"><button class="btn danger sm" onclick="revoke('${v.code}')">${t('common.revoke')}</button></td>
    </tr>`).join('') || `<tr><td colspan="5" class="empty">${t('inv.empty')}</td></tr>`;
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
    /* ⚠ The link is put in the field and the copy handler is BOUND, not written
       into an onclick string. It carried the url through two layers of quoting
       already, and a translated word inside the same handler would be a third. */
    n.innerHTML='<p class="sub">'+t('inv.copy_now')+'</p>'+
      '<div class="row"><input class="mono" readonly value="'+escAttr(out.join_url)+'" style="flex:1" onclick="this.select()">'+
      '<button class="btn ghost" id="i_copy">'+t('common.copy')+'</button></div>';
    $('i_copy').onclick = function(){ navigator.clipboard.writeText(out.join_url); this.textContent=t('common.copied'); };
    loadInvites();
  }
  catch(e){ $('i_err').textContent=t('err.create',{err:e.message}); }
}
async function revoke(code){ try{ await api('DELETE','/invites/'+encodeURIComponent(code)); loadInvites(); }catch(e){ alert(e.message); } }

/* ---- access tokens (closed island) ---- */
/* The wire value is `invite` or `standing`. The words are the ones on the picker
   above the table, so a row and the picker cannot say different things; anything
   else the island grows is shown as it arrives. */
function kindLabel(k){ return k==='invite' ? t('acc.kind.invite') : k==='standing' ? t('acc.kind.standing') : String(k||''); }
async function loadAccess() {
  try {
    const rows = await api('GET','/access-tokens');
    $('access').innerHTML = rows.map(x=>`<tr>
      <td>${x.label||'<span style="color:var(--dim)">—</span>'}${x.parent_id?' <span style="color:var(--dim)">'+t('acc.device')+'</span>':''}</td>
      <td>${escAttr(kindLabel(x.kind))}</td>
      <td>${x.uses}${x.max_uses?('/'+x.max_uses):''}</td>
      <td style="color:var(--dim)">${x.last_used_at?timeago(x.last_used_at):'—'}</td>
      <td style="text-align:right">${x.revoked?'<span style="color:var(--dim)">'+t('acc.revoked')+'</span>':'<button class="btn danger sm" onclick="revokeAccess('+x.id+')">'+t('common.revoke')+'</button>'}</td>
    </tr>`).join('') || `<tr><td colspan="5" class="empty">${t('acc.empty')}</td></tr>`;
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
    n.innerHTML='<p class="sub">'+t('acc.copy_now')+'</p>'+
      '<div class="row"><input class="mono" readonly value="'+escAttr(out.token)+'" style="flex:1" onclick="this.select()">'+
      '<button class="btn ghost" id="a_copy">'+t('common.copy')+'</button></div>';
    $('a_copy').onclick = function(){ navigator.clipboard.writeText(out.token); this.textContent=t('common.copied'); };
    loadAccess();
  } catch(e){ $('a_err').textContent=t('err.create',{err:e.message}); }
}
async function revokeAccess(id){ try{ await api('POST','/access-tokens/'+id+'/revoke'); loadAccess(); }catch(e){ alert(e.message); } }

/* ---- users ---- */
/* The states an account is shown in. The wire value is the fallback, so a state
   the island grows appears as itself rather than as nothing. */
const STATUS_IDS = {active:'usr.st.active', online:'usr.st.online', offline:'usr.st.offline', away:'usr.st.away'};
function statusLabel(s){
  const id = STATUS_IDS[String(s||'')];
  return id ? t(id) : String(s||'');
}
/* The kinds THIS island knows. Asked once; an island that has none falls back
   to the three the server ships with, so the picker is never empty. */
let BADGE_KINDS = null;
async function badgeKinds() {
  if (BADGE_KINDS) return BADGE_KINDS;
  try { const r = await api('GET','/badges'); BADGE_KINDS = (r&&r.kinds&&r.kinds.length)?r.kinds:['official','tester','special']; }
  catch(e){ BADGE_KINDS = ['official','tester','special']; }
  return BADGE_KINDS;
}
function badgePicker(kinds, current, onchange) {
  const opts = ['<option value="">'+t('usr.nobadge')+'</option>'].concat(
    kinds.map(k=>`<option value="${escAttr(k)}"${k===current?' selected':''}>${escAttr(k)}</option>`)
  );
  /* An island may carry a kind the console does not list (set by hand, or
     added after this page was written). Keep it selectable rather than
     silently rewriting it to nothing on the next change. */
  if (current && kinds.indexOf(current) < 0) opts.push(`<option value="${escAttr(current)}" selected>${escAttr(current)}</option>`);
  return `<select style="width:130px" onchange="${onchange}">${opts.join('')}</select>`;
}
async function searchUsers() {
  const q=$('u_q').value.trim(); if(!q) return;
  const kinds = await badgeKinds();
  try {
    const r = await api('GET','/users?q='+encodeURIComponent(q));
    $('users').innerHTML = (r.items||[]).map(u=>`<tr>
      <td class="mono">${u.uin}</td><td>${escAttr(u.nickname||'')}</td>
      <td>${u.is_suspended?'<span class="pill red">'+t('usr.suspended')+'</span>':'<span style="color:var(--mut)">'+escAttr(statusLabel(u.status||'active'))+'</span>'}</td>
      <td>${num(u.reports_against)}</td>
      <td>${badgePicker(kinds, u.badge||'', 'setUserBadge('+u.uin+', this.value, this)')}</td>
      <td style="text-align:right"><button class="btn ${u.is_suspended?'ghost':'danger'} sm" onclick="ban(${u.uin},${!u.is_suspended})">${u.is_suspended?t('usr.unban'):t('usr.ban')}</button></td>
    </tr>`).join('') || `<tr><td colspan="6" class="empty">${t('usr.empty.none')}</td></tr>`;
  } catch(e){ $('users').innerHTML='<tr><td colspan="6" class="err">'+e.message+'</td></tr>'; }
  /* Groups are searched with the same words. A closed group still shows: the
     operator has to be able to reach one to badge or inspect it. */
  try {
    const g = await api('GET','/groups?q='+encodeURIComponent(q));
    $('ugroups').innerHTML = (g.items||[]).map(x=>`<tr>
      <td>${escAttr(x.name||t('usr.group_n',{id:x.id}))}${x.is_closed?' <span class="pill">'+t('usr.closed')+'</span>':''}<div class="mono" style="color:var(--dim);font-size:11px">id ${x.id}</div></td>
      <td class="mono">${x.owner_uin}${x.owner_nickname?' <span style="color:var(--mut)">'+escAttr(x.owner_nickname)+'</span>':''}</td>
      <td>${num(x.member_count)}</td>
      <td>${badgePicker(kinds, x.badge||'', 'setGroupBadge('+x.id+', this.value, this)')}</td>
    </tr>`).join('') || `<tr><td colspan="4" class="empty">${t('usr.groups.none')}</td></tr>`;
  } catch(e){ $('ugroups').innerHTML='<tr><td colspan="4" class="err">'+e.message+'</td></tr>'; }
}
/* The select is the source of truth while the request is in flight: disable it
   so a second change cannot race the first, and put the old value back if the
   island refuses. No full re-search, which would throw away the operator's
   place in a long list. */
async function setBadgeOn(path, value, el) {
  const before = el.getAttribute('data-was') || '';
  el.disabled = true;
  try { await api('POST', path, {badge: value || null}); el.setAttribute('data-was', value); }
  catch(e){ el.value = before; alert(e.message); }
  finally { el.disabled = false; }
}
function setUserBadge(uin, value, el){ return setBadgeOn('/users/'+uin+'/badge', value, el); }
function setGroupBadge(id, value, el){ return setBadgeOn('/groups/'+id+'/badge', value, el); }
async function ban(uin,suspended){ try{ await api('POST','/users/'+uin+'/ban',{suspended}); searchUsers(); }catch(e){ alert(e.message); } }

/* ---- reports (user + bug reports; auto crash dumps are a maintainer concern) ---- */
async function loadReports() {
  try {
    const r = await api('GET','/reports?status=open&kind=user');
    $('reports').innerHTML = (r.items||[]).map(rp=>`<tr>
      <td>${rp.id}</td>
      <td class="mono">${rp.target_uin?rp.target_uin:'—'}${rp.target_nickname?' <span style="color:var(--dim)">('+esc(rp.target_nickname)+')</span>':''}${siteOf(rp)?' <span style="color:var(--dim)">'+esc(siteOf(rp))+'</span>':''}</td>
      <td style="white-space:normal;overflow-wrap:anywhere">${esc(rp.reason||'')}${rp.has_evidence?' <span class="pill" style="cursor:pointer" onclick="viewEvidence('+rp.id+')">'+t('rep.evidence')+'</span>':''}${rp.replied_at?' <span class="pill" title="'+esc(rp.reply_text||'')+'">'+t('rep.answered')+'</span>':''}</td><td><span class="pill">${esc(contextLabel(rp.context))}</span></td>
      <td class="acts"><button class="btn ghost sm" onclick="reply(${rp.id})">${t('rep.reply')}</button> <button class="btn ghost sm" onclick="resolve(${rp.id},false)">${t('rep.dismiss')}</button> ${siteOf(rp)?'<button class="btn danger sm" onclick="freezeReportedSite('+rp.id+', \\''+esc(siteOf(rp))+'\\')">'+t('rep.freeze_site')+'</button> ':''}${isAbuse(rp)?'<button class="btn danger sm" onclick="resolve('+rp.id+',true)">'+t('rep.ban')+'</button>':''}</td>
    </tr>`).join('') || `<tr><td colspan="5" class="empty">${t('rep.empty')}</td></tr>`;
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
const CONTEXT_LABELS = Object.assign(Object.create(null), {bug_bounty:'rep.ctx.bug', contact:'rep.ctx.contact', hood:'rep.ctx.hood', search:'rep.ctx.search', story:'rep.ctx.story', message:'rep.ctx.message', user:'rep.ctx.user', premium_media:'rep.ctx.premium', random:'rep.ctx.random', stranger_mode:'rep.ctx.random', profile:'rep.ctx.profile', chat:'rep.ctx.chat', group:'rep.ctx.group'});
function contextLabel(c){
  if(!c) return '—';
  if (CONTEXT_LABELS[c]) return t(CONTEXT_LABELS[c]);
  if (c.startsWith('group:')) return t('rep.ctx.about_group');
  if (c.startsWith('site:')) return t('rep.ctx.about_site');
  if (c.startsWith('message:')) return t('rep.ctx.message');
  return c;
}
/* A report about a site names it as `site:<name>@<host>`; the name is what
   the freeze endpoint takes. A site on another island is not ours to freeze,
   so only a bare name or our own host qualifies. */
function siteOf(rp){
  const c = rp.context || '';
  if (!c.startsWith('site:')) return '';
  const ref = c.slice(5); const at = ref.indexOf('@');
  if (at < 0) return ref;
  const host = ref.slice(at+1);
  return (MOCK ? host === 'island.example' : host === location.host) ? ref.slice(0, at) : '';
}
/* Freezing stops the site being served and delists it; the report stays open
   so the operator still answers the person who wrote in. */
async function freezeReportedSite(id, name){
  if(!confirm(t('rep.freeze_confirm',{name:name}))) return;
  try { await api('POST','/sites/'+encodeURIComponent(name)+'/freeze?frozen=true'); alert(t('rep.frozen_ok',{name:name})); }
  catch(e){ alert(e.message); }
}
function esc(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;'); }
/* Answer the reporter. The text is stored on the report and the reporter reads
   it back over their own authenticated session; the push we send is only a
   doorbell and carries none of it. Replying does NOT resolve the report — you
   can answer first and decide the verdict after. */
async function reply(id){
  const text = prompt(t('rep.reply_prompt'));
  if(text===null) return;
  if(!text.trim()){ alert(t('rep.reply_empty')); return; }
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
    if(!res.ok){ alert(res.status===404?t('rep.ev.gone'):'HTTP '+res.status); return; }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const w = window.open('', '_blank');
    if(!w){ URL.revokeObjectURL(url); alert(t('rep.ev.popup')); return; }
    const tag = blob.type.startsWith('video/') ? 'video controls autoplay' : 'img';
    w.document.write('<title>'+escAttr(t('rep.ev.title',{id:id}))+'</title><body style="margin:0;background:#111;display:flex;align-items:center;justify-content:center;height:100vh"><'+tag+' src="'+url+'" style="max-width:100%;max-height:100%"></body>');
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
        ver = `<span class="mono">${u.current}</span> &nbsp;<span style="color:var(--mut)">${t('srv.upd.off')}</span>`;
      } else if (u && u.update_available) {
        ver = `<span class="mono">${u.current}</span> &nbsp;<span class="pill">${t('srv.upd.avail',{latest:escAttr(u.latest)})}</span>`
            + ` &nbsp;<a href="${escAttr(u.repo_url)}" target="_blank" rel="noopener" style="color:var(--acc)">${t('srv.upd.changed')}</a>`;
      } else if (u && u.reachable === false) {
        const look = `<a href="${escAttr(u.repo_url)}" target="_blank" rel="noopener" style="color:var(--acc)">${t('srv.upd.look')}</a>`;
        ver = `<span class="mono">${u.current}</span> &nbsp;<span class="pill">${t('srv.upd.nocheck')}</span>`
            + ` &nbsp;<span style="color:var(--mut)">${t('srv.upd.nocheck_help',{link:look})}</span>`;
      } else if (u) {
        ver = `<span class="mono">${u.current}</span> &nbsp;<span class="pill green">${t('srv.upd.uptodate')}</span>`;
      }
    } catch(e) { ver = `<span style="color:var(--dim)">${t('common.unknown')}</span>`; }
    const host = MOCK ? 'island.example' : location.host;
    $('srv-kv').innerHTML = `
      <dt>${t('srv.kv.version')}</dt><dd>${ver}</dd>
      <dt>${t('srv.kv.name')}</dt><dd>${info.name||'—'}</dd>
      <dt>${t('srv.kv.host')}</dt><dd class="mono">${host}</dd>
      <dt>${t('srv.kv.reg')}</dt><dd>${reg==='invite'?'<span class="pill">'+t('srv.reg.invite')+'</span> &nbsp;<span style="color:var(--mut)">'+t('srv.reg.invite_help')+'</span>':'<span class="pill green">'+t('srv.reg.open')+'</span> &nbsp;<span style="color:var(--mut)">'+t('srv.reg.open_help')+'</span>'}</dd>
      <dt>${t('srv.kv.shop')}</dt><dd>${info.capabilities.uin_shop?t('srv.shop.on'):'<span style="color:var(--dim)">'+t('srv.shop.off')+'</span>'}</dd>
      <dt>${t('srv.kv.fed')}</dt><dd><span class="pill green">${t('srv.fed.on')}</span> &nbsp;<span style="color:var(--mut)">${t('srv.fed.reach',{addr:'<span class="mono">number@'+host+'</span>'})}</span></dd>`;
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
  if(s<0) return t('ago.now');
  if(s<60)return t('ago.now'); if(s<3600)return t('ago.m',{n:Math.floor(s/60)}); if(s<86400)return t('ago.h',{n:Math.floor(s/3600)}); return t('ago.d',{n:Math.floor(s/86400)});
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
    const ts = await api('GET','/timeseries/dau?days=30');
    const pts = ts.points||[]; const max = Math.max(1, ...pts.map(p=>p.count));
    $('chart-dau').innerHTML = pts.map(p=>`<div class="bar" style="height:${Math.round(p.count/max*100)}%" title="${p.date}: ${p.count}"></div>`).join('');
    if (pts.length) $('chart-dau-x').innerHTML = `<span>${pts[0].date.slice(5)}</span><span>${pts[pts.length-1].date.slice(5)}</span>`;
  } catch(e){ $('chart-dau').innerHTML=''; }
}
async function loadOnline() {
  try {
    const rows = await api('GET','/presence/online');
    $('online').innerHTML = (rows&&rows.length)
      ? '<table><thead><tr><th>'+t('usr.th.uin')+'</th><th>'+t('usr.th.nick')+'</th><th>'+t('usr.th.status')+'</th><th>'+t('ov.th.lastseen')+'</th></tr></thead><tbody>'+rows.map(u=>`<tr>
          <td class="mono">${u.uin}</td><td>${escAttr(u.nickname||'')}</td><td>${escAttr(statusLabel(u.status||''))}</td>
          <td class="mono" style="color:var(--dim)">${u.last_seen?timeago(u.last_seen):'—'}</td></tr>`).join('')+'</tbody></table>'
      : '<div class="empty">'+t('ov.nobody_online')+'</div>';
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
      <td style="text-align:right"><button class="btn danger sm" onclick="deleteNews(${p.id})">${t('common.delete')}</button></td>
    </tr>`).join('') : `<tr><td colspan="4" class="empty">${t('news.empty')}</td></tr>`;
  } catch(e){ $('news').innerHTML='<tr><td colspan="4" class="err">'+e.message+'</td></tr>'; }
}
async function uploadNewsMedia(file) {
  if (MOCK) return {media_id:'mock-'+Math.random().toString(36).slice(2,10), mime:file.type||'image/png', kind:'image'};
  const fd = new FormData(); fd.append('blob', file);
  const r = await fetch('/admin/news/upload', {method:'POST', body:fd, credentials:'same-origin'});
  if (!r.ok) throw new Error(t('news.upload_failed',{status:r.status}));
  return r.json();
}
async function publishNews() {
  $('n_err').textContent='';
  const body = $('n_body').value.trim();
  if (!body) { $('n_err').textContent=t('news.need_body'); return; }
  try {
    const atts = []; const files = $('n_files').files||[];
    for (let i=0;i<files.length;i++){ const u = await uploadNewsMedia(files[i]); atts.push({media_id:u.media_id, mime:u.mime}); }
    const payload = { body, attachments: atts };
    if ($('n_author').value.trim()) payload.author_label=$('n_author').value.trim();
    await api('POST','/news',payload);
    $('n_body').value=''; $('n_author').value=''; $('n_files').value='';
    loadNews();
  } catch(e){ $('n_err').textContent=t('news.err_publish',{err:e.message}); }
}
async function deleteNews(id){ if(!confirm(t('news.del_confirm')))return; try{ await api('DELETE','/news/'+id); loadNews(); }catch(e){ alert(e.message); } }

/* ---- sites (.rcq bundles; the only bytes on the island an operator can read) ---- */
async function loadSites() {
  try {
    const rows = (await api('GET','/sites'))||[];
    const listed = rows.filter(s=>s.listed&&!s.frozen).length;
    const featured = rows.filter(s=>s.featured).length;
    $('sites-summary').innerHTML = rows.length
      ? t('sit.summary',{n:num(rows.length), listed:num(listed), featured:num(featured)}) : '';
    $('sites').innerHTML = rows.length ? rows.map(s=>{
      const n = escAttr(s.name);
      const state = s.frozen ? '<span class="pill red">'+t('sit.frozen')+'</span>'
        : s.listed ? '<span class="pill green">'+t('sit.in_cat')+'</span>'+(s.featured?' <span class="pill vanity">'+t('sit.featured')+'</span>':'')
        : '<span class="pill">'+t('sit.byname')+'</span>';
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
      <td class="acts">
        <button class="btn ghost sm" onclick="openViewer('${n}')">${t('sit.view')}</button>
        <button class="btn ghost sm" ${s.frozen?'disabled title="'+escAttr(t('sit.t.frozen_listed'))+'"':''} onclick="siteListed('${n}',${!s.listed})">${s.listed?t('sit.unlist'):t('sit.list')}</button>
        <button class="btn ghost sm" ${canFeature?'':'disabled title="'+escAttr(t('sit.t.needs_listed'))+'"'} onclick="siteFeatured('${n}',${!s.featured})">${s.featured?t('sit.unfeature'):t('sit.feature')}</button>
        <button class="btn danger sm" onclick="siteFrozen('${n}',${!s.frozen})">${s.frozen?t('sit.unfreeze'):t('sit.freeze')}</button>
      </td></tr>`;}).join('') : `<tr><td colspan="7" class="empty">${t('sit.empty')}</td></tr>`;
  } catch(e){ $('sites').innerHTML='<tr><td colspan="7" class="err">'+e.message+'</td></tr>'; }
}
async function siteListed(name, on){ try{ await api('POST','/sites/'+encodeURIComponent(name)+'/listed?listed='+on); loadSites(); }catch(e){ alert(e.message); } }
async function siteFeatured(name, on){ try{ await api('POST','/sites/'+encodeURIComponent(name)+'/featured',{featured:on}); loadSites(); }catch(e){ alert(e.message); } }
async function siteFrozen(name, on){ if(on&&!confirm(t('sit.freeze_confirm',{name:name})))return; try{ await api('POST','/sites/'+encodeURIComponent(name)+'/freeze?frozen='+on); loadSites(); }catch(e){ alert(e.message); } }

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
  viewerSay(t('vw.loading_page',{path:path}));
  try { $('v_frame').srcdoc = await siteRender(name, viewerManifest, path); }
  catch(e){ viewerSay(e.message==='frozen' ? t('vw.frozen') : e.message==='missing' ? t('vw.missing',{path:path}) : t('vw.unreachable',{err:e.message})); }
}
async function openViewer(name) {
  $('v_addr').textContent = name+'.rcq';
  $('v_pages').innerHTML = '';
  $('viewer').classList.add('on');
  viewerSay(t('vw.loading'));
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
  } catch(e){ viewerSay(e.message==='frozen' ? t('vw.frozen') : t('vw.failed',{err:e.message})); }
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
      ? t('rel.summary',{live:num(live), dead:num(dead)})+(dead?' · <button class="btn ghost sm" onclick="pruneDeadRelays()">'+t('rel.prune')+'</button>':'')
      : '';
    $('relays').innerHTML = rows.length ? rows.map(x=>{
      const alive = relayLive(x.last_ok);
      const d = x.descriptor||{};
      const ep = d.server ? (d.server+':'+(d.port||'')) : '—';
      return `<tr>
      <td>${alive?'<span class="pill green">'+t('rel.serving')+'</span>':'<span class="pill red">'+t('rel.noanswer')+'</span>'}</td>
      <td class="mono" style="color:var(--dim)">${escAttr(ep)}</td>
      <td class="mono">${escAttr(x.tag)}</td>
      <td>${x.pool_id?'<span class="pill" title="'+escAttr(t('rel.paid_hint'))+'">'+escAttr(t('rel.pool',{pool:x.pool_id}))+'</span>':(x.tenant_id?'<span class="pill" title="'+escAttr(t('rel.paid_hint'))+'">'+t('rel.tenant')+'</span>':'<span class="pill '+(x.tier==='trusted'?'green':'')+'">'+x.tier+'</span>')}</td>
      <td>${x.enabled?'<span class="pill green">'+t('rel.on')+'</span>':'<span class="pill red">'+t('rel.off')+'</span>'}</td>
      <td class="mono" style="color:var(--dim)">${timeago(x.last_ok)}</td>
      <td>${x.fail_count||0}</td>
      <td class="acts">
        <button class="btn ghost sm" onclick="setRelay('${escAttr(x.tag)}',{enabled:${!x.enabled}})">${x.enabled?t('rel.disable'):t('rel.enable')}</button>
        ${(x.pool_id||x.tenant_id)?'':`<button class="btn ghost sm" onclick="setRelay('${escAttr(x.tag)}',{tier:'${x.tier==='trusted'?'community':'trusted'}'})">${x.tier==='trusted'?t('rel.demote'):t('rel.promote')}</button>`}
        <button class="btn danger sm" onclick="removeRelay('${escAttr(x.tag)}','${escAttr(x.pool_id?t('rel.pool',{pool:x.pool_id}):(x.tenant_id?t('rel.tenant'):''))}')">${t('common.remove')}</button>
      </td></tr>`;}).join('') : `<tr><td colspan="8" class="empty">${t('rel.empty')}</td></tr>`;
  } catch(e){ $('relays').innerHTML='<tr><td colspan="8" class="err">'+t('rel.err_broker',{err:e.message})+'</td></tr>'; }
}
/* Dead rows never disappear on their own: a relay that moves to a new IP
   registers a NEW tag and the old one stays forever. Seventeen of them had
   piled up by August, all last seen in June, and every one of them still ate a
   canary probe every ten minutes. */
async function pruneDeadRelays(){
  const r = await rawApi('GET','/broker/admin/list');
  const dead = ((r&&r.relays)||[]).filter(x=>!relayLive(x.last_ok));
  if(!dead.length) return;
  if(!confirm(t('rel.prune_confirm',{n:dead.length}))) return;
  for(const x of dead){ try{ await rawApi('DELETE','/broker/admin/'+encodeURIComponent(x.tag)); }catch(e){} }
  loadRelays();
}
async function setRelay(tag, patch){ try{ await rawApi('POST','/broker/admin/set', Object.assign({tag}, patch)); loadRelays(); }catch(e){ alert(e.message); } }
async function removeRelay(tag, who){ if(!confirm(who?t('rel.remove_paid_confirm',{tag:tag,who:who}):t('rel.remove_confirm',{tag:tag})))return; try{ await rawApi('DELETE','/broker/admin/'+encodeURIComponent(tag)); loadRelays(); }catch(e){ alert(e.message); } }

/* ---- features (operator toggles) ---- */
const FGROUPS = { features:'fea.g.features', limits:'fea.g.limits', numbers:'fea.g.numbers', branding:'fea.g.branding' };
/* The label of a setting is translated by its KEY; the help paragraph under it
   is the island's own English and stays that way (see the dictionaries). A key
   this console has never heard of keeps the island's label, which is how an
   older console stays usable against a newer island. */
function settingLabel(s){ return tOpt('set.'+s.key) || s.label || s.key; }
/* ⚠⚠ Preferred order, not the whole list: a group the server grew and this page
   had not heard of used to vanish, leaving settings that existed in the API and
   were editable by nobody. Anything unknown renders after these under its own
   raw name, which is ugly enough to notice and better than absent. */
function fgroupOrder(groups){
  const known = Object.keys(FGROUPS).filter(g=>groups[g]);
  const rest = Object.keys(groups).filter(g=>!(g in FGROUPS)).sort();
  return known.concat(rest);
}
function escAttr(s){ return String(s==null?'':s).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;'); }
async function loadFeatures(){
  try { const r = await api('GET','/settings'); renderFeatures((r&&r.settings)||[]); }
  catch(e){ $('features').innerHTML='<div class="card pad"><span class="err">'+t('ov.err_auth',{err:e.message})+'</span></div>'; }
}
function renderFeatures(list){
  const groups = {}; list.forEach(s=>{ (groups[s.group]=groups[s.group]||[]).push(s); });
  ISLAND_NAME = (list.find(s=>s.key==='island_name')||{}).value || '';
  $('features').innerHTML = fgroupOrder(groups).map(g=>`
    <div class="card pad"><div class="ftitle">${FGROUPS[g] ? t(FGROUPS[g]) : escAttr(g)}</div>
      ${g==='branding'?'<div id="logorow"></div>':''}
      ${groups[g].map((s,i)=>frow(s,i===0&&g!=='branding')).join('')}</div>`).join('')
    || '<div class="card pad"><div class="empty">'+t('fea.none')+'</div></div>';
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

function fmtBytes(n){ return n>=1024 ? t('bytes.kb',{n:num(Math.round(n/1024))}) : t('bytes.b',{n:num(n)}); }

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
    +   '<div class="flabel">'+t('logo.label')+(st.has_logo?' <span class="pill green">'+t('logo.custom')+'</span>':'')+'</div>'
    +   '<div class="fhelp">'+t('logo.help1')+'</div>'
    // ⚠ The rules, BEFORE the picker. Nobody should learn a limit by having a
    // file refused after they chose it.
    +   '<div class="fhelp">'+t('logo.help2',{types:types, max:fmtBytes(st.max_bytes), edge:LOGO_EDGE})+'</div>'
    +   (err?'<div class="fhelp err">'+escAttr(err)+'</div>':'')
    + '</div><div class="fctl">'
    +   shot
    +   '<input type="file" id="logofile" accept="'+escAttr(st.mimes.join(','))+'" style="display:none">'
    +   '<button class="btn sm" id="logopick">'+(st.has_logo?t('logo.replace'):t('logo.upload'))+'</button>'
    +   (st.has_logo?'<button class="btn sm ghost" id="logodrop">'+t('common.remove')+'</button>':'')
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
    r.onerror = () => reject(new Error(t('logo.err_read')));
    r.onload = () => {
      const raw = String(r.result);
      if (file.type === 'image/gif') {
        if (raw.length*0.75 > maxBytes) return reject(new Error(t('logo.err_gif',
          {size:fmtBytes(Math.round(raw.length*0.75)), max:fmtBytes(maxBytes)})));
        return resolve(raw);
      }
      const img = new Image();
      img.onerror = () => reject(new Error(t('logo.err_notimage')));
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
          if (!ctx) return reject(new Error(t('logo.err_canvas')));
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
        reject(new Error(t(transparent ? 'logo.err_big_alpha' : 'logo.err_big', {max:fmtBytes(maxBytes)})));
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
/* ⚠⚠ THREE SETTINGS ARE JSON, AND AN OPERATOR SHOULD NEVER TYPE JSON.
 *
 * `uin_payout_addresses`, `uin_prices` and `badge_labels` are stored as JSON
 * strings because that is what the island parses, and until now this console
 * put that string in a 220px text box and left the operator to get the braces
 * right. Somebody naming a badge had to write
 * {"official":{"label":"...","description":"...","color":"#3B9EE8"}} in one
 * line, and somebody entering a wallet had to know the chain ids. One typo and
 * the island logs a parse error and quietly keeps the old value.
 *
 * The wire format does not change: these editors build the same JSON and PATCH
 * the same key. What changes is that a person sees fields.
 *
 * The `editor` hint comes from the island (server_settings.describe). A console
 * that does not know a hint falls through to the text box, which is what keeps
 * an older console usable against a newer island. */

/* ⚠ The chains a wallet can be pasted for, and the ids MUST be the ones the
 * till knows (`console-worker/payments.js`): the map saved here is handed to it
 * verbatim as `addresses[chain]`, so a key it does not recognise is a wallet
 * that is never offered and never explains why.
 *
 * Polygon is one row for three tokens on purpose. USDT and both USDCs are
 * different contracts at the SAME address of yours — an EVM wallet does not
 * have a per-token address — so asking for three would be asking for the same
 * string three times. */
const CHAINS = [
  ['tron', 'USDT (TRC-20)', 'T…'],
  ['ton', 'TON', 'UQ…'],
  ['btc', 'Bitcoin', 'bc1…'],
  ['polygon', 'USDT / USDC (Polygon)', '0x…'],
];
/* Nine down to four. Three-digit numbers are never sold (uin_shop.py), so the
 * row is not offered rather than offered and refused. */
/* ⚠ Three is in the list. The island has always priced three-digit numbers
 * (the built-in ladder puts them at $999) and the shop has always been willing
 * to sell one through the voucher door, but this editor did not offer the row,
 * so an operator could neither see the price nor change it and the help text
 * underneath claimed they were never sold (founder, 07.09). */
const PRICE_LENGTHS = [9, 8, 7, 6, 5, 4, 3];
/* ⚠ 'resident' is in the seed because the island grants it ITSELF the moment
   somebody's entry voucher verifies (routers/auth.py). It was the one kind
   an operator was never offered a row for, so nobody ever named or
   coloured the only mark their island hands out on its own. */
const BADGE_SEED = ['official', 'tester', 'special', 'resident'];
/* The colour each client already draws a known kind in, so a row an operator
   has not touched shows the mark as people actually see it instead of the same
   blue for all four. Mirrors BadgeMark on iOS, badgeTintOf on Android and
   COLOUR in the web client; anything else keeps the neutral blue. */
const BADGE_DEFAULT_COLOR = {
  official: '#3b9ee8',
  tester: '#e0a21b',
  special: '#e05068',
  resident: '#f97316',
};

function parseJSONSetting(v){
  if (!v) return {};
  try { const o = JSON.parse(v); return (o && typeof o === 'object') ? o : {}; }
  catch(e){ return null; }   /* null = unparseable; we say so instead of eating it */
}

function walletsEditor(s){
  const cur = parseJSONSetting(s.value);
  if (cur === null) return null;
  const rows = CHAINS.map(([id, label, hint]) => `
    <div class="erow">
      <label for="w_${id}">${label}</label>
      <input id="w_${id}" value="${escAttr(cur[id]||'')}" placeholder="${hint}" spellcheck="false">
    </div>`).join('');
  return `<div class="editor">${rows}
    <button class="btn sm" onclick="saveWallets()">${t('ed.wallets.save')}</button>
    <div class="ehelp">${t('ed.wallets.help')}</div></div>`;
}
function saveWallets(){
  const out = {};
  for (const [id] of CHAINS){
    const v = ($('w_'+id).value||'').trim();
    if (v) out[id] = v;
  }
  setFeature('uin_payout_addresses', Object.keys(out).length ? JSON.stringify(out) : '');
}

function pricesEditor(s){
  const cur = parseJSONSetting(s.value);
  if (cur === null) return null;
  const rows = PRICE_LENGTHS.map((n) => `
    <div class="erow">
      <label for="p_${n}">${t('ed.prices.digits',{n:n})}</label>
      <input id="p_${n}" type="number" min="0" step="0.01" style="width:110px"
             value="${cur[n]!=null ? (Number(cur[n])/100) : ''}" placeholder="${escAttr(t('ed.prices.notsold'))}">
      <span class="ehint">USD</span>
    </div>`).join('');
  return `<div class="editor">${rows}
    <button class="btn sm" onclick="savePrices()">${t('ed.prices.save')}</button>
    <div class="ehelp">${t('ed.prices.help')}</div></div>`;
}
function savePrices(){
  const out = {};
  for (const n of PRICE_LENGTHS){
    const raw = ($('p_'+n).value||'').trim();
    if (raw === '') continue;
    const cents = Math.round(parseFloat(raw) * 100);
    if (!isFinite(cents) || cents < 0) { alert(t('ed.prices.bad',{n:n})); return; }
    out[n] = cents;
  }
  setFeature('uin_prices', Object.keys(out).length ? JSON.stringify(out) : '');
}

function badgesEditor(s){
  const cur = parseJSONSetting(s.value);
  if (cur === null) return null;
  /* The kinds this island already names, plus the three the clients know, plus
   * a blank row so a new kind can be minted without leaving the page. */
  const kinds = Array.from(new Set([...Object.keys(cur), ...BADGE_SEED]));
  const rows = kinds.map((k, i) => badgeRow(k, cur[k]||{}, i)).join('');
  return `<div class="editor" id="badge-rows">${rows}
    <button class="btn sm ghost" onclick="addBadgeRow()">${t('ed.badges.add')}</button>
    <button class="btn sm" onclick="saveBadges()">${t('ed.badges.save')}</button>
    <div class="ehelp">${t('ed.badges.help')}</div></div>`;
}
function badgeRow(kind, v, i){
  return `<div class="brow" data-i="${i}">
    <input class="bkind" value="${escAttr(kind)}" placeholder="${escAttr(t('ed.badges.ph.kind'))}" style="width:110px" spellcheck="false">
    <input class="blabel" value="${escAttr(v.label||'')}" placeholder="${escAttr(t('ed.badges.ph.label'))}" style="width:160px">
    <input class="bcolor" type="color" value="${/^#[0-9a-fA-F]{6}$/.test(v.color||'') ? v.color : (BADGE_DEFAULT_COLOR[kind] || '#3b9ee8')}" title="${escAttr(t('ed.badges.color'))}">
    <input class="bdesc" value="${escAttr(v.description||'')}" placeholder="${escAttr(t('ed.badges.ph.desc'))}" style="flex:1;min-width:220px">
  </div>`;
}
let badgeSeq = 900;
function addBadgeRow(){
  const host = $('badge-rows');
  const btn = host.querySelector('button');
  btn.insertAdjacentHTML('beforebegin', badgeRow('', {}, badgeSeq++));
}
function saveBadges(){
  const out = {};
  for (const row of document.querySelectorAll('#badge-rows .brow')){
    const kind = (row.querySelector('.bkind').value||'').trim().toLowerCase();
    if (!kind) continue;
    if (!/^[a-z0-9_-]{1,16}$/.test(kind)) { alert(t('ed.badges.bad_kind',{kind:kind})); return; }
    const label = (row.querySelector('.blabel').value||'').trim();
    const description = (row.querySelector('.bdesc').value||'').trim();
    const color = (row.querySelector('.bcolor').value||'').trim();
    /* A row with nothing in it is a kind the operator has not renamed: leave it
     * out entirely so the apps fall back to their own translated wording,
     * rather than writing empty strings that mean the same thing but look set. */
    if (!label && !description) continue;
    const e = {};
    if (label) e.label = label;
    if (description) e.description = description;
    if (color) e.color = color;
    out[kind] = e;
  }
  setFeature('badge_labels', Object.keys(out).length ? JSON.stringify(out) : '');
}

function frow(s, first){
  let ctl;
  if (s.editor) {
    const built = s.editor==='wallets' ? walletsEditor(s)
                : s.editor==='prices'  ? pricesEditor(s)
                : s.editor==='badges'  ? badgesEditor(s) : null;
    /* ⚠ Unparseable existing value: do NOT draw the fields over it. The editor
     * would save whatever the empty fields hold and silently discard what is
     * there. Fall back to the raw box and say why. */
    ctl = built !== null && built !== undefined
      ? built
      : `<div><div class="ehelp" style="color:var(--err)">${t('fea.badjson')}</div>
         <input id="f_${s.key}" value="${escAttr(s.value)}" style="width:220px">
         <button class="btn sm" onclick="setFeature('${s.key}', $('f_${s.key}').value)">${t('common.save')}</button></div>`;
  }
  else if (s.type==='bool')
    ctl = `<button class="btn sm ${s.value?'':'ghost'}" onclick="setFeature('${s.key}', ${!s.value})">${s.value?t('fea.on'):t('fea.off')}</button>`;
  else if (s.type==='int')
    ctl = `<input type="number" id="f_${s.key}" value="${s.value}"${s.min!=null?' min='+s.min:''}${s.max!=null?' max='+s.max:''} style="width:88px"><button class="btn sm" onclick="setFeature('${s.key}', parseInt($('f_${s.key}').value,10))">${t('common.save')}</button>`;
  else if (s.choices)
    ctl = `<select onchange="setFeature('${s.key}', this.value)">${s.choices.map(c=>`<option value="${c}"${c===s.value?' selected':''}>${c}</option>`).join('')}</select>`;
  else
    ctl = `<input id="f_${s.key}" value="${escAttr(s.value)}" placeholder="${escAttr(t('fea.ph.none'))}" style="width:220px"><button class="btn sm" onclick="setFeature('${s.key}', $('f_${s.key}').value)">${t('common.save')}</button>`;
  const badge = s.overridden ? ' <span class="pill green">'+t('fea.custom')+'</span>' : '';
  return `<div class="frow${first?' first':''}"><div class="finfo"><div class="flabel">${escAttr(settingLabel(s))}${badge}</div><div class="fhelp">${s.help||''}</div></div><div class="fctl">${ctl}</div></div>`;
}
async function setFeature(key, value){
  if (typeof value==='number' && isNaN(value)) { alert(t('fea.need_number')); return; }
  try { const r = await api('PATCH','/settings', {[key]: value}); renderFeatures((r&&r.settings)||[]); }
  catch(e){ alert(t('fea.err_save',{err:e.message})); loadFeatures(); }
}

let MOCK_SETTINGS = [
  {key:'random_enabled',type:'bool',group:'features',label:'Random Chat',help:'Anonymous roulette-style chat.',value:true,default:true,overridden:false,min:null,max:null,choices:null},
  {key:'registration_policy',type:'str',group:'limits',label:'Registration',help:'Who may create an account on this island.',value:'open',default:'open',overridden:false,min:null,max:null,choices:['open','invite','paid']},
  {key:'max_accounts_per_device',type:'int',group:'limits',label:'Max accounts / device',help:'How many accounts one device may hold.',value:5,default:5,overridden:false,min:1,max:50,choices:null},
  {key:'island_name',type:'str',group:'branding',label:'Island name',help:'Display name clients read from /server/info.',value:'Example Island',default:'RCQ Backend',overridden:true,min:null,max:null,choices:null},
  {key:'welcome_text',type:'str',group:'branding',label:'Welcome / rules',help:'Optional welcome or rules text shown in the app.',value:'',default:'',overridden:false,min:null,max:null,choices:null},
  {key:'badge_labels',type:'str',group:'branding',label:'Badge names and descriptions',help:'What your island calls its badges. Leave a row blank and the apps use their own translated wording.',value:'{"official":{"label":"Official","description":"Confirmed by this island.","color":"#3b9ee8"},"resident":{"label":"Resident","description":"Holds residency on this island.","color":"#f97316"}}',default:'',overridden:true,min:null,max:null,choices:null,editor:'badges'},
  {key:'uin_payout_addresses',type:'str',group:'numbers',label:'Your wallets',help:'Where buyers pay YOU for numbers this island sells and for entry to it.',value:'{"tron":"TYj5rJMVSJ5LATG9kPgemEiaDH9ft1FqY5","polygon":"0x0000000000000000000000000000000000000000"}',default:'',overridden:true,min:null,max:null,choices:null,editor:'wallets'},
  {key:'uin_prices',type:'str',group:'numbers',label:'Your prices',help:'What YOU charge for a number, by how many digits it has.',value:'{"6":1499,"7":499}',default:'',overridden:true,min:null,max:null,choices:null,editor:'prices'},
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
  if (path==='/badges') return {kinds:['official','tester','special']};
  if (path.indexOf('/badge')>0 && method==='POST') return {ok:true};
  if (path.startsWith('/users?q=')) return {items:[
    {uin:100200300, nickname:'ann', is_suspended:false, badge:'official', status:'active', reports_against:0},
    {uin:100200301, nickname:'bo', is_suspended:false, badge:null, status:'active', reports_against:2}]};
  if (path.startsWith('/groups?q=')) return {items:[
    {id:21, name:'Island Beta', owner_uin:100200300, owner_nickname:'ann', member_count:2210, is_closed:false, badge:'official'},
    {id:44, name:'Bug reports', owner_uin:100200301, owner_nickname:'bo', member_count:38, is_closed:true, badge:null}]};
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
    // ⚠ In the language the operator chose, and English until they choose one.
    // This bar was once the single Russian sentence in an English page: a
    // self-hoster who does not read Russian got a red bar of characters they
    // could not parse, at the top of the screen, on the day a fix they needed
    // shipped. The operators of this island are not necessarily us, which is
    // why English is the default here and everywhere else on the page.
    // ⚠ The two commands are NOT translated. They are typed into a shell.
    const cmd = (c) => '<code style="background:rgba(0,0,0,.25);padding:1px 5px;border-radius:4px">'+c+'</code>';
    bar.innerHTML = t('upd.bar', {
      latest: escAttr(u.latest),
      current: escAttr(u.current),
      cmd: cmd('sudo bash deploy/rcq-update.sh'),
      timer: cmd('sudo bash deploy/rcq-update.sh --install-timer'),
      link: '<a href="'+escAttr(u.repo_url)+'" target="_blank" rel="noopener" style="color:#fff;text-decoration:underline">'+t('upd.link')+'</a>',
    });
    bar.style.display='block';
    document.body.style.paddingTop='46px';
  } catch(e) {}
}

/* ---- boot ---- */
/* English off the markup FIRST, so t() has a fallback before anything asks it
   for a string, then the chosen language over the top of it. */
i18nCapture();
applyI18n();
loadStats(); loadChart(); loadDau(); loadActivity(); loadOnline(); checkUpdate();
</script>
</body>
</html>"""
