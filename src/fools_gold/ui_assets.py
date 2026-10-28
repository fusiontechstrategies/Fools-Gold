"""Presentation assets for the local operations console.

Tailored CSS and a bundled prospector mascot: no CDN, hosted fonts, scripts
from other origins, analytics or build pipeline.
"""

import hashlib

# Python >=3.12 is the package's declared minimum; files() is supported there.
# nosemgrep: python.lang.compatibility.python37.python37-compatibility-importlib2
from importlib.resources import files

MASCOT_BYTES = files("fools_gold").joinpath("assets", "prospector.png").read_bytes()
MASCOT_ETAG = '"' + hashlib.sha256(MASCOT_BYTES).hexdigest() + '"'
MASCOT_PATH = "/assets/prospector-" + MASCOT_ETAG[1:13] + ".png"
MARK = (
    f"<img class='mark' src='{MASCOT_PATH}' width='56' height='56' "
    "alt='' aria-hidden='true'>"
)

STYLES = """
:root {
  --ink: #1c1f24;
  --ink-2: #3d434c;
  --muted: #6b717b;
  --paper: #f6f3ec;
  --surface: #ffffff;
  --line: #e2ddd2;
  --line-strong: #d2ccbf;
  --rail: #23262b;
  --rail-ink: #b9bec7;
  --rail-muted: #858b95;
  --gold: #c59a3f;
  --gold-ink: #7d5d17;
  --gold-soft: #f6ecd2;
  --bad: #9c2f2a;
  --bad-bg: #fbeceb;
  --warn: #7c5a13;
  --warn-bg: #faf0da;
  --ok: #22604a;
  --ok-bg: #e8f3ed;
  --info: #2c4f7c;
  --info-bg: #eaf0f8;
  --radius: 10px;
  --shadow: 0 1px 2px rgba(28, 31, 36, 0.06);
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
  --sans: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
}

* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0;
  background: var(--paper);
  color: var(--ink);
  font: 400 15px/1.55 var(--sans);
}
h1, h2, h3 { margin: 0; font-weight: 600; letter-spacing: -0.01em; }
h1 { font-size: 25px; line-height: 1.25; }
h2 { font-size: 16px; }
h3 { font-size: 14px; }
p { margin: 0; }
a { color: var(--info); text-decoration-thickness: 1px; text-underline-offset: 2px; }
a:hover { color: #1d3a5f; }
code, .mono { font-family: var(--mono); font-size: 0.86em; }
small, .small { font-size: 12.5px; }
.muted { color: var(--muted); }
.nowrap { white-space: nowrap; }
.truncate { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

.skip-link {
  position: absolute; left: -999px; top: 8px; z-index: 10;
  background: var(--surface); padding: 8px 12px; border-radius: 6px;
}
.skip-link:focus { left: 8px; }

:focus-visible {
  outline: 2px solid var(--gold);
  outline-offset: 2px;
  border-radius: 4px;
}

/* Application shell */
.shell { display: grid; grid-template-columns: 234px minmax(0, 1fr); min-height: 100vh; }
.rail {
  background: var(--rail);
  color: var(--rail-ink);
  padding: 22px 18px 18px;
  position: sticky; top: 0; align-self: start;
  height: 100vh;
  display: flex; flex-direction: column; gap: 26px;
}
.brand { display: flex; align-items: center; gap: 11px; color: #f4e6c6; text-decoration: none; }
.brand:hover { color: #fff3d8; }
.brand .mark { flex: none; width: 72px; height: 72px; object-fit: contain; }
.brand-text { display: flex; flex-direction: column; line-height: 1.2; }
.brand-name { font-weight: 600; letter-spacing: 0.01em; color: #f3f1ec; font-size: 16px; }
.brand-tag { font-size: 11.5px; color: var(--rail-muted); letter-spacing: 0.04em; }
.nav { display: flex; flex-direction: column; gap: 2px; }
.nav-link {
  display: flex; align-items: center; gap: 10px;
  color: var(--rail-ink); text-decoration: none;
  padding: 9px 10px; border-radius: 7px; font-size: 14px;
  border-left: 2px solid transparent;
}
.nav-link:hover { background: rgba(255, 255, 255, 0.05); color: #f1f2f4; }
.nav-link[aria-current="page"] {
  background: rgba(197, 154, 63, 0.12);
  border-left-color: var(--gold);
  color: #f6eddb;
}
.nav-glyph {
  width: 6px; height: 6px; border-radius: 1px;
  background: currentColor; opacity: 0.35; flex: none;
}
.nav-link[aria-current="page"] .nav-glyph { background: var(--gold); opacity: 1; }
.rail-foot { margin-top: auto; border-top: 1px solid rgba(255,255,255,0.08); padding-top: 14px; }
.rail-foot p { color: var(--rail-muted); font-size: 11.5px; line-height: 1.5; }
.rail-foot a { color: var(--rail-ink); }

.main { min-width: 0; display: flex; flex-direction: column; }
.topbar {
  display: flex; align-items: flex-end; justify-content: space-between; gap: 24px;
  padding: 28px 36px 18px;
  border-bottom: 1px solid var(--line);
}
.topbar .purpose { color: var(--muted); font-size: 13.5px; margin-top: 6px; max-width: 70ch; }
.topbar-meta { display: flex; align-items: center; gap: 14px; font-size: 12.5px; color: var(--muted); }
.content { padding: 26px 36px 56px; max-width: 1180px; width: 100%; }

/* Cards and grids */
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(196px, 1fr)); gap: 14px; }
.metrics { grid-template-columns: repeat(6, minmax(0, 1fr)); }
.metrics .card { min-width: 0; padding: 16px 14px; }
.card {
  background: var(--surface); border: 1px solid var(--line);
  border-radius: var(--radius); padding: 18px; box-shadow: var(--shadow);
}
.card-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; margin-bottom: 12px; }
.card-label { font-size: 11px; letter-spacing: 0.09em; text-transform: uppercase; color: var(--muted); font-weight: 600; }
.card-value { font-size: 27px; font-weight: 600; line-height: 1.15; margin-top: 4px; }
.card-scope { font-size: 12.5px; color: var(--muted); margin-top: 6px; }
.card-link { margin-top: 12px; font-size: 13px; }
.metric-bad .card-value { color: var(--bad); }
.metric-warn .card-value { color: var(--warn); }
.metric-ok .card-value { color: var(--ok); }

.section { margin-top: 30px; }
.section-head { display: flex; align-items: baseline; justify-content: space-between; gap: 16px; margin-bottom: 12px; }
.section-head p { color: var(--muted); font-size: 13px; }
.panel { background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius); box-shadow: var(--shadow); }
.panel-pad { padding: 18px; }
.split { display: grid; grid-template-columns: minmax(0, 1.55fr) minmax(0, 1fr); gap: 18px; align-items: start; }
.stack { display: flex; flex-direction: column; gap: 12px; }

/* Badges */
.badge {
  display: inline-flex; align-items: center; gap: 6px;
  font-size: 11.5px; font-weight: 600; letter-spacing: 0.02em;
  padding: 3px 8px; border-radius: 999px; border: 1px solid transparent;
  white-space: nowrap;
}
.badge .dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
.badge-neutral { background: #f1efe9; color: var(--ink-2); border-color: var(--line); }
.badge-ok { background: var(--ok-bg); color: var(--ok); border-color: #cfe4d9; }
.badge-warn { background: var(--warn-bg); color: var(--warn); border-color: #eeddb6; }
.badge-bad { background: var(--bad-bg); color: var(--bad); border-color: #f0cdca; }
.badge-info { background: var(--info-bg); color: var(--info); border-color: #cfdcec; }

/* Buttons */
.btn {
  display: inline-flex; align-items: center; justify-content: center; gap: 8px;
  background: var(--ink); color: #fdfaf3; text-decoration: none;
  border: 1px solid var(--ink); border-radius: 7px;
  font: 600 13.5px/1 var(--sans); padding: 9px 14px; cursor: pointer;
}
.btn:hover { background: #2c3036; color: #fff; }
.btn-secondary {
  background: var(--surface); color: var(--ink);
  border-color: var(--line-strong);
}
.btn-secondary:hover { background: #f3f0e9; color: var(--ink); }
.btn-quiet { background: transparent; color: var(--ink-2); border-color: transparent; padding-left: 8px; padding-right: 8px; }
.btn-quiet:hover { background: #efece4; color: var(--ink); }
.btn-small { padding: 7px 11px; font-size: 12.5px; }
.btn-row { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }

/* Alert queue rows */
.queue { display: flex; flex-direction: column; }
.alert-row {
  display: grid; grid-template-columns: minmax(0, 1fr) auto;
  gap: 18px; align-items: center;
  padding: 15px 18px;
  border-top: 1px solid var(--line);
}
.alert-row:first-child { border-top: 0; }
.alert-title { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.alert-title a { color: var(--ink); font-weight: 600; text-decoration: none; font-size: 14.5px; }
.alert-title a:hover { text-decoration: underline; text-underline-offset: 3px; }
.alert-meta { display: flex; flex-wrap: wrap; gap: 4px 10px; margin-top: 5px; color: var(--muted); font-size: 12.5px; }
.alert-meta .sep { opacity: 0.5; }
.alert-side { display: flex; align-items: center; gap: 14px; }
.alert-when { text-align: right; font-size: 12.5px; color: var(--ink-2); min-width: 148px; }
.alert-when .small { display: block; color: var(--muted); }
.src-chip {
  font-size: 11px; font-weight: 600; letter-spacing: 0.05em; text-transform: uppercase;
  color: var(--ink-2); background: #f1efe9; border: 1px solid var(--line);
  padding: 2px 7px; border-radius: 4px;
}

/* Filters */
.filters { padding: 16px 18px; display: flex; flex-direction: column; gap: 12px; }
.filter-row { display: flex; flex-wrap: wrap; gap: 12px; align-items: flex-end; }
.field { display: flex; flex-direction: column; gap: 5px; min-width: 0; }
.field label { font-size: 11.5px; font-weight: 600; letter-spacing: 0.06em; text-transform: uppercase; color: var(--muted); }
.input, .select {
  font: 400 13.5px/1.3 var(--sans); color: var(--ink);
  background: #fff; border: 1px solid var(--line-strong); border-radius: 7px;
  padding: 8px 10px; min-width: 140px;
}
.input:focus, .select:focus { outline: 2px solid var(--gold); outline-offset: 1px; border-color: var(--gold); }
.chips { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.chip {
  display: inline-flex; align-items: center; gap: 6px;
  background: var(--gold-soft); color: var(--gold-ink);
  border: 1px solid #e8d8b4; border-radius: 999px;
  padding: 3px 10px; font-size: 12px; text-decoration: none;
}
.chip:hover { background: #f1e3bf; color: var(--gold-ink); }
.chip .x { font-weight: 700; opacity: 0.7; }

/* Tables */
.table-wrap { overflow-x: auto; }
table.data { width: 100%; border-collapse: collapse; font-size: 13px; }
table.data th, table.data td { text-align: left; padding: 10px 14px; border-top: 1px solid var(--line); vertical-align: top; }
table.data thead th { border-top: 0; font-size: 11px; letter-spacing: 0.07em; text-transform: uppercase; color: var(--muted); font-weight: 600; }
table.data tbody tr:hover { background: #fbf9f4; }

/* Detail */
.detail-grid { display: grid; grid-template-columns: minmax(0, 1.6fr) minmax(0, 1fr); gap: 18px; align-items: start; }
.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; }
.summary-item .k { font-size: 11px; letter-spacing: 0.08em; text-transform: uppercase; color: var(--muted); font-weight: 600; }
.summary-item .v { margin-top: 4px; font-size: 14px; overflow-wrap: anywhere; }
.timeline { list-style: none; margin: 0; padding: 0 0 0 18px; border-left: 1px solid var(--line); display: flex; flex-direction: column; gap: 16px; }
.timeline li { position: relative; }
.timeline li::before {
  content: ""; position: absolute; left: -23px; top: 5px;
  width: 9px; height: 9px; border-radius: 50%;
  background: var(--surface); border: 2px solid var(--line-strong);
}
.timeline li.done::before { border-color: var(--gold); background: var(--gold); }
.timeline .t { font-weight: 600; font-size: 13.5px; }
.timeline .when { color: var(--ink-2); font-size: 12.5px; }
.timeline .note { color: var(--muted); font-size: 12.5px; margin-top: 2px; }
details.evidence { border: 1px solid var(--line); border-radius: 8px; background: #fbf9f4; }
details.evidence summary { cursor: pointer; padding: 11px 14px; font-weight: 600; font-size: 13px; }
details.evidence summary:focus-visible { outline: 2px solid var(--gold); outline-offset: 2px; }
details.evidence pre {
  margin: 0; padding: 0 14px 14px; overflow: auto; max-height: 420px;
  font-family: var(--mono); font-size: 12px; line-height: 1.5; color: var(--ink-2);
}

/* Forms */
.ack-panel { border-left: 3px solid var(--gold); }
.form-row { display: flex; flex-wrap: wrap; gap: 12px; align-items: flex-end; margin-top: 12px; }
.form-row .field { flex: 1 1 220px; }
.form-hint { color: var(--muted); font-size: 12.5px; margin-top: 8px; }
.form-error {
  margin-top: 12px; padding: 10px 12px; border-radius: 7px;
  background: var(--bad-bg); border: 1px solid #f0cdca; color: var(--bad); font-size: 13px;
}
.flash {
  margin-bottom: 18px; padding: 11px 14px; border-radius: 8px;
  background: var(--ok-bg); border: 1px solid #cfe4d9; color: var(--ok); font-size: 13.5px;
}

/* Empty / guidance states */
.empty {
  border: 1px dashed var(--line-strong); border-radius: var(--radius);
  background: #fbf9f4; padding: 26px; text-align: center; color: var(--muted); font-size: 13.5px;
}
.empty strong { color: var(--ink); display: block; margin-bottom: 4px; font-size: 14px; }
.guidance { background: #fbf9f4; border: 1px solid var(--line); border-radius: var(--radius); padding: 16px 18px; }
.guidance h3 { margin-bottom: 8px; }
.guidance ul { margin: 0; padding-left: 18px; color: var(--ink-2); font-size: 13px; }
.guidance li { margin: 5px 0; }
.guidance code { background: #f1eee6; border: 1px solid var(--line); padding: 1px 5px; border-radius: 4px; }

/* Pagination */
.pager { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 14px 18px; border-top: 1px solid var(--line); }
.pager .pages { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; }
.pager a, .pager span.current {
  display: inline-flex; align-items: center; justify-content: center;
  min-width: 30px; height: 30px; padding: 0 8px; border-radius: 6px;
  font-size: 12.5px; text-decoration: none; border: 1px solid transparent;
}
.pager a { color: var(--ink-2); border-color: var(--line); background: #fff; }
.pager a:hover { background: #f3f0e9; }
.pager span.current { background: var(--ink); color: #fff; border-color: var(--ink); font-weight: 600; }

/* Login */
.login-shell { min-height: 100vh; display: grid; place-items: center; padding: 28px; background: var(--paper); }
.login-card { width: 100%; max-width: 398px; background: var(--surface); border: 1px solid var(--line); border-radius: 12px; padding: 30px; box-shadow: 0 8px 28px rgba(28,31,36,0.06); }
.login-brand { display: flex; align-items: center; gap: 11px; margin-bottom: 22px; color: var(--ink); }
.login-brand .mark { width: 82px; height: 82px; object-fit: contain; }
.login-brand .brand-name { color: var(--ink); }
.login-brand .brand-tag { color: var(--muted); }
.login-title { font-size: 20px; }
.login-sub { color: var(--muted); font-size: 13px; margin-top: 6px; }
.login-form { margin-top: 22px; display: flex; flex-direction: column; gap: 14px; }
.login-form .input { width: 100%; }
.login-foot { margin-top: 20px; color: var(--muted); font-size: 12px; line-height: 1.6; }

/* Misc */
.kv { display: grid; grid-template-columns: max-content minmax(0, 1fr); gap: 6px 16px; font-size: 13px; }
.kv dt { color: var(--muted); }
.kv dd { margin: 0; overflow-wrap: anywhere; }
.tag-list { display: flex; flex-wrap: wrap; gap: 6px; }
.stat-line { display: flex; justify-content: space-between; gap: 12px; padding: 9px 0; border-top: 1px solid var(--line); font-size: 13px; }
.stat-line:first-child { border-top: 0; }
.visually-hidden {
  position: absolute !important; width: 1px; height: 1px; padding: 0; margin: -1px;
  overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; border: 0;
}
.status-list { display: flex; flex-direction: column; }
.status-row { display: grid; grid-template-columns: minmax(0, 1.2fr) auto; gap: 12px; align-items: start; padding: 12px 0; border-top: 1px solid var(--line); }
.status-row:first-child { border-top: 0; }
.status-row .detail { color: var(--muted); font-size: 12.5px; margin-top: 3px; overflow-wrap: anywhere; }
.inline-link { font-size: 12.5px; }
.mono-id { font-family: var(--mono); font-size: 12px; overflow-wrap: anywhere; }

@media (max-width: 1280px) {
  .metrics { grid-template-columns: repeat(3, minmax(0, 1fr)); }
}

@media (max-width: 980px) {
  .shell { grid-template-columns: 1fr; }
  .rail { position: static; height: auto; padding: 16px 18px; gap: 14px; }
  .nav { flex-direction: row; flex-wrap: wrap; gap: 4px; }
  .nav-link { border-left: 0; border-bottom: 2px solid transparent; padding: 7px 10px; }
  .nav-link[aria-current="page"] { border-left: 0; border-bottom-color: var(--gold); }
  .rail-foot { margin-top: 4px; border-top: 0; padding-top: 0; }
  .topbar { padding: 20px 20px 14px; }
  .content { padding: 20px 20px 44px; }
  .split, .detail-grid { grid-template-columns: 1fr; }
}

@media (max-width: 640px) {
  h1 { font-size: 21px; }
  .cards { grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); }
  .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .alert-row { grid-template-columns: 1fr; gap: 10px; }
  .alert-side { justify-content: space-between; }
  .alert-when { text-align: left; }
  .filter-row { gap: 10px; }
  .input, .select { min-width: 0; width: 100%; }
  .field { flex: 1 1 100%; }
  .topbar { align-items: flex-start; flex-direction: column; gap: 8px; }
}

@media (prefers-reduced-motion: reduce) {
  * { scroll-behavior: auto !important; }
}
"""
