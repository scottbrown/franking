package output

// htmlCSS is the whole stylesheet. No web font: the serif and monospace
// stacks are what the reader's machine already has, so the file carries no
// font bytes and renders identically offline.
//
// Class colours live here, keyed by a slug from a fixed set. Nothing from a
// report is ever interpolated into a stylesheet.
const htmlCSS = `
:root {
  --paper:#faf8f3; --panel:#fff; --ink:#1c1917; --ink-2:#44403c;
  --ink-3:#57534e; --muted:#78716c; --rule:#ddd7cc; --rule-2:#ece7dc;
  --pass:#2f6b4f; --dkim-only:#2a6478; --spf-only:#8a5d12;
  --partial:#a8541f; --fail:#9b2c2c; --unknown:#57534e;
  --serif:'Iowan Old Style','Palatino Linotype',Palatino,'Book Antiqua',Georgia,serif;
  --mono:ui-monospace,SFMono-Regular,'SF Mono',Menlo,Consolas,'Liberation Mono',monospace;
}
*{box-sizing:border-box}
[hidden]{display:none!important}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--paper);color:var(--ink);font-family:var(--serif);
  -webkit-font-smoothing:antialiased;line-height:1.5}
a{color:var(--dkim-only);text-decoration:none;border-bottom:1px solid #c3d2d8}
a:hover{color:var(--ink);border-bottom-color:var(--ink)}
button{font:inherit;color:inherit;background:none;border:none;padding:0;cursor:pointer}
button:focus-visible,input:focus-visible{outline:2px solid var(--dkim-only);outline-offset:2px}
h1,h2{margin:0;font-weight:400}
p{margin:0}
.mono{font-family:var(--mono);font-variant-numeric:tabular-nums}
.tiny{font-size:12px}
.muted{color:var(--muted)}
.vh{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);
  clip-path:inset(50%);white-space:nowrap}

.sheet{max-width:1080px;margin:0 auto;padding:56px 72px 64px}

.masthead{display:flex;justify-content:space-between;align-items:flex-start;gap:40px}
.eyebrow{text-transform:uppercase;letter-spacing:.14em;font-size:11px;color:var(--muted)}
.masthead h1{font-size:40px;line-height:1.1;letter-spacing:-.01em;margin-top:14px;
  overflow-wrap:anywhere}
.subhead{font-size:16px;color:var(--ink-3);margin-top:10px}
.stamp{display:flex;flex-direction:column;align-items:flex-end;gap:10px;padding-top:4px;flex-shrink:0}

.rule-strong{height:1px;background:var(--ink);margin:28px 0 0;
  box-shadow:0 4px 0 -3px var(--rule)}
.rule{height:1px;background:var(--rule);margin:10px 0 22px}
.section{margin-top:52px}

.verdict{display:flex;align-items:baseline;gap:28px;flex-wrap:wrap;margin-top:44px}
.rate{font-size:88px;line-height:.92;letter-spacing:-.03em}
.verdict-prose{max-width:560px;font-size:21px;line-height:1.5;color:var(--ink-2);
  text-wrap:pretty}
.verdict-prose .mono{font-size:19px}

.bar{margin-top:32px;display:flex;height:7px;background:#e8e2d6;border-radius:1px;overflow:hidden}
.bar-fill{height:100%}
.bar-legend{display:flex;justify-content:space-between;margin-top:9px;font-size:11px;color:var(--muted)}

.callout{margin-top:26px;padding:16px 20px;background:#f2ede2;border-left:3px solid var(--muted);
  font-size:15px;line-height:1.6;color:var(--ink-2);text-wrap:pretty}
.callout .mono{font-size:14px}
.note{margin-top:24px;padding:13px 16px;background:#f5f2ea;border-left:3px solid #cfc7b8;
  font-size:14px;line-height:1.6;color:var(--ink-3);max-width:780px;text-wrap:pretty}

.stats{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:28px}
.stat-value{font-size:30px;letter-spacing:-.02em}
.stat-label{font-size:13px;color:var(--ink-3);margin-top:4px}
.t-ink{color:var(--ink)}.t-muted{color:var(--muted)}.t-fail{color:var(--fail)}

.groups{display:flex;flex-direction:column;gap:26px}
.group{display:flex;gap:26px;align-items:flex-start}
.group-mark{width:132px;flex-shrink:0;padding-top:2px}
.mark{text-transform:uppercase;letter-spacing:.14em;font-size:11px}
.mark-rule{height:2px;margin-top:6px;width:100%}
.group-mark .tiny{margin-top:7px;font-size:11px}
.group-body{flex-grow:1;min-width:0}
.advice{font-size:16px;line-height:1.55;color:var(--ink-2);font-style:italic;
  margin-bottom:12px;max-width:620px;text-wrap:pretty}
.action-list{display:flex;flex-direction:column;gap:7px}
.action{display:flex;align-items:baseline;gap:16px;padding:7px 12px;background:var(--panel);
  border:1px solid #e8e2d6;border-radius:2px;flex-wrap:wrap}
.action-ip{font-size:14px;width:132px;flex-shrink:0}
.action-msgs{font-size:13px;color:var(--ink-3);width:96px;flex-shrink:0}
.action-spf{font-size:13px;color:var(--ink-3);overflow-wrap:anywhere}
.action-spf .mono{font-size:13px}

.all-clear{display:flex;align-items:center;gap:18px;padding:26px 28px;background:var(--panel);
  border:1px solid #e0e7de;border-radius:2px}
.all-clear p{font-size:17px;line-height:1.55;color:var(--ink-2);text-wrap:pretty}
.all-clear svg{flex-shrink:0}

.controls{display:flex;justify-content:space-between;align-items:center;gap:24px;
  flex-wrap:wrap;margin-bottom:18px}
.chips{display:flex;gap:8px;flex-wrap:wrap}
.chip{font-family:var(--mono);text-transform:uppercase;letter-spacing:.14em;font-size:10px;
  padding:10px 12px;min-height:36px;border:1px solid var(--rule);color:var(--ink-3);
  background:transparent;border-radius:2px}
.chip:hover{border-color:var(--ink);color:var(--ink)}
.chip.on{color:#fff}
.c-bg-all{background:var(--dkim-only);border-color:var(--dkim-only)}
.c-bg-pass{background:var(--pass);border-color:var(--pass)}
.c-bg-dkim-only{background:var(--dkim-only);border-color:var(--dkim-only)}
.c-bg-spf-only{background:var(--spf-only);border-color:var(--spf-only)}
.c-bg-partial{background:var(--partial);border-color:var(--partial)}
.c-bg-fail{background:var(--fail);border-color:var(--fail)}
.search{display:flex;align-items:center;gap:9px;border-bottom:1px solid var(--rule);padding-bottom:5px}
.search input{border:none;background:transparent;font-size:13px;color:var(--ink);width:210px;padding:2px 0}

table{width:100%;border-collapse:collapse;table-layout:auto}
thead th{text-align:left;padding:0 12px 9px;border-bottom:1px solid var(--ink);vertical-align:bottom}
.th{text-transform:uppercase;letter-spacing:.14em;font-size:10px;color:var(--ink-3);font-weight:400}
th[data-sort]{cursor:pointer}
th[data-sort]:hover .th{color:var(--ink)}
th[data-sort] .th::after{content:'';font-family:var(--mono);margin-left:5px}
th[aria-sort=descending] .th::after{content:'\25be'}
th[aria-sort=ascending] .th::after{content:'\25b4'}
tbody td{padding:13px 12px;border-bottom:1px solid var(--rule-2);vertical-align:top;font-size:14px}
tbody tr:hover{background:#f4f0e8}
.num{text-align:right}
.right{text-align:right}
td.zero{color:var(--muted)}
.share{height:2px;background:var(--rule);margin-top:4px;margin-left:auto;width:62px}
.share-fill{height:2px}
.rownote{margin-top:12px;font-size:13px;color:var(--muted);font-style:italic}

.sources td.mono{overflow-wrap:anywhere}
.files td{padding:9px 12px;font-size:12px}
tr.reason td{border-bottom:1px solid var(--rule-2);padding-top:0;color:var(--fail);
  font-style:italic;font-size:13px}
.s-error{color:var(--fail)}
.s-skipped{color:var(--muted)}
.s-ok{color:var(--ink-3)}

.c-pass{color:var(--pass)}.c-dkim-only{color:var(--dkim-only)}
.c-spf-only{color:var(--spf-only)}.c-partial{color:var(--partial)}
.c-fail{color:var(--fail)}.c-unknown{color:var(--unknown)}
.b-pass{background:var(--pass)}.b-dkim-only{background:var(--dkim-only)}
.b-spf-only{background:var(--spf-only)}.b-partial{background:var(--partial)}
.b-fail{background:var(--fail)}.b-unknown{background:var(--unknown)}
.f-pass{background:var(--pass)}.f-partial{background:var(--partial)}
.f-fail{background:var(--fail)}.f-unknown{background:var(--unknown)}
.v-pass{color:var(--pass)}.v-partial{color:var(--partial)}
.v-fail{color:var(--fail)}.v-unknown{color:var(--unknown)}
.u-pass{border-bottom:2px solid var(--pass)}
.u-dkim-only{border-bottom:2px solid var(--dkim-only)}
.u-spf-only{border-bottom:2px solid var(--spf-only)}
.u-partial{border-bottom:2px solid var(--partial)}
.u-fail{border-bottom:2px solid var(--fail)}
.u-unknown{border-bottom:2px solid var(--unknown)}
td .mark{padding-bottom:2px;font-size:10px}

.diag-headline{font-size:21px;line-height:1.5;color:var(--ink);margin-bottom:20px;
  max-width:680px;text-wrap:pretty}
table.diag{width:auto;margin-bottom:6px}
table.diag td{border:none;padding:6px 26px 6px 0;font-size:14px;vertical-align:baseline}
table.diag td.num{text-align:left}
.evidence{font-size:14px;line-height:1.6;color:var(--ink-3);max-width:680px;
  margin-top:10px;text-wrap:pretty}
ol.todo{margin:0;padding-left:0;list-style:none;counter-reset:step;
  display:flex;flex-direction:column;gap:18px}
ol.todo li{counter-increment:step;display:grid;grid-template-columns:34px minmax(0,1fr);gap:12px}
ol.todo .todo-body{min-width:0}
ol.todo li::before{content:counter(step) ".";font-size:16px;color:var(--muted);
  font-variant-numeric:tabular-nums}
.todo-title{font-size:17px;line-height:1.45;color:var(--ink)}
.todo-detail{font-size:15px;line-height:1.6;color:var(--ink-3);margin-top:5px;
  max-width:640px;text-wrap:pretty}

.footer-rule{margin-top:52px}
footer{display:flex;justify-content:space-between;gap:40px;flex-wrap:wrap;
  font-size:12px;color:var(--ink-3);margin-top:22px}
.provenance{max-width:560px;line-height:1.7;text-wrap:pretty}
.colophon{text-align:right;line-height:1.7}

/* ── Phone ─────────────────────────────────────────────────────────── */
@media (max-width:720px){
  .sheet{padding:28px 20px 40px}
  .masthead h1{font-size:26px}
  .rate{font-size:62px}
  .verdict{gap:0;margin-top:28px}
  .verdict-prose{font-size:17px;margin-top:14px}
  .stats{grid-template-columns:repeat(2,minmax(0,1fr));gap:20px}
  .group{flex-direction:column;gap:11px}
  .diag-headline{font-size:18px}
  table.diag,table.diag tbody,table.diag tr,table.diag td{display:block}
  table.diag tr{margin-bottom:12px}
  table.diag td{padding:1px 0}
  .group-mark{width:auto}
  .mark-rule{width:54px}
  .chip{padding:14px 13px;min-height:44px}
  .search input{width:100%}
  .search{flex-grow:1}
  footer{flex-direction:column;gap:18px}
  .colophon{text-align:left}

  /* The table becomes one stacked record per address. */
  .sources thead{display:none}
  .sources tr{display:block;padding:14px 0;border-bottom:1px solid var(--rule-2)}
  .sources tbody tr:hover{background:transparent}
  .sources td{display:flex;justify-content:space-between;gap:12px;border:none;
    padding:2px 0;text-align:left}
  .sources td::before{content:attr(data-label);text-transform:uppercase;
    letter-spacing:.14em;font-size:10px;color:var(--muted);font-family:var(--serif)}
  .sources td[data-label='']::before{content:none}
  .share{display:none}
  .files{display:block;overflow-x:auto;white-space:nowrap}
}

/* ── Print ─────────────────────────────────────────────────────────── */
@media print{
  :root{--paper:#fff}
  .noprint{display:none!important}
  body{background:#fff}
  .sheet{max-width:none;padding:0}
  /* Reading copy to the 12pt floor; labels and footer no lower than 10.5pt. */
  .advice,.callout,.all-clear p,.evidence,.todo-detail{font-size:16px}
  ol.todo li,.diag-headline{break-inside:avoid}
  .action-ip,.action-msgs,.action-spf,.action-spf .mono{font-size:16px}
  .action-ip{width:152px}.action-msgs{width:92px}
  footer,.provenance,.colophon,.rownote,.stat-label{font-size:14px}
  tbody td{font-size:14px;padding:8px 12px}
  .rate{font-size:66px}
  /* A hairline-bounded bar rather than a flood fill, so it does not drink ink. */
  .bar{border:1px solid var(--ink);background:#fff;height:10px;border-radius:0}
  .group,.action,tr,.all-clear{break-inside:avoid}
  h2{break-after:avoid}
  a{color:var(--ink);border-bottom-color:var(--ink)}
}
`

// htmlJS is progressive enhancement and nothing else. Every row is already
// in the markup, so with scripting off the reader still gets the whole
// table; the controls stay hidden until this runs rather than sitting there
// dead. It reads only data- attributes, so no report string is ever parsed
// as code.
const htmlJS = `
(function () {
  'use strict';
  var table = document.getElementById('sources');
  var controls = document.getElementById('controls');
  var note = document.getElementById('rownote');
  if (!table || !controls) { return; }

  var body = table.tBodies[0];
  var rows = [].slice.call(body.querySelectorAll('tr[data-row]'));
  if (!rows.length) { return; }

  var total = rows.length;
  var state = { filter: 'all', query: '', key: 'msgs', dir: 'desc' };

  function num(row) { return parseInt(row.getAttribute('data-msgs'), 10) || 0; }

  function apply() {
    var shown = 0;
    rows.forEach(function (row) {
      var okClass = state.filter === 'all' || row.getAttribute('data-class') === state.filter;
      var okQuery = !state.query ||
        (row.getAttribute('data-search') || '').indexOf(state.query) >= 0;
      var visible = okClass && okQuery;
      row.hidden = !visible;
      if (visible) { shown++; }
    });
    if (note) {
      note.textContent = shown === total
        ? 'Showing all ' + total + ' addresses, busiest first.'
        : 'Showing ' + shown + ' of ' + total + ' addresses.';
    }
  }

  function sort(key) {
    if (state.key === key) {
      state.dir = state.dir === 'desc' ? 'asc' : 'desc';
    } else {
      state.key = key;
      state.dir = key === 'ip' ? 'asc' : 'desc';
    }
    var sign = state.dir === 'desc' ? -1 : 1;
    rows.sort(function (a, b) {
      if (state.key === 'ip') {
        return sign * a.getAttribute('data-ip').localeCompare(b.getAttribute('data-ip'));
      }
      return sign * (num(a) - num(b));
    });
    rows.forEach(function (row) { body.appendChild(row); });
    [].forEach.call(table.querySelectorAll('th[data-sort]'), function (th) {
      th.setAttribute('aria-sort', th.getAttribute('data-sort') === state.key
        ? (state.dir === 'desc' ? 'descending' : 'ascending') : 'none');
    });
  }

  var chips = [].slice.call(controls.querySelectorAll('[data-filter]'));
  chips.forEach(function (chip) {
    chip.addEventListener('click', function () {
      state.filter = chip.getAttribute('data-filter');
      chips.forEach(function (other) {
        var on = other === chip;
        other.setAttribute('aria-pressed', on ? 'true' : 'false');
        other.classList.toggle('on', on);
        var slug = other.getAttribute('data-filter');
        other.classList.toggle('c-bg-' + slug, on);
      });
      apply();
    });
  });

  [].forEach.call(table.querySelectorAll('th[data-sort]'), function (th) {
    th.tabIndex = 0;
    th.setAttribute('role', 'button');
    th.addEventListener('click', function () { sort(th.getAttribute('data-sort')); });
    th.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); sort(th.getAttribute('data-sort')); }
    });
  });

  var search = document.getElementById('src-filter');
  if (search) {
    search.addEventListener('input', function () {
      state.query = search.value.trim().toLowerCase();
      apply();
    });
  }

  controls.hidden = false;
}());
`
