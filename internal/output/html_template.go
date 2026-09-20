package output

// htmlTemplate is the whole report: one document, with the stylesheet and
// the script inlined. It references nothing outside itself — no CDN, no web
// font, no image — so the file works offline and can be mailed as-is.
//
// The script is progressive enhancement only. Every row is in the markup, so
// with scripting off the reader still gets the complete table; the controls
// stay hidden until the script reveals them, rather than sitting there dead.
const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DMARC report — {{.Domain}}</title>
<style>` + htmlCSS + `</style>
</head>
<body>
<main class="sheet">

  <header class="masthead">
    <div>
      <div class="eyebrow">DMARC aggregate report</div>
      <h1>{{.Domain}}</h1>
      <div class="subhead">{{.RangeLabel}}</div>
    </div>
    <div class="stamp">
      <svg width="62" height="40" viewBox="0 0 62 40" fill="none" aria-hidden="true">
        <rect x="1" y="1" width="60" height="38" rx="3" stroke="#a8a096" stroke-width="1.5" stroke-dasharray="4 3"/>
        <path d="M9 14c3-3 6 3 9 0s6 3 9 0" stroke="#8a827a" stroke-width="1.5" stroke-linecap="round"/>
        <path d="M9 20c3-3 6 3 9 0s6 3 9 0" stroke="#8a827a" stroke-width="1.5" stroke-linecap="round"/>
        <path d="M9 26c3-3 6 3 9 0s6 3 9 0" stroke="#8a827a" stroke-width="1.5" stroke-linecap="round"/>
        <path d="M38 13v14M38 13h8a3.5 3.5 0 0 1 0 7h-8" stroke="#57534e" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      <div class="mono tiny muted">{{.GeneratedAt}}</div>
    </div>
  </header>

  <div class="rule-strong"></div>

  <section class="verdict">
    <p class="rate v-{{.VerdictClass}}">{{.PassRate}}</p>
    <p class="verdict-prose">
      of <span class="mono">{{.Totals.Messages}}</span> messages carried a valid mark
      across <span class="mono">{{.SourceCount}}</span> sending addresses.
      <span class="v-{{.VerdictClass}}">{{.VerdictClause}}</span>
    </p>
  </section>

  <div class="bar" role="img" aria-label="{{.PassRate}} of messages passed DMARC">
    <div class="bar-fill f-{{.VerdictClass}}" style="width:{{.PassPercent}}%"></div>
  </div>
  <div class="bar-legend">
    <span class="mono">{{.Totals.DMARCPass}} passed</span>
    <span class="mono">{{.FailMessages}} did not</span>
  </div>

  <p class="callout">
    Published policy <span class="mono">p={{.PolicyP}}</span> for the full range.
    {{.PolicyAdvice}}
  </p>

  <h2 class="eyebrow section">What was read</h2>
  <div class="rule"></div>
  <div class="stats">
    {{range .Stats}}
    <div>
      <div class="stat-value mono t-{{.Tone}}">{{.Value}}</div>
      <div class="stat-label">{{.Label}}</div>
    </div>
    {{end}}
  </div>

  <h2 class="eyebrow section">What needs doing</h2>
  <div class="rule"></div>
  {{if .Groups}}
  <div class="groups">
    {{range .Groups}}
    <div class="group">
      <div class="group-mark">
        <div class="mark mono c-{{.Slug}}">{{.Name}}</div>
        <div class="mark-rule b-{{.Slug}}"></div>
        <div class="mono tiny muted">{{.Tally}}</div>
      </div>
      <div class="group-body">
        <p class="advice">{{.Advice}}</p>
        <div class="action-list">
          {{range .Sources}}
          <div class="action">
            <span class="mono action-ip">{{.IP}}</span>
            <span class="mono action-msgs">{{.MsgsLabel}}</span>
            <span class="action-spf"><span class="muted">spf:</span> <span class="mono">{{.SPFDomain}}</span></span>
          </div>
          {{end}}
        </div>
      </div>
    </div>
    {{end}}
  </div>
  {{else}}
  <div class="all-clear">
    <svg width="30" height="30" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="12" cy="12" r="9.25" stroke="#2f6b4f" stroke-width="1.5"/>
      <path d="M7.75 12.25l2.9 2.9 5.6-5.6" stroke="#2f6b4f" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
    <p>Nothing. Every sending address aligned on DKIM or SPF for every message in the range.</p>
  </div>
  {{end}}
  {{if .NoActionNote}}<p class="note">{{.NoActionNote}}</p>{{end}}

  <h2 class="eyebrow section">Every sending address</h2>
  <div class="rule"></div>

  <div class="controls noprint" id="controls" hidden>
    <div class="chips">
      {{range .Chips}}
      <button type="button" class="chip{{if .Active}} on c-bg-{{.Slug}}{{end}}" data-filter="{{.Key}}" aria-pressed="{{.Pressed}}">{{.Label}}</button>
      {{end}}
    </div>
    <div class="search">
      <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true">
        <circle cx="7" cy="7" r="4.5" stroke="#78716c" stroke-width="1.5"/>
        <path d="M10.5 10.5L14 14" stroke="#78716c" stroke-width="1.5" stroke-linecap="round"/>
      </svg>
      <label class="vh" for="src-filter">Filter addresses</label>
      <input id="src-filter" class="mono" type="text" placeholder="filter by address or domain" autocomplete="off">
    </div>
  </div>

  <table class="sources" id="sources">
    <thead>
      <tr>
        <th scope="col" data-sort="ip" aria-sort="none"><span class="th">Address</span></th>
        {{if .Resolve}}<th scope="col"><span class="th">Reverse name</span></th>{{end}}
        <th scope="col" class="num" data-sort="msgs" aria-sort="descending"><span class="th">Msgs</span></th>
        <th scope="col" class="num"><span class="th">DKIM</span></th>
        <th scope="col" class="num"><span class="th">SPF</span></th>
        <th scope="col"><span class="th">SPF domain</span></th>
        <th scope="col" class="right"><span class="th">Class</span></th>
      </tr>
    </thead>
    <tbody>
      {{range .Rows}}
      <tr data-row data-class="{{.Slug}}" data-msgs="{{.Messages}}" data-ip="{{.IP}}" data-search="{{.Search}}">
        <td class="mono" data-label="">{{.IP}}</td>
        {{if $.Resolve}}<td class="mono tiny muted" data-label="Reverse">{{.Host}}</td>{{end}}
        <td class="num" data-label="Msgs">
          <div class="mono">{{.Messages}}</div>
          <div class="share"><div class="share-fill b-{{.Slug}}" style="width:{{.ShareWidth}}%"></div></div>
        </td>
        <td class="num mono{{if .DKIMZero}} zero{{end}}" data-label="DKIM">{{.DKIM}}</td>
        <td class="num mono{{if .SPFZero}} zero{{end}}" data-label="SPF">{{.SPF}}</td>
        <td class="mono tiny" data-label="SPF domain">{{.SPFDomain}}</td>
        <td class="right" data-label=""><span class="mark mono c-{{.Slug}} u-{{.Slug}}">{{.Class}}</span></td>
      </tr>
      {{end}}
    </tbody>
  </table>
  <p class="rownote" id="rownote">{{.RowNote}}</p>

  {{if or .ShowFiles .FileErrors}}
  <h2 class="eyebrow section">Files read</h2>
  <div class="rule"></div>
  <table class="files">
    <thead>
      <tr>
        <th scope="col"><span class="th">File</span></th>
        <th scope="col"><span class="th">Organization</span></th>
        <th scope="col" class="num"><span class="th">Records</span></th>
        <th scope="col" class="num"><span class="th">Messages</span></th>
        <th scope="col" class="right"><span class="th">Status</span></th>
      </tr>
    </thead>
    <tbody>
      {{range .FileRows}}
      <tr>
        <td class="mono tiny">{{.Name}}</td>
        <td class="tiny">{{.Org}}</td>
        <td class="num mono tiny">{{.Records}}</td>
        <td class="num mono tiny">{{.Messages}}</td>
        <td class="right mono tiny s-{{.Status}}">{{.Status}}</td>
      </tr>
      {{if .Reason}}<tr class="reason"><td colspan="5">{{.Name}} — {{.Reason}}</td></tr>{{end}}
      {{end}}
    </tbody>
  </table>
  {{end}}

  <div class="rule-strong footer-rule"></div>
  <footer>
    <div class="provenance">
      {{if .Resolve}}Reverse names were resolved against your DNS resolver, which means these
      source addresses were sent to it.{{else}}No network call was made while producing this
      report.{{end}}
      Every input file was opened read-only; nothing was written, extracted or executed.
      Limits in effect: <span class="mono">{{.Limits.MaxFileSize}}</span> per file,
      <span class="mono">{{.Limits.MaxXMLSize}}</span> decompressed,
      <span class="mono">{{.Limits.MaxRatio}}</span> ratio.
    </div>
    <div class="colophon mono">
      franking {{.Version}}<br>
      <span class="muted">{{.Command}}</span>
    </div>
  </footer>

</main>
<script>` + htmlJS + `</script>
</body>
</html>
`
