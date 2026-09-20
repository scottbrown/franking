package output

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"time"

	"franking/internal/aggregate"
	"franking/internal/report"
)

func renderHTML(t *testing.T, res *aggregate.Result, opt Options) string {
	t.Helper()
	if opt.Now.IsZero() {
		opt.Now = time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	}
	if opt.Limits == (LimitLabels{}) {
		opt.Limits = DefaultLimitLabels()
	}
	var buf bytes.Buffer
	if err := WriteHTML(&buf, res, opt); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	return buf.String()
}

// TestHTMLCarriesTheDMARCUnion is the load-bearing test. A DMARC pass is the
// union of aligned DKIM and aligned SPF, so it cannot be recovered from the
// two column percentages: 62% and 41% is neither 100% (a capped sum) nor
// 103%. The writer must print the count the aggregate carries.
func TestHTMLCarriesTheDMARCUnion(t *testing.T) {
	agg := aggregate.New()
	agg.AddFile(agg.AddReport("r.xml", &report.Report{
		Metadata: report.Metadata{Org: "google.com", Range: report.DateRange{
			Begin: time.Unix(1700000000, 0), End: time.Unix(1700086400, 0)}},
		Policy: report.Policy{Domain: "example.ca", P: "none"},
		Records: []report.Record{
			// 60 DKIM-only, 39 SPF-only, and 11 that pass both: 96 messages,
			// 88 of which pass DMARC. No arithmetic over 62%/41% gives 88.
			mkRecord("198.51.100.4", 49, report.AuthPass, report.AuthFail),
			mkRecord("198.51.100.4", 11, report.AuthPass, report.AuthPass),
			mkRecord("198.51.100.4", 28, report.AuthFail, report.AuthPass),
			mkRecord("198.51.100.4", 8, report.AuthFail, report.AuthFail),
		},
	}))
	res := agg.Result(1)

	src := res.Sources[0]
	if src.Messages != 96 || src.DKIMPass != 60 || src.SPFPass != 39 || src.DMARCPass != 88 {
		t.Fatalf("fixture drifted: %d msgs, dkim %d, spf %d, dmarc %d",
			src.Messages, src.DKIMPass, src.SPFPass, src.DMARCPass)
	}

	html := renderHTML(t, res, Options{})
	if !strings.Contains(html, "88 passed") {
		t.Errorf("want the aggregate's union count (88) in the report")
	}
	if !strings.Contains(html, "8 did not") {
		t.Errorf("want 8 failing messages")
	}
	for _, wrong := range []string{"96 passed", "99 passed", "60 passed", "39 passed"} {
		if strings.Contains(html, wrong) {
			t.Errorf("the pass count was recomputed from the columns: found %q", wrong)
		}
	}
	if !strings.Contains(html, "91.7%") {
		t.Errorf("want 88/96 = 91.7%%, got:\n%s", firstLines(html, 60))
	}
}

func TestHTMLIsSelfContained(t *testing.T) {
	html := renderHTML(t, hostileResult(), Options{ShowFiles: true, Resolve: true})

	external := regexp.MustCompile(`(?i)(src|href)\s*=\s*"([^"#][^"]*)"`)
	for _, m := range external.FindAllStringSubmatch(html, -1) {
		t.Errorf("external reference %q — the report must be one self-contained file", m[2])
	}
	for _, bad := range []string{"http://", "https://", "//cdn", "@import", "url("} {
		if strings.Contains(html, bad) {
			t.Errorf("report reaches outside itself: %q", bad)
		}
	}
	if !strings.Contains(html, "<style>") || !strings.Contains(html, "<script>") {
		t.Error("the stylesheet and the script must be inlined")
	}
}

func TestHTMLEscapesHostileStrings(t *testing.T) {
	agg := aggregate.New()
	agg.AddFile(agg.AddReport("r.xml", &report.Report{
		Metadata: report.Metadata{
			// Everything here has already passed the sanitizer; html/template
			// is the second line of defence, and it has to hold.
			Org:   `</script><script>alert(1)</script>`,
			Range: report.DateRange{Begin: time.Unix(1700000000, 0), End: time.Unix(1700086400, 0)},
		},
		Policy: report.Policy{Domain: `x" onload="alert(1)`, P: `none"><b>`},
		Records: []report.Record{
			mkRecord(`" onmouseover="alert(1)`, 5, report.AuthFail, report.AuthFail),
		},
	}))
	agg.AddFile(aggregate.FileResult{
		Name:   `</td></tr><script>alert(2)</script>`,
		Status: aggregate.StatusError,
		Reason: `<img src=x onerror=alert(3)>`,
	})
	html := renderHTML(t, agg.Result(1), Options{ShowFiles: true})

	// Angle brackets and quotes are what turn a string into markup. With
	// those escaped the payload text itself is inert prose on the page.
	for _, raw := range []string{
		"<script>alert(1)", "<script>alert(2)", "<img src=x",
		`onload="alert(1)"`, `onmouseover="alert(1)"`, "</td></tr><script>",
	} {
		if strings.Contains(html, raw) {
			t.Errorf("unescaped hostile string reached the output: %q", raw)
		}
	}
	if strings.Contains(html, "ZgotmplZ") {
		t.Error("html/template refused a value, which means something untrusted reached a CSS or JS context")
	}
	// Exactly the two script and style blocks this writer emits.
	if n := strings.Count(html, "<script"); n != 1 {
		t.Errorf("found %d script tags, want exactly 1", n)
	}
	if n := strings.Count(html, "<style"); n != 1 {
		t.Errorf("found %d style tags, want exactly 1", n)
	}
}

func TestHTMLHoldsNoControlBytes(t *testing.T) {
	for _, tc := range []struct {
		name string
		res  *aggregate.Result
	}{
		{"hostile", hostileResult()},
		{"simple", simpleResult()},
		{"empty", aggregate.New().Result(1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			html := renderHTML(t, tc.res, Options{ShowFiles: true, Resolve: true})
			for i := range len(html) {
				if html[i] < 0x20 && html[i] != '\n' && html[i] != '\t' {
					t.Fatalf("byte %d is a control character 0x%02x", i, html[i])
				}
			}
		})
	}
}

func TestHTMLActionsExcludeTheClassesThatAreDone(t *testing.T) {
	tests := []struct {
		class aggregate.Class
		want  bool
	}{
		{aggregate.ClassFail, true},
		{aggregate.ClassPartial, true},
		{aggregate.ClassSPFOnly, true},
		{aggregate.ClassDKIMOnly, false},
		{aggregate.ClassPass, false},
	}
	for _, tc := range tests {
		t.Run(string(tc.class), func(t *testing.T) {
			if got := needsAction(tc.class); got != tc.want {
				t.Fatalf("needsAction(%q) = %v, want %v", tc.class, got, tc.want)
			}
		})
	}
}

func TestHTMLAllClearState(t *testing.T) {
	agg := aggregate.New()
	agg.AddFile(agg.AddReport("clean.xml", &report.Report{
		Metadata: report.Metadata{Org: "google.com", Range: report.DateRange{
			Begin: time.Unix(1700000000, 0), End: time.Unix(1700086400, 0)}},
		Policy:  report.Policy{Domain: "example.ca", P: "none"},
		Records: []report.Record{mkRecord("192.0.2.1", 17, report.AuthPass, report.AuthPass)},
	}))
	html := renderHTML(t, agg.Result(1), Options{})

	if !strings.Contains(html, "Nothing needs your attention.") {
		t.Error("want the all-clear verdict")
	}
	if !strings.Contains(html, "class=\"all-clear\"") {
		t.Error("want the all-clear block instead of an empty actions list")
	}
	if !strings.Contains(html, "tightening the policy is safe") {
		t.Error("want the advice that the policy can move forward")
	}
	if strings.Contains(html, "would be discarded") {
		t.Error("the below-100% warning must not appear on a clean run")
	}
}

func TestHTMLEmptyRunDoesNotClaimAnything(t *testing.T) {
	html := renderHTML(t, aggregate.New().Result(1), Options{})
	if !strings.Contains(html, "No messages were reported") {
		t.Errorf("want an honest empty-run verdict, got:\n%s", firstLines(html, 40))
	}
	if strings.Contains(html, "sources need attention") {
		t.Error("an empty run must not point at sources")
	}
}

func TestHTMLFileTableFollowsShowFiles(t *testing.T) {
	res := simpleResult()
	res.Files = append(res.Files, aggregate.FileResult{
		Name: "broken.xml", Status: aggregate.StatusError, Reason: "xml: parse error",
	})
	res.FilesError = 1

	quiet := renderHTML(t, res, Options{})
	if !strings.Contains(quiet, "broken.xml") {
		t.Error("an error row must print even without -files")
	}
	if strings.Contains(quiet, "good.xml") {
		t.Error("a healthy row must not print without -files")
	}

	full := renderHTML(t, res, Options{ShowFiles: true})
	if !strings.Contains(full, "good.xml") {
		t.Error("-files must print every row")
	}
}

func TestHTMLResolveControlsTheHostColumn(t *testing.T) {
	res := simpleResult()
	res.Sources[0].Host = "mail.example.ca"

	plain := renderHTML(t, res, Options{})
	if strings.Contains(plain, "Reverse name") || strings.Contains(plain, "mail.example.ca") {
		t.Error("the host column must appear only with -resolve")
	}
	if !strings.Contains(plain, "No network call was made") {
		t.Error("want the no-network provenance line by default")
	}

	resolved := renderHTML(t, res, Options{Resolve: true})
	if !strings.Contains(resolved, "Reverse name") || !strings.Contains(resolved, "mail.example.ca") {
		t.Error("-resolve must add the host column")
	}
	if !strings.Contains(resolved, "sent to it") {
		t.Error("want the resolver disclosure when -resolve is on")
	}
}

func TestHTMLClassSlugsCoverEveryClass(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range aggregate.Classes() {
		slug := classSlug(c)
		if slug == "unknown" {
			t.Errorf("class %q has no slug", c)
		}
		if seen[slug] {
			t.Errorf("slug %q is used twice", slug)
		}
		seen[slug] = true
		// Every slug needs the colour rules the markup asks for.
		for _, prefix := range []string{"c-", "b-", "u-", "c-bg-"} {
			if !strings.Contains(htmlCSS, "."+prefix+slug+"{") &&
				!strings.Contains(htmlCSS, "."+prefix+slug+"{") {
				t.Errorf("stylesheet has no .%s%s rule", prefix, slug)
			}
		}
	}
	if got := classSlug(aggregate.Class("something else")); got != "unknown" {
		t.Errorf("an unknown class must fall back to %q, got %q", "unknown", got)
	}
}

func TestHTMLStructureIsBalanced(t *testing.T) {
	html := renderHTML(t, hostileResult(), Options{ShowFiles: true, Resolve: true})

	if !strings.HasPrefix(html, "<!DOCTYPE html>") {
		t.Error("want a doctype first")
	}
	for _, tag := range []string{"html", "head", "body", "main", "table", "thead", "tbody", "tr", "td", "th"} {
		open := strings.Count(html, "<"+tag+" ") + strings.Count(html, "<"+tag+">")
		close := strings.Count(html, "</"+tag+">")
		if open != close {
			t.Errorf("<%s>: %d opened, %d closed", tag, open, close)
		}
	}
}

func TestHTMLPercentagesAreBounded(t *testing.T) {
	tests := []struct {
		in   float64
		want float64
	}{
		{-5, 0}, {0, 0}, {46.2962962962963, 46.3}, {91.149, 91.1}, {100, 100}, {140, 100},
	}
	for _, tc := range tests {
		if got := clampPercent(tc.in); got != tc.want {
			t.Errorf("clampPercent(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
	html := renderHTML(t, hostileResult(), Options{})
	widths := regexp.MustCompile(`width:([0-9.]+)%`).FindAllStringSubmatch(html, -1)
	if len(widths) == 0 {
		t.Fatal("no bar widths rendered")
	}
	for _, m := range widths {
		if len(m[1]) > 5 {
			t.Errorf("width %q carries more precision than a label can match", m[1])
		}
	}
}

func TestHaystackDropsEmptyFields(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want string
	}{
		{"all present", []string{"192.0.2.1", "Mail.Example.CA"}, "192.0.2.1 mail.example.ca"},
		{"empty host", []string{"192.0.2.1", "", "vendor.net"}, "192.0.2.1 vendor.net"},
		{"dash placeholder", []string{"192.0.2.1", "-"}, "192.0.2.1"},
		{"nothing", []string{"", "-"}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := haystack(tc.in...); got != tc.want {
				t.Fatalf("haystack(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestHTMLScriptIsProgressiveEnhancement(t *testing.T) {
	html := renderHTML(t, simpleResult(), Options{})

	// Controls stay hidden until the script reveals them, so no-JS readers
	// never see a dead filter bar.
	if !strings.Contains(html, `id="controls" hidden`) {
		t.Error("the controls must ship hidden")
	}
	if !strings.Contains(html, "controls.hidden = false") {
		t.Error("the script must reveal the controls")
	}
	// Every row is in the markup, not handed to the script as data.
	if strings.Contains(html, "JSON.parse") || strings.Contains(html, "application/json") {
		t.Error("report data must not be embedded for the script to parse")
	}
	rows := strings.Count(html, "<tr data-row")
	if rows != len(simpleResult().Sources) {
		t.Errorf("%d rows in the markup, want %d", rows, len(simpleResult().Sources))
	}
}

func mkRecord(ip string, count int64, dkim, spf report.AuthResult) report.Record {
	return report.Record{
		SourceIP: ip, Count: count, Disposition: report.DispositionNone,
		DKIM: dkim, SPF: spf, HeaderFrom: "example.ca",
		SPFDomains: []string{"example.ca"},
	}
}

func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
