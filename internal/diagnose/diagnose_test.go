package diagnose

import (
	"strings"
	"testing"
	"time"

	"github.com/scottbrown/franking/internal/aggregate"
	"github.com/scottbrown/franking/internal/report"
)

// source describes one sending address for a scenario.
type source struct {
	ip          string
	msgs        int64
	dkim, spf   report.AuthResult
	dkimDomains []string
	spfDomain   string
}

// build turns a scenario into a finished Result, through the real
// aggregator, so the diagnosis is tested against the same shapes the tool
// actually produces.
func build(t *testing.T, policy, domain string, days int, sources ...source) *aggregate.Result {
	t.Helper()
	return buildReports(t, domain, period{policy: policy, days: days, sources: sources})
}

// period is one report: the policy it carried, when it ran, counted in days
// from a fixed start, and what it saw.
type period struct {
	policy     string
	from, days int
	sources    []source
}

func buildReports(t *testing.T, domain string, periods ...period) *aggregate.Result {
	t.Helper()
	start := time.Unix(1789171200, 0)
	agg := aggregate.New()
	for _, p := range periods {
		begin := start.Add(time.Duration(p.from) * 24 * time.Hour)
		end := begin.Add(time.Duration(p.days) * 24 * time.Hour)
		agg.AddFile(agg.AddReport("r.xml", &report.Report{
			Metadata: report.Metadata{Org: "google.com",
				Range: report.DateRange{Begin: begin, End: end}},
			Policy:  report.Policy{Domain: domain, P: p.policy},
			Records: records(domain, p.sources),
		}))
	}
	return agg.Result(1)
}

func records(domain string, sources []source) []report.Record {
	var records []report.Record
	for _, s := range sources {
		rec := report.Record{
			SourceIP: s.ip, Count: s.msgs, Disposition: report.DispositionNone,
			DKIM: s.dkim, SPF: s.spf, HeaderFrom: domain,
			DKIMDomains: s.dkimDomains,
		}
		if s.spfDomain != "" {
			rec.SPFDomains = []string{s.spfDomain}
		}
		records = append(records, rec)
	}
	return records
}

// forgedFleet is what a spoofing campaign looks like: many addresses, no
// signature, the envelope forged as the policy domain, one or two messages
// each.
func forgedFleet(n int, domain string) []source {
	out := make([]source, 0, n)
	for i := range n {
		out = append(out, source{
			ip:   "203.0.113." + itoa(i+1),
			msgs: int64(1 + i%2),
			dkim: report.AuthFail, spf: report.AuthFail,
			spfDomain: domain,
		})
	}
	return out
}

// steadyFleet is the same campaign seen over weeks rather than days: each
// address keeps coming back, so its total climbs past a handful while its
// daily rate stays tiny.
func steadyFleet(n int, domain string, minMsgs, spread int64) []source {
	out := make([]source, 0, n)
	for i := range n {
		out = append(out, source{
			ip:   "198.18." + itoa(i/250) + "." + itoa(i%250+1),
			msgs: minMsgs + int64(i)%spread,
			dkim: report.AuthFail, spf: report.AuthFail,
			spfDomain: domain,
		})
	}
	return out
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func TestDiagnoseScenarios(t *testing.T) {
	const dom = "example.ca"

	healthy := source{ip: "192.0.2.1", msgs: 500, dkim: report.AuthPass, spf: report.AuthPass,
		dkimDomains: []string{dom}, spfDomain: dom}

	tests := []struct {
		name        string
		policy      string
		days        int
		sources     []source
		wantFinding Finding
		wantKinds   map[Kind]int
		wantSafe    bool
		wantNext    string
		headlineHas string
	}{
		{
			name: "forgery against a healthy domain", policy: "none", days: 7,
			sources:     append([]source{healthy}, forgedFleet(40, dom)...),
			wantFinding: FindingForgery,
			wantKinds:   map[Kind]int{KindPassing: 1, KindForged: 40},
			wantSafe:    true, wantNext: "quarantine",
			headlineHas: "forging your domain",
		},
		{
			name: "an unaligned sender of your own", policy: "none", days: 30,
			sources: []source{
				healthy,
				// Identifies itself with its own bounce domain: an ESP.
				{ip: "198.51.100.7", msgs: 900, dkim: report.AuthFail, spf: report.AuthFail,
					spfDomain: "bounce.example-sender.net"},
			},
			wantFinding: FindingUnaligned,
			wantKinds:   map[Kind]int{KindPassing: 1, KindUnaligned: 1},
			wantSafe:    false,
			headlineHas: "not aligned",
		},
		{
			name: "a sender whose signature does not verify", policy: "none", days: 30,
			sources: []source{
				healthy,
				{ip: "198.51.100.8", msgs: 300, dkim: report.AuthFail, spf: report.AuthFail,
					dkimDomains: []string{dom}, spfDomain: dom},
			},
			wantFinding: FindingUnaligned,
			wantKinds:   map[Kind]int{KindPassing: 1, KindUnaligned: 1},
			wantSafe:    false,
		},
		{
			name: "both at once", policy: "none", days: 30,
			sources: append([]source{
				healthy,
				{ip: "198.51.100.7", msgs: 900, dkim: report.AuthFail, spf: report.AuthFail,
					spfDomain: "bounce.example-sender.net"},
			}, forgedFleet(30, dom)...),
			wantFinding: FindingForgery,
			wantKinds:   map[Kind]int{KindPassing: 1, KindUnaligned: 1, KindForged: 30},
			wantSafe:    false,
			headlineHas: "forging your domain, and 1 sender of yours is not aligned",
		},
		{
			name: "a few unattributed sources are not called forgery", policy: "none", days: 30,
			sources: []source{
				healthy,
				// One address, real volume, claims your domain, unsigned.
				// That is far more likely a server you forgot than a fleet.
				{ip: "198.51.100.9", msgs: 240, dkim: report.AuthFail, spf: report.AuthFail,
					spfDomain: dom},
			},
			wantFinding: FindingUnknowns,
			wantKinds:   map[Kind]int{KindPassing: 1, KindUnidentified: 1},
			wantSafe:    false,
			headlineHas: "could not be identified",
		},
		{
			name: "healthy, nothing to do", policy: "quarantine", days: 30,
			sources:     []source{healthy},
			wantFinding: FindingHealthy,
			wantKinds:   map[Kind]int{KindPassing: 1},
			wantSafe:    true, wantNext: "reject",
			headlineHas: "Everything authenticates",
		},
		{
			name: "forwarded mail is normal", policy: "none", days: 30,
			sources: []source{
				healthy,
				{ip: "198.51.100.20", msgs: 60, dkim: report.AuthPass, spf: report.AuthFail,
					dkimDomains: []string{dom}, spfDomain: "forwarder.example.net"},
			},
			wantFinding: FindingForwarding,
			wantKinds:   map[Kind]int{KindPassing: 1, KindForwarded: 1},
			wantSafe:    true, wantNext: "quarantine",
		},
		{
			// A real run: 24 days, 300 addresses at 3 to 12 messages each.
			// Each one cleared the old fixed limit of 2 and the fleet went
			// unrecognised.
			name: "steady forgery over a long window", policy: "quarantine", days: 24,
			sources:     append([]source{healthy}, steadyFleet(300, dom, 3, 10)...),
			wantFinding: FindingForgery,
			wantKinds:   map[Kind]int{KindPassing: 1, KindForged: 300},
			wantSafe:    true, wantNext: "reject",
			headlineHas: "forging your domain",
		},
		{
			// Ten servers at two a day each is a farm of your own that SPF
			// forgot, not a fleet of forgers.
			name: "a few busy unsigned servers are not called forgery", policy: "none", days: 30,
			sources:     append([]source{healthy}, steadyFleet(10, dom, 60, 1)...),
			wantFinding: FindingUnknowns,
			wantKinds:   map[Kind]int{KindPassing: 1, KindUnidentified: 10},
			wantSafe:    false,
		},
		{
			name: "already at reject", policy: "reject", days: 30,
			sources:     append([]source{healthy}, forgedFleet(20, dom)...),
			wantFinding: FindingForgery,
			wantSafe:    true, wantNext: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := Run(build(t, tc.policy, dom, tc.days, tc.sources...))

			if !d.Has(tc.wantFinding) {
				t.Errorf("findings = %v, want it to include %q", d.Findings, tc.wantFinding)
			}
			for kind, want := range tc.wantKinds {
				if got := d.Group(kind).Count(); got != want {
					t.Errorf("%s sources = %d, want %d", kind, got, want)
				}
			}
			if d.Readiness.Safe != tc.wantSafe {
				t.Errorf("readiness safe = %v, want %v (%s)",
					d.Readiness.Safe, tc.wantSafe, d.Readiness.Reason)
			}
			if tc.wantNext != "" && d.Readiness.Next != tc.wantNext {
				t.Errorf("next policy = %q, want %q", d.Readiness.Next, tc.wantNext)
			}
			if tc.headlineHas != "" && !strings.Contains(d.Headline, tc.headlineHas) {
				t.Errorf("headline = %q, want it to mention %q", d.Headline, tc.headlineHas)
			}
			if d.Headline == "" {
				t.Error("every diagnosis needs a headline")
			}
		})
	}
}

// TestForgeryDoesNotMoveTheOwnRate is the point of the whole package: an
// attacker controls the headline rate and must not control the number the
// reader acts on.
func TestForgeryDoesNotMoveTheOwnRate(t *testing.T) {
	const dom = "example.ca"
	healthy := source{ip: "192.0.2.1", msgs: 100, dkim: report.AuthPass, spf: report.AuthPass,
		dkimDomains: []string{dom}, spfDomain: dom}

	clean := Run(build(t, "none", dom, 7, healthy))
	spoofed := Run(build(t, "none", dom, 7, append([]source{healthy}, forgedFleet(150, dom)...)...))

	if clean.OwnRate() != 1 || spoofed.OwnRate() != 1 {
		t.Fatalf("own rate moved under forgery: %.3f then %.3f", clean.OwnRate(), spoofed.OwnRate())
	}
	if spoofed.HeadlineRate >= clean.HeadlineRate {
		t.Fatalf("the headline rate should fall under forgery: %.3f then %.3f",
			clean.HeadlineRate, spoofed.HeadlineRate)
	}
	// And the advice must still be "tighten", not "fix your senders".
	if !spoofed.Readiness.Safe {
		t.Fatalf("tightening must stay safe under forgery: %s", spoofed.Readiness.Reason)
	}
	var titles []string
	for _, a := range spoofed.Actions {
		titles = append(titles, a.Title)
	}
	joined := strings.Join(titles, " | ")
	if !strings.Contains(joined, "Move the policy from p=none to p=quarantine") {
		t.Fatalf("actions = %s, want the policy move first", joined)
	}
}

func TestTinyLimitScalesWithTheWindow(t *testing.T) {
	tests := []struct {
		days int
		want int64
	}{
		{0, dispersedTinyMsgs},
		{1, dispersedTinyMsgs},
		{7, 4},
		{24, 12},
		{31, 16},
	}
	for _, tc := range tests {
		if got := tinyLimit(tc.days); got != tc.want {
			t.Errorf("tinyLimit(%d) = %d, want %d", tc.days, got, tc.want)
		}
	}
}

func TestDispersionEvidenceNamesTheWindow(t *testing.T) {
	const dom = "example.ca"
	healthy := source{ip: "192.0.2.1", msgs: 100, dkim: report.AuthPass, spf: report.AuthPass,
		dkimDomains: []string{dom}, spfDomain: dom}
	d := Run(build(t, "none", dom, 24, append([]source{healthy}, steadyFleet(50, dom, 3, 10)...)...))

	joined := strings.Join(d.Evidence, " | ")
	if !strings.Contains(joined, "50 of 50 sent 12 messages or fewer over 24 days") {
		t.Fatalf("evidence = %s", joined)
	}
}

// TestPolicyChangedInTheRange is a domain tightened part-way through the
// reports: the advice must start from the policy in force now, not from a
// list of every policy the range ever saw.
func TestPolicyChangedInTheRange(t *testing.T) {
	const dom = "example.ca"
	healthy := source{ip: "192.0.2.1", msgs: 100, dkim: report.AuthPass, spf: report.AuthPass,
		dkimDomains: []string{dom}, spfDomain: dom}
	unknown := source{ip: "198.51.100.9", msgs: 240, dkim: report.AuthFail, spf: report.AuthFail,
		spfDomain: dom}

	tests := []struct {
		name      string
		sources   []source
		wantTitle string
	}{
		{
			name:      "safe to tighten again",
			sources:   append([]source{healthy}, forgedFleet(40, dom)...),
			wantTitle: "Move the policy from p=quarantine to p=reject",
		},
		{
			name:      "hold where it is now",
			sources:   []source{healthy, unknown},
			wantTitle: "Leave the policy at p=quarantine for now",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := buildReports(t, dom,
				period{policy: "none", from: 0, days: 10},
				period{policy: "quarantine", from: 10, days: 14, sources: tc.sources})
			d := Run(res)

			if d.Readiness.Current != "quarantine" {
				t.Fatalf("current policy = %q, want quarantine", d.Readiness.Current)
			}
			var titles []string
			for _, a := range d.Actions {
				titles = append(titles, a.Title)
			}
			if joined := strings.Join(titles, " | "); !strings.Contains(joined, tc.wantTitle) {
				t.Fatalf("actions = %s, want %q", joined, tc.wantTitle)
			}
		})
	}
}

func TestThinSampleIsCalledOut(t *testing.T) {
	const dom = "example.ca"
	d := Run(build(t, "none", dom, 3,
		source{ip: "192.0.2.1", msgs: 12, dkim: report.AuthPass, spf: report.AuthPass,
			dkimDomains: []string{dom}, spfDomain: dom}))

	if !d.Readiness.Safe {
		t.Fatal("a clean run should still be safe to tighten")
	}
	if len(d.Readiness.Caveats) < 2 {
		t.Fatalf("want caveats about both the window and the volume, got %v", d.Readiness.Caveats)
	}
	joined := strings.Join(d.Readiness.Caveats, " ")
	if !strings.Contains(joined, "3 days") || !strings.Contains(joined, "thin sample") {
		t.Errorf("caveats = %v", d.Readiness.Caveats)
	}
}

func TestEmptyRunSaysNothing(t *testing.T) {
	d := Run(aggregate.New().Result(1))
	if !d.Has(FindingNoData) {
		t.Fatalf("findings = %v", d.Findings)
	}
	if d.Readiness.Safe {
		t.Error("an empty run cannot be safe to tighten")
	}
	if len(d.Actions) != 0 {
		t.Errorf("an empty run should recommend nothing, got %v", d.Actions)
	}
}

func TestAligns(t *testing.T) {
	tests := []struct {
		name     string
		envelope string
		domains  []string
		want     bool
	}{
		{"exact", "example.ca", []string{"example.ca"}, true},
		{"subdomain", "bounce.example.ca", []string{"example.ca"}, true},
		{"deep subdomain", "a.b.example.ca", []string{"example.ca"}, true},
		{"trailing dot", "example.ca.", []string{"example.ca"}, true},
		{"case", "EXAMPLE.CA", []string{"example.ca"}, true},
		{"third party", "bounce.sendgrid.net", []string{"example.ca"}, false},
		{"suffix trick", "notexample.ca", []string{"example.ca"}, false},
		{"empty policy", "example.ca", nil, false},
		{"one of several", "example.org", []string{"example.ca", "example.org"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := aligns(tc.envelope, tc.domains); got != tc.want {
				t.Fatalf("aligns(%q, %v) = %v, want %v", tc.envelope, tc.domains, got, tc.want)
			}
		})
	}
}

func TestDispersionThreshold(t *testing.T) {
	const dom = "example.ca"
	healthy := source{ip: "192.0.2.1", msgs: 100, dkim: report.AuthPass, spf: report.AuthPass,
		dkimDomains: []string{dom}, spfDomain: dom}

	tests := []struct {
		name     string
		n        int
		wantKind Kind
	}{
		{"below the source floor", dispersedMinSources - 1, KindUnidentified},
		{"at the source floor", dispersedMinSources, KindForged},
		{"well above", 60, KindForged},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := Run(build(t, "none", dom, 30, append([]source{healthy}, forgedFleet(tc.n, dom)...)...))
			if got := d.Group(tc.wantKind).Count(); got != tc.n {
				t.Fatalf("%s = %d, want %d", tc.wantKind, got, tc.n)
			}
		})
	}
}

func TestEveryActionHasBothPieces(t *testing.T) {
	const dom = "example.ca"
	d := Run(build(t, "none", dom, 30, append([]source{
		{ip: "192.0.2.1", msgs: 100, dkim: report.AuthPass, spf: report.AuthPass,
			dkimDomains: []string{dom}, spfDomain: dom},
		{ip: "198.51.100.7", msgs: 900, dkim: report.AuthFail, spf: report.AuthFail,
			spfDomain: "bounce.example-sender.net"},
		{ip: "198.51.100.8", msgs: 40, dkim: report.AuthFail, spf: report.AuthPass,
			spfDomain: dom},
	}, forgedFleet(30, dom)...)...))

	if len(d.Actions) == 0 {
		t.Fatal("want actions")
	}
	for i, a := range d.Actions {
		if strings.TrimSpace(a.Title) == "" || strings.TrimSpace(a.Detail) == "" {
			t.Errorf("action %d is incomplete: %+v", i, a)
		}
		if !strings.HasSuffix(strings.TrimSpace(a.Detail), ".") {
			t.Errorf("action %d detail should be a sentence: %q", i, a.Detail)
		}
	}
}
