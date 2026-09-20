package aggregate

import (
	"math"
	"strings"
	"testing"
	"time"

	"franking/internal/report"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		name string
		src  *Source
		want Class
	}{
		{"everything passes", &Source{Messages: 10, DKIMPass: 10, SPFPass: 10, DMARCPass: 10}, ClassPass},
		{"dkim only", &Source{Messages: 10, DKIMPass: 10, SPFPass: 0, DMARCPass: 10}, ClassDKIMOnly},
		{"spf only", &Source{Messages: 10, DKIMPass: 0, SPFPass: 10, DMARCPass: 10}, ClassSPFOnly},
		{"partial", &Source{Messages: 10, DKIMPass: 4, SPFPass: 0, DMARCPass: 4}, ClassPartial},
		{"nothing passes", &Source{Messages: 10, DKIMPass: 0, SPFPass: 0, DMARCPass: 0}, ClassFail},
		{"mixed but complete", &Source{Messages: 10, DKIMPass: 6, SPFPass: 4, DMARCPass: 10}, ClassPass},
		{"no messages", &Source{Messages: 0}, ClassFail},
		{"nil source", nil, ClassFail},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.src); got != tc.want {
				t.Fatalf("Classify() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestEveryClassHasAnAction(t *testing.T) {
	for _, c := range Classes() {
		if c.Action() == "" {
			t.Errorf("class %q has no action text", c)
		}
	}
	if len(Classes()) != 5 {
		t.Fatalf("want five classes, got %d", len(Classes()))
	}
}

func TestAddReportKeysOnTheSourceAddress(t *testing.T) {
	agg := New()
	agg.AddFile(agg.AddReport("first.xml", reportWith("google.com", "example.ca",
		1700000000, 1700086400,
		record("203.0.113.10", 40, report.AuthPass, report.AuthFail, "example.ca", "mail.vendor.net"),
		record("192.0.2.1", 10, report.AuthFail, report.AuthFail, "", "other.vendor.net"),
	)))
	agg.AddFile(agg.AddReport("second.xml", reportWith("Yahoo", "example.ca",
		1700086400, 1700172800,
		record("203.0.113.10", 60, report.AuthFail, report.AuthPass, "example.ca", "relay.vendor.net"),
	)))

	res := agg.Result(1)
	if len(res.Sources) != 2 {
		t.Fatalf("sources = %d, want 2", len(res.Sources))
	}
	top := res.Sources[0]
	if top.IP != "203.0.113.10" {
		t.Fatalf("sorted first = %q, want the busiest address", top.IP)
	}
	if top.Messages != 100 || top.DKIMPass != 40 || top.SPFPass != 60 || top.DMARCPass != 100 {
		t.Fatalf("counts = %+v", top)
	}
	if got := strings.Join(top.SPFDomains(), ","); got != "mail.vendor.net,relay.vendor.net" {
		t.Fatalf("spf domains = %q", got)
	}
	if got := strings.Join(top.Orgs(), ","); got != "Yahoo,google.com" {
		t.Fatalf("orgs = %q", got)
	}
	if top.FirstSeen.Unix() != 1700000000 || top.LastSeen.Unix() != 1700172800 {
		t.Fatalf("seen range = %v to %v", top.FirstSeen, top.LastSeen)
	}
	if res.Totals.Messages != 110 || res.Totals.DMARCPass != 100 {
		t.Fatalf("totals = %+v", res.Totals)
	}
	if got := res.Totals.PassRate(); math.Abs(got-100.0/110.0) > 1e-9 {
		t.Fatalf("pass rate = %v", got)
	}
	if res.Begin.Unix() != 1700000000 || res.End.Unix() != 1700172800 {
		t.Fatalf("range = %v to %v", res.Begin, res.End)
	}
}

func TestResultCountsFileStatuses(t *testing.T) {
	agg := New()
	agg.AddFile(FileResult{Name: "ok.xml", Status: StatusOK})
	agg.AddFile(FileResult{Name: "skip.xml", Status: StatusSkipped, Reason: "out of range"})
	agg.AddFile(FileResult{Name: "bad.xml", Status: StatusError, Reason: "xml: parse error"})
	agg.AddFile(FileResult{Name: "bad2.xml", Status: StatusError, Reason: "xml: parse error"})

	res := agg.Result(1)
	if res.FilesFound != 4 || res.FilesParsed != 1 || res.FilesSkipped != 1 || res.FilesError != 2 {
		t.Fatalf("counts = %d/%d/%d/%d",
			res.FilesFound, res.FilesParsed, res.FilesSkipped, res.FilesError)
	}
}

func TestResultHidesSourcesBelowMinCount(t *testing.T) {
	agg := New()
	agg.AddReport("r.xml", reportWith("org", "example.ca", 1, 2,
		record("203.0.113.1", 100, report.AuthPass, report.AuthPass, "example.ca", "example.ca"),
		record("203.0.113.2", 2, report.AuthFail, report.AuthFail, "", "vendor.net"),
	))

	res := agg.Result(10)
	if len(res.Sources) != 1 || res.Sources[0].IP != "203.0.113.1" {
		t.Fatalf("sources = %+v", res.Sources)
	}
	if res.Totals.Messages != 102 {
		t.Fatalf("totals must still count the hidden source, got %d", res.Totals.Messages)
	}
}

func TestSourceLimit(t *testing.T) {
	agg := NewWithLimit(3)
	recs := []report.Record{
		record("192.0.2.1", 1, report.AuthPass, report.AuthPass, "", ""),
		record("192.0.2.2", 1, report.AuthPass, report.AuthPass, "", ""),
		record("192.0.2.3", 1, report.AuthPass, report.AuthPass, "", ""),
		record("192.0.2.4", 1, report.AuthPass, report.AuthPass, "", ""),
		record("192.0.2.5", 1, report.AuthPass, report.AuthPass, "", ""),
	}
	agg.AddReport("r.xml", reportWith("org", "example.ca", 1, 2, recs...))

	res := agg.Result(1)
	if len(res.Sources) != 3 {
		t.Fatalf("sources = %d, want the limit of 3", len(res.Sources))
	}
	if !res.Truncated {
		t.Fatal("want the result marked as truncated")
	}
	if len(res.Warnings) == 0 {
		t.Fatal("want a warning about the dropped addresses")
	}
}

func TestCountsSaturateRatherThanWrap(t *testing.T) {
	agg := New()
	huge := int64(1) << 31
	var recs []report.Record
	for range 8 {
		recs = append(recs, record("203.0.113.1", huge, report.AuthPass, report.AuthPass, "", ""))
	}
	agg.AddReport("r.xml", reportWith("org", "example.ca", 1, 2, recs...))

	res := agg.Result(1)
	if res.Sources[0].Messages < 0 || res.Totals.Messages < 0 {
		t.Fatalf("a total wrapped negative: %+v", res.Totals)
	}
}

func TestPassRateOfAnEmptyRun(t *testing.T) {
	res := New().Result(1)
	if res.Totals.PassRate() != 0 {
		t.Fatalf("pass rate = %v, want 0", res.Totals.PassRate())
	}
	if len(res.Sources) != 0 {
		t.Fatalf("sources = %v", res.Sources)
	}
}

func TestFileResultStringsAreSanitized(t *testing.T) {
	agg := New()
	agg.AddFile(FileResult{Name: "../../etc/pa\x1bsswd.xml", Reason: "bad\x00reason", Status: StatusError})
	res := agg.Result(1)
	if res.Files[0].Name != "passwd.xml" {
		t.Fatalf("name = %q", res.Files[0].Name)
	}
	if res.Files[0].Reason != "badreason" {
		t.Fatalf("reason = %q", res.Files[0].Reason)
	}
}

func TestSourceRates(t *testing.T) {
	s := &Source{Messages: 4, DKIMPass: 1}
	if got := s.Rate(s.DKIMPass); got != 0.25 {
		t.Fatalf("rate = %v", got)
	}
	empty := &Source{}
	if got := empty.Rate(5); got != 0 {
		t.Fatalf("rate of an empty source = %v", got)
	}
	if got := empty.PrimarySPFDomain(); got != "" {
		t.Fatalf("primary spf domain = %q", got)
	}
}

// --- helpers -------------------------------------------------------------

func reportWith(org, domain string, begin, end int64, records ...report.Record) *report.Report {
	return &report.Report{
		Metadata: report.Metadata{
			Org:      org,
			ReportID: "id",
			Range: report.DateRange{
				Begin: time.Unix(begin, 0),
				End:   time.Unix(end, 0),
			},
		},
		Policy:  report.Policy{Domain: domain, P: "none"},
		Records: records,
	}
}

func record(ip string, count int64, dkim, spf report.AuthResult, dkimDomain, spfDomain string) report.Record {
	rec := report.Record{
		SourceIP:    ip,
		Count:       count,
		Disposition: report.DispositionNone,
		DKIM:        dkim,
		SPF:         spf,
		HeaderFrom:  "example.ca",
	}
	if dkimDomain != "" {
		rec.DKIMDomains = []string{dkimDomain}
	}
	if spfDomain != "" {
		rec.SPFDomains = []string{spfDomain}
	}
	return rec
}
