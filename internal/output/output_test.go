package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/scottbrown/franking/internal/aggregate"
	"github.com/scottbrown/franking/internal/report"
)

func TestParseFormat(t *testing.T) {
	tests := []struct {
		in      string
		want    Format
		wantErr bool
	}{
		{"text", FormatText, false},
		{"TEXT", FormatText, false},
		{" json ", FormatJSON, false},
		{"csv", FormatCSV, false},
		{"yaml", "", true},
		{"", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseFormat(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseFormat(%q) = %q, want an error", tc.in, got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("ParseFormat(%q) = %q, %v", tc.in, got, err)
			}
		})
	}
}

func TestWriteTextHoldsNoControlBytes(t *testing.T) {
	res := hostileResult()
	var buf bytes.Buffer
	if err := Write(&buf, FormatText, res, Options{ShowFiles: true, Resolve: true}); err != nil {
		t.Fatal(err)
	}
	assertPrintable(t, buf.Bytes())
	for _, want := range []string{"Run summary", "Diagnosis", "Files", "Sources", "What to do", "Policy: p="} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("output is missing the %q block:\n%s", want, buf.String())
		}
	}
}

func TestWriteTextShowsFilesOnlyOnRequestOrOnError(t *testing.T) {
	res := simpleResult()
	res.Files = append(res.Files, aggregate.FileResult{
		Name: "broken.xml", Status: aggregate.StatusError, Reason: "xml: parse error",
	})
	res.FilesError = 1

	var quiet bytes.Buffer
	if err := WriteText(&quiet, res, Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(quiet.String(), "broken.xml") {
		t.Fatal("an error row must print even without -files")
	}
	if strings.Contains(quiet.String(), "good.xml") {
		t.Fatal("a healthy row must not print without -files")
	}

	var full bytes.Buffer
	if err := WriteText(&full, res, Options{ShowFiles: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(full.String(), "good.xml") {
		t.Fatal("-files must print every row")
	}
}

func TestWriteTextPolicyLine(t *testing.T) {
	// A clean run: the close should point at the next policy step.
	clean := aggregate.New()
	clean.AddFile(clean.AddReport("clean.xml", &report.Report{
		Metadata: report.Metadata{Org: "google.com", Range: report.DateRange{
			Begin: time.Unix(1700000000, 0), End: time.Unix(1702592000, 0)}},
		Policy: report.Policy{Domain: "example.ca", P: "none"},
		Records: []report.Record{{
			SourceIP: "203.0.113.10", Count: 400,
			Disposition: report.DispositionNone,
			DKIM:        report.AuthPass, SPF: report.AuthPass,
			DKIMDomains: []string{"example.ca"}, SPFDomains: []string{"example.ca"},
		}},
	}))
	var buf bytes.Buffer
	if err := WriteText(&buf, clean.Result(1), Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "move to p=quarantine") {
		t.Fatalf("want the next policy step, got:\n%s", buf.String())
	}

	// A run with a sender of your own still failing: do not move.
	broken := simpleResult()
	buf.Reset()
	if err := WriteText(&buf, broken, Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "should not move yet") {
		t.Fatalf("want the hold verdict, got:\n%s", buf.String())
	}
}

// TestWriteTextSeparatesOwnRateFromHeadline is the reason the diagnosis
// exists: a forger drives the headline rate down, and the close must not
// let that read as the reader's own configuration being broken.
func TestWriteTextSeparatesOwnRateFromHeadline(t *testing.T) {
	agg := aggregate.New()
	records := []report.Record{{
		SourceIP: "203.0.113.10", Count: 100,
		Disposition: report.DispositionNone,
		DKIM:        report.AuthPass, SPF: report.AuthPass,
		DKIMDomains: []string{"example.ca"}, SPFDomains: []string{"example.ca"},
	}}
	for i := range 40 {
		records = append(records, report.Record{
			SourceIP: fmt.Sprintf("198.51.100.%d", i+1), Count: 2,
			Disposition: report.DispositionNone,
			DKIM:        report.AuthFail, SPF: report.AuthFail,
			SPFDomains: []string{"example.ca"},
		})
	}
	agg.AddFile(agg.AddReport("r.xml", &report.Report{
		Metadata: report.Metadata{Org: "google.com", Range: report.DateRange{
			Begin: time.Unix(1700000000, 0), End: time.Unix(1702592000, 0)}},
		Policy:  report.Policy{Domain: "example.ca", P: "none"},
		Records: records,
	}))

	var buf bytes.Buffer
	if err := WriteText(&buf, agg.Result(1), Options{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "forging your domain") {
		t.Errorf("want the forgery headline, got:\n%s", out)
	}
	if !strings.Contains(out, "100.0% over your own senders") {
		t.Errorf("want the own-sender rate stated separately, got:\n%s", out)
	}
	if !strings.Contains(out, "move to p=quarantine") {
		t.Errorf("forgery is a reason to tighten, not to hold, got:\n%s", out)
	}
	if strings.Contains(out, "resolve the sources above before moving") {
		t.Error("the old advice told the reader to fix mail that was never theirs")
	}
}

func TestWriteJSONIsValid(t *testing.T) {
	res := hostileResult()
	var buf bytes.Buffer
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	if err := Write(&buf, FormatJSON, res, Options{Now: now}); err != nil {
		t.Fatal(err)
	}

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	for _, key := range []string{"generated_at", "files", "range", "totals", "sources"} {
		if _, ok := doc[key]; !ok {
			t.Errorf("JSON is missing %q", key)
		}
	}
	sources, ok := doc["sources"].([]any)
	if !ok || len(sources) == 0 {
		t.Fatalf("sources = %v", doc["sources"])
	}
	first, ok := sources[0].(map[string]any)
	if !ok {
		t.Fatalf("source is not an object: %v", sources[0])
	}
	for _, key := range []string{"ip", "messages", "dkim_pass", "spf_pass", "dmarc_pass",
		"class", "spf_domains", "dispositions", "first_seen", "last_seen"} {
		if _, ok := first[key]; !ok {
			t.Errorf("source is missing %q", key)
		}
	}
	assertPrintable(t, buf.Bytes())
}

func TestWriteCSVEscapesEveryFormulaCell(t *testing.T) {
	res := hostileResult()
	var buf bytes.Buffer
	if err := Write(&buf, FormatCSV, res, Options{Resolve: true}); err != nil {
		t.Fatal(err)
	}

	rows, err := csv.NewReader(bytes.NewReader(buf.Bytes())).ReadAll()
	if err != nil {
		t.Fatalf("output is not valid CSV: %v", err)
	}
	if len(rows) < 2 {
		t.Fatalf("want a header and at least one row, got %d rows", len(rows))
	}
	for _, row := range rows {
		for i, cell := range row {
			if cell == "" {
				continue
			}
			switch cell[0] {
			case '=', '+', '-', '@', '\t', '\r':
				t.Fatalf("cell %d %q was not escaped", i, cell)
			}
		}
	}
	if !strings.Contains(buf.String(), "'-rogue.example.ca") {
		t.Fatalf("want the leading dash escaped:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "'=cmd") {
		t.Fatalf("want the formula escaped:\n%s", buf.String())
	}
}

func TestWriteCSVHeaderFollowsResolve(t *testing.T) {
	res := simpleResult()
	var plain, resolved bytes.Buffer
	if err := WriteCSV(&plain, res, Options{}); err != nil {
		t.Fatal(err)
	}
	if err := WriteCSV(&resolved, res, Options{Resolve: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.SplitN(plain.String(), "\n", 2)[0], "host") {
		t.Fatal("the host column must appear only with -resolve")
	}
	if !strings.Contains(strings.SplitN(resolved.String(), "\n", 2)[0], "host") {
		t.Fatal("-resolve must add the host column")
	}
}

func TestWriteDefaultsToText(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, Format("nonsense"), simpleResult(), Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "Run summary") {
		t.Fatal("an unknown format must fall back to text")
	}
}

// --- helpers -------------------------------------------------------------

func assertPrintable(t *testing.T, b []byte) {
	t.Helper()
	for i, c := range b {
		if c < 0x20 && c != '\n' && c != '\t' {
			t.Fatalf("byte %d is a control character 0x%02x", i, c)
		}
	}
}

func simpleResult() *aggregate.Result {
	agg := aggregate.New()
	agg.AddFile(agg.AddReport("good.xml", &report.Report{
		Metadata: report.Metadata{
			Org:      "google.com",
			ReportID: "1",
			Range: report.DateRange{
				Begin: time.Unix(1700000000, 0),
				End:   time.Unix(1700086400, 0),
			},
		},
		Policy: report.Policy{Domain: "example.ca", P: "none"},
		Records: []report.Record{{
			SourceIP: "203.0.113.10", Count: 10,
			Disposition: report.DispositionNone,
			DKIM:        report.AuthPass, SPF: report.AuthFail,
			SPFDomains: []string{"mail.vendor.net"},
		}, {
			SourceIP: "198.51.100.1", Count: 5,
			Disposition: report.DispositionReject,
			DKIM:        report.AuthFail, SPF: report.AuthFail,
			SPFDomains: []string{"bulk.example-sender.net"},
		}},
	}))
	return agg.Result(1)
}

// hostileResult holds the strings that a crafted report would carry, after
// the parser has sanitized them.
func hostileResult() *aggregate.Result {
	agg := aggregate.New()
	agg.AddFile(agg.AddReport("crafted.xml", &report.Report{
		Metadata: report.Metadata{
			Org:      "=cmd|' /c calc'!A0",
			ReportID: "@SUM(1+1)",
			Range: report.DateRange{
				Begin: time.Unix(1700000000, 0),
				End:   time.Unix(1700086400, 0),
			},
		},
		Policy: report.Policy{Domain: "example.ca", P: "none"},
		Records: []report.Record{{
			SourceIP: "203.0.113.202", Count: 6,
			Disposition: report.DispositionNone,
			DKIM:        report.AuthFail, SPF: report.AuthPass,
			SPFDomains:  []string{"-rogue.example.ca"},
			DKIMDomains: []string{"+plus.example.ca"},
		}, {
			SourceIP: "invalid", Count: 4,
			Disposition: report.DispositionUnknown,
			DKIM:        report.AuthUnknown, SPF: report.AuthUnknown,
		}},
	}))
	agg.AddFile(aggregate.FileResult{
		Name: "broken.xml", Status: aggregate.StatusError, Reason: "xml: syntax error at line 3",
	})
	res := agg.Result(1)
	res.Sources[0].Host = "host.example.ca"
	return res
}
