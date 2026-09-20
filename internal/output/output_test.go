package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"franking/internal/aggregate"
	"franking/internal/report"
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
	for _, want := range []string{"Run summary", "Files", "Sources", "Actions", "Policy: p="} {
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
	perfect := simpleResult()
	perfect.Totals = aggregate.Totals{Messages: 10, DMARCPass: 10}
	var buf bytes.Buffer
	if err := WriteText(&buf, perfect, Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "at 100%") {
		t.Fatalf("want the 100%% verdict, got:\n%s", buf.String())
	}

	partial := simpleResult()
	buf.Reset()
	if err := WriteText(&buf, partial, Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "below 100%") {
		t.Fatalf("want the below-100%% verdict, got:\n%s", buf.String())
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
