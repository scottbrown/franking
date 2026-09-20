package report

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const minimalReport = `<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply@google.com</email>
    <report_id>1234567890</report_id>
    <date_range><begin>1700000000</begin><end>1700086400</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.ca</domain><adkim>r</adkim><aspf>r</aspf>
    <p>none</p><sp>none</sp><pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>203.0.113.10</source_ip>
      <count>42</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>fail</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.ca</header_from></identifiers>
    <auth_results>
      <dkim><domain>example.ca</domain><selector>s1</selector><result>pass</result></dkim>
      <spf><domain>mail.vendor.net</domain><result>pass</result></spf>
    </auth_results>
  </record>
</feedback>`

func TestParseMinimalReport(t *testing.T) {
	rep, err := Parse(strings.NewReader(minimalReport))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if rep.Metadata.Org != "google.com" {
		t.Errorf("org = %q", rep.Metadata.Org)
	}
	if rep.Metadata.ReportID != "1234567890" {
		t.Errorf("report id = %q", rep.Metadata.ReportID)
	}
	if rep.Policy.Domain != "example.ca" || rep.Policy.P != "none" {
		t.Errorf("policy = %+v", rep.Policy)
	}
	if got := rep.Metadata.Range.Begin.Unix(); got != 1700000000 {
		t.Errorf("begin = %d", got)
	}
	if len(rep.Records) != 1 {
		t.Fatalf("records = %d, want 1", len(rep.Records))
	}
	rec := rep.Records[0]
	if rec.SourceIP != "203.0.113.10" || rec.Count != 42 {
		t.Errorf("record = %+v", rec)
	}
	if rec.DKIM != AuthPass || rec.SPF != AuthFail {
		t.Errorf("aligned results = %s/%s", rec.DKIM, rec.SPF)
	}
	if !rec.DMARCPass() {
		t.Error("DKIM aligned pass must give a DMARC pass")
	}
	if got := rep.Messages(); got != 42 {
		t.Errorf("messages = %d", got)
	}
}

func TestParseSampleFiles(t *testing.T) {
	tests := []struct {
		file        string
		wantOrg     string
		wantRecords int
		wantSPFDoms []string
	}{
		{"multi-dkim.xml", "mailer.example.ca", 1,
			[]string{"bounce.example-sender.net", "relay.example-sender.net"}},
	}
	for _, tc := range tests {
		t.Run(tc.file, func(t *testing.T) {
			f, err := os.Open(filepath.Join("..", "..", "testdata", "reports", tc.file))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			rep, err := Parse(f)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if rep.Metadata.Org != tc.wantOrg {
				t.Errorf("org = %q, want %q", rep.Metadata.Org, tc.wantOrg)
			}
			if len(rep.Records) != tc.wantRecords {
				t.Fatalf("records = %d, want %d", len(rep.Records), tc.wantRecords)
			}
			got := strings.Join(rep.Records[0].SPFDomains, ",")
			if got != strings.Join(tc.wantSPFDoms, ",") {
				t.Errorf("spf domains = %q", got)
			}
		})
	}
}

func TestParseKeepsEveryDKIMElement(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "..", "testdata", "reports", "multi-dkim.xml"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rep, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	got := rep.Records[0].DKIMDomains
	want := []string{"example.ca", "newsletter.example.ca", "third-party.example.ca"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("dkim domains = %v, want %v", got, want)
	}
}

func TestParseIgnoresUnknownElementsAndOrder(t *testing.T) {
	doc := `<feedback>
	  <version>1.0</version>
	  <something_new><nested>x</nested></something_new>
	  <record>
	    <auth_results><spf><domain>vendor.net</domain><result>pass</result></spf></auth_results>
	    <row><count>3</count><source_ip>192.0.2.1</source_ip>
	      <policy_evaluated><spf>pass</spf><dkim>fail</dkim><disposition>none</disposition></policy_evaluated>
	    </row>
	  </record>
	  <report_metadata><org_name>late.example.ca</org_name></report_metadata>
	</feedback>`
	rep, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if rep.Metadata.Org != "late.example.ca" {
		t.Errorf("org = %q", rep.Metadata.Org)
	}
	if len(rep.Records) != 1 || rep.Records[0].Count != 3 || rep.Records[0].SPF != AuthPass {
		t.Errorf("record = %+v", rep.Records)
	}
}

func TestParseRejects(t *testing.T) {
	deep := nestedDocument(1000)
	tests := []struct {
		name    string
		doc     string
		wantErr error
		wantSub string
	}{
		{"root is not feedback", `<html><feedback/></html>`, ErrNotFeedback, ""},
		{"empty document", ``, ErrEmpty, ""},
		{"unclosed element", `<feedback><record>`, nil, "syntax error"},
		{"undefined entity", `<feedback><record>&boom;</record></feedback>`, nil, "syntax error"},
		{"nested 1000 deep", deep, nil, "nesting deeper than"},
		{"utf-7 declared", `<?xml version="1.0" encoding="UTF-7"?><feedback/>`, ErrCharset, ""},
		{"charset name with a url",
			`<?xml version="1.0" encoding="http://127.0.0.1:8080/x"?><feedback/>`, ErrCharset, ""},
		{"raw escape byte", "<feedback><report_metadata><org_name>\x1b[2J</org_name></report_metadata></feedback>",
			nil, "syntax error"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(tc.doc))
			if err == nil {
				t.Fatal("want an error")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
			if tc.wantSub != "" && !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.wantSub)
			}
			assertNoRawInput(t, err.Error())
		})
	}
}

// assertNoRawInput checks that an error message carries no control byte and
// no quoted element content from the document.
func assertNoRawInput(t *testing.T, msg string) {
	t.Helper()
	for i := range len(msg) {
		if msg[i] < 0x20 {
			t.Fatalf("error message holds a control byte at %d: %q", i, msg)
		}
	}
	if strings.Contains(msg, "<record>") || strings.Contains(msg, "boom") {
		t.Fatalf("error message repeats input content: %q", msg)
	}
}

func TestParseHostileSampleFiles(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "malicious", "reject")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no hostile samples found")
	}
	for _, e := range entries {
		t.Run(e.Name(), func(t *testing.T) {
			f, err := os.Open(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			rep, err := Parse(f)
			if err == nil {
				t.Fatalf("want a rejection, got a report with %d records", len(rep.Records))
			}
			assertNoRawInput(t, err.Error())
		})
	}
}

func TestParseSanitizesUntrustedStrings(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "malicious", "sanitize")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Run(e.Name(), func(t *testing.T) {
			f, err := os.Open(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			rep, err := Parse(f)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			strs := []string{rep.Metadata.Org, rep.Metadata.Email, rep.Metadata.ReportID,
				rep.Policy.Domain, rep.Policy.P}
			for _, rec := range rep.Records {
				strs = append(strs, rec.SourceIP, rec.HeaderFrom)
				strs = append(strs, rec.DKIMDomains...)
				strs = append(strs, rec.SPFDomains...)
			}
			for _, s := range strs {
				for i := range len(s) {
					if s[i] < 0x20 || s[i] == 0x7f {
						t.Fatalf("control byte survived in %q", s)
					}
				}
				if strings.ContainsAny(s, "‪‫‬‭‮⁦⁧⁨⁩") {
					t.Fatalf("bidi character survived in %q", s)
				}
			}
		})
	}
}

// TestExternalEntityReadsNothingAndCallsNobody points an external entity at
// a real file and at a real listening socket, and proves that neither is
// touched.
func TestExternalEntityReadsNothingAndCallsNobody(t *testing.T) {
	const secret = "secret-file-content-that-must-not-leak"

	secretPath := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(secretPath, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen here: %v", err)
	}
	defer listener.Close()

	var accepted atomic.Int64
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			conn.Close()
		}
	}()

	doc := fmt.Sprintf(`<?xml version="1.0"?>
<!DOCTYPE feedback [
  <!ENTITY local SYSTEM "file://%s">
  <!ENTITY remote SYSTEM "http://%s/collect">
]>
<feedback>
  <report_metadata><org_name>&local;</org_name><email>&remote;</email></report_metadata>
</feedback>`, secretPath, listener.Addr().String())

	rep, err := Parse(strings.NewReader(doc))
	if err == nil {
		t.Fatalf("want a rejection, got %+v", rep.Metadata)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("the file content reached the error message")
	}
	time.Sleep(200 * time.Millisecond)
	if n := accepted.Load(); n != 0 {
		t.Fatalf("the parser opened %d connections", n)
	}
}

func TestParseDropsBadCounts(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "..", "testdata", "malicious", "sanitize", "bad-counts.xml"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rep, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	if got := rep.Messages(); got != 17 {
		t.Fatalf("messages = %d, want only the one usable count (17)", got)
	}
	if len(rep.Warnings) == 0 {
		t.Fatal("want a warning about the dropped counts")
	}
}

func TestParseRecordLimit(t *testing.T) {
	var b strings.Builder
	b.WriteString("<feedback>")
	for range 20 {
		b.WriteString(`<record><row><source_ip>192.0.2.1</source_ip><count>1</count></row></record>`)
	}
	b.WriteString("</feedback>")

	_, err := ParseWithLimits(strings.NewReader(b.String()), Limits{MaxDepth: 32, MaxRecords: 5})
	if !errors.Is(err, ErrTooManyRecs) {
		t.Fatalf("error = %v, want %v", err, ErrTooManyRecs)
	}
}

func TestParseDepthLimitAppliesInsideARecord(t *testing.T) {
	var b strings.Builder
	b.WriteString("<feedback><record><row>")
	for range 60 {
		b.WriteString("<x>")
	}
	for range 60 {
		b.WriteString("</x>")
	}
	b.WriteString("</row></record></feedback>")

	_, err := Parse(strings.NewReader(b.String()))
	if err == nil || !strings.Contains(err.Error(), "nesting deeper than") {
		t.Fatalf("error = %v, want a depth rejection", err)
	}
}

func TestParseAcceptsLegacyCharsets(t *testing.T) {
	// 0xE9 is 'é' in ISO-8859-1 and 0x93 is a left quote in windows-1252.
	tests := []struct {
		name string
		doc  []byte
		want string
	}{
		{"iso-8859-1",
			append([]byte(`<?xml version="1.0" encoding="iso-8859-1"?><feedback><report_metadata><org_name>Soci`),
				append([]byte{0xe9}, []byte(`t</org_name></report_metadata></feedback>`)...)...),
			"Société"[:len("Socié")] + "t"},
		{"windows-1252",
			append([]byte(`<?xml version="1.0" encoding="windows-1252"?><feedback><report_metadata><org_name>a`),
				append([]byte{0x93}, []byte(`b</org_name></report_metadata></feedback>`)...)...),
			"a“b"},
		{"us-ascii",
			[]byte(`<?xml version="1.0" encoding="us-ascii"?><feedback><report_metadata><org_name>plain</org_name></report_metadata></feedback>`),
			"plain"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rep, err := Parse(strings.NewReader(string(tc.doc)))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if rep.Metadata.Org != tc.want {
				t.Fatalf("org = %q, want %q", rep.Metadata.Org, tc.want)
			}
		})
	}
}

func TestParseDisposition(t *testing.T) {
	tests := []struct {
		in   string
		want Disposition
	}{
		{"none", DispositionNone},
		{"NONE", DispositionNone},
		{" quarantine ", DispositionQuarantine},
		{"reject", DispositionReject},
		{"drop-everything", DispositionUnknown},
		{"", DispositionUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := ParseDisposition(tc.in); got != tc.want {
				t.Fatalf("ParseDisposition(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseAuthResult(t *testing.T) {
	tests := []struct {
		in   string
		want AuthResult
	}{
		{"pass", AuthPass},
		{"PASS", AuthPass},
		{"fail", AuthFail},
		{"softfail", AuthSoftFail},
		{"temperror", AuthTempError},
		{"nonsense", AuthUnknown},
		{"", AuthUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := ParseAuthResult(tc.in); got != tc.want {
				t.Fatalf("ParseAuthResult(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestEpochRejectsNonsense(t *testing.T) {
	for _, in := range []string{"", "-1", "not-a-time", "999999999999999999"} {
		if got := epoch(in); !got.IsZero() {
			t.Fatalf("epoch(%q) = %v, want the zero time", in, got)
		}
	}
}

// nestedDocument builds a feedback document nested n levels deep.
func nestedDocument(n int) string {
	var b strings.Builder
	b.WriteString("<feedback>")
	for i := range n {
		fmt.Fprintf(&b, "<a%d>", i%10)
	}
	for i := n - 1; i >= 0; i-- {
		fmt.Fprintf(&b, "</a%d>", i%10)
	}
	b.WriteString("</feedback>")
	return b.String()
}
