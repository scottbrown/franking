package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// FuzzParse drives the parser entry point. The target must never panic and
// must always return inside the deadline.
func FuzzParse(f *testing.F) {
	f.Add(minimalReport)
	for _, dir := range []string{
		filepath.Join("..", "..", "testdata", "reports"),
		filepath.Join("..", "..", "testdata", "malicious", "reject"),
		filepath.Join("..", "..", "testdata", "malicious", "sanitize"),
	} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".xml") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			f.Add(string(b))
		}
	}

	f.Fuzz(func(t *testing.T, doc string) {
		type outcome struct {
			rep *Report
			err error
		}
		done := make(chan outcome, 1)
		go func() {
			rep, err := Parse(strings.NewReader(doc))
			done <- outcome{rep, err}
		}()

		var got outcome
		select {
		case got = <-done:
		case <-time.After(20 * time.Second):
			t.Fatal("Parse did not return inside the time limit")
		}
		if got.err != nil {
			assertClean(t, got.err.Error())
			return
		}
		// Whatever comes back must already be sanitized.
		assertClean(t, got.rep.Metadata.Org)
		assertClean(t, got.rep.Metadata.ReportID)
		assertClean(t, got.rep.Policy.Domain)
		for _, rec := range got.rep.Records {
			if rec.Count < 0 || rec.Count > 1<<31 {
				t.Fatalf("count %d survived", rec.Count)
			}
			assertClean(t, rec.SourceIP)
			assertClean(t, rec.HeaderFrom)
			for _, d := range rec.DKIMDomains {
				assertClean(t, d)
			}
			for _, d := range rec.SPFDomains {
				assertClean(t, d)
			}
		}
	})
}

func assertClean(t *testing.T, s string) {
	t.Helper()
	for i := range len(s) {
		if s[i] < 0x20 || s[i] == 0x7f {
			t.Fatalf("control byte survived in %q", s)
		}
	}
}
