package run

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/scottbrown/franking/internal/aggregate"
	"github.com/scottbrown/franking/internal/output"
)

func TestRunReadsAMixedDirectory(t *testing.T) {
	res := runDir(t, reportsDir(t), func(cfg *Config) {})

	if res.FilesFound != 6 {
		t.Errorf("files found = %d, want 6", res.FilesFound)
	}
	if res.FilesParsed != 4 {
		t.Errorf("files parsed = %d, want 4", res.FilesParsed)
	}
	if res.Totals.Messages != 199 {
		t.Errorf("messages = %d, want 199", res.Totals.Messages)
	}
	if res.Totals.DMARCPass != 181 {
		t.Errorf("dmarc pass = %d, want 181", res.Totals.DMARCPass)
	}

	want := map[string]aggregate.Class{
		"192.0.2.25":    aggregate.ClassPass,
		"203.0.113.10":  aggregate.ClassDKIMOnly,
		"192.0.2.200":   aggregate.ClassDKIMOnly,
		"198.51.100.77": aggregate.ClassFail,
		"203.0.113.99":  aggregate.ClassSPFOnly,
		"2001:db8::1":   aggregate.ClassPass,
	}
	if len(res.Sources) != len(want) {
		t.Fatalf("sources = %d, want %d", len(res.Sources), len(want))
	}
	for _, s := range res.Sources {
		if got := s.Class(); got != want[s.IP] {
			t.Errorf("%s classified %q, want %q", s.IP, got, want[s.IP])
		}
	}
	// The busiest source comes first.
	if res.Sources[0].IP != "192.0.2.25" {
		t.Errorf("first source = %q, want the busiest", res.Sources[0].IP)
	}
	// The same address in two reports folds into one row.
	for _, s := range res.Sources {
		if s.IP == "203.0.113.10" && s.Messages != 50 {
			t.Errorf("203.0.113.10 has %d messages, want 42 + 8", s.Messages)
		}
	}
}

func TestRunContinuesPastABrokenFile(t *testing.T) {
	res := runDir(t, reportsDir(t), func(cfg *Config) {})

	var broken []aggregate.FileResult
	for _, f := range res.Files {
		if f.Status == aggregate.StatusError {
			broken = append(broken, f)
		}
	}
	if len(broken) != 2 {
		t.Fatalf("errors = %d, want malformed.xml and no-xml-member.zip", len(broken))
	}
	for _, f := range broken {
		if f.Reason == "" {
			t.Errorf("%s has no reason", f.Name)
		}
		if strings.Contains(f.Reason, "\n") {
			t.Errorf("%s: a reason must be one line, got %q", f.Name, f.Reason)
		}
	}
	if res.Totals.Messages == 0 {
		t.Fatal("the run must still aggregate the healthy files")
	}
}

func TestRunRejectsEveryHostileSampleAndKeepsGoing(t *testing.T) {
	dir := t.TempDir()
	copyDir(t, filepath.Join("..", "..", "testdata", "malicious", "reject"), dir)
	writeGenerated(t, dir)
	// One valid report in the same directory.
	copyFile(t, filepath.Join(reportsDir(t), "multi-dkim.xml"), filepath.Join(dir, "valid.xml"))

	res := runDir(t, dir, func(cfg *Config) {})

	if res.FilesParsed != 1 {
		t.Fatalf("files parsed = %d, want only the valid report", res.FilesParsed)
	}
	if res.Totals.Messages != 21 {
		t.Fatalf("messages = %d, want the valid report's 21", res.Totals.Messages)
	}
	for _, f := range res.Files {
		if f.Name == "valid.xml" {
			continue
		}
		if f.Status != aggregate.StatusError {
			t.Errorf("%s: status %q, want an error", f.Name, f.Status)
		}
		if f.Reason == "" {
			t.Errorf("%s: want one clear reason", f.Name)
		}
		assertPrintable(t, f.Reason)
	}
}

func TestRunOutputOfHostileSamplesIsClean(t *testing.T) {
	dir := t.TempDir()
	copyDir(t, filepath.Join("..", "..", "testdata", "malicious", "reject"), dir)
	copyDir(t, filepath.Join("..", "..", "testdata", "malicious", "sanitize"), dir)
	writeGenerated(t, dir)
	copyDir(t, reportsDir(t), dir)

	res := runDir(t, dir, func(cfg *Config) {})

	for _, format := range []output.Format{output.FormatText, output.FormatJSON, output.FormatCSV} {
		t.Run(string(format), func(t *testing.T) {
			var buf bytes.Buffer
			opt := output.Options{ShowFiles: true}
			if err := output.Write(&buf, format, res, opt); err != nil {
				t.Fatal(err)
			}
			for i, c := range buf.Bytes() {
				if c < 0x20 && c != '\n' && c != '\t' {
					t.Fatalf("byte %d is a control character 0x%02x", i, c)
				}
			}
		})
	}
}

func TestRunSanitizesAHostileFileName(t *testing.T) {
	dir := t.TempDir()
	name := "clear\x1b[2Jscreen.xml"
	if err := os.WriteFile(filepath.Join(dir, name), []byte("not xml at all"), 0o644); err != nil {
		t.Skipf("cannot create that file name here: %v", err)
	}
	res := runDir(t, dir, func(cfg *Config) {})
	if len(res.Files) != 1 {
		t.Fatalf("files = %d", len(res.Files))
	}
	assertPrintable(t, res.Files[0].Name)
	if strings.Contains(res.Files[0].Name, "\x1b") {
		t.Fatalf("the escape byte survived in %q", res.Files[0].Name)
	}
}

func TestRunSkipsASymlink(t *testing.T) {
	dir := t.TempDir()
	copyFile(t, filepath.Join(reportsDir(t), "multi-dkim.xml"), filepath.Join(dir, "valid.xml"))
	if err := os.Symlink("/dev/zero", filepath.Join(dir, "zero.xml")); err != nil {
		t.Skipf("cannot create a symlink here: %v", err)
	}

	done := make(chan *aggregate.Result, 1)
	go func() {
		done <- runDir(t, dir, func(cfg *Config) {})
	}()
	select {
	case res := <-done:
		if res.FilesFound != 1 {
			t.Fatalf("files found = %d, want only the regular file", res.FilesFound)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the run followed the symlink and did not return")
	}
}

func TestRunWritesNothingToAReadOnlyDirectory(t *testing.T) {
	dir := t.TempDir()
	copyDir(t, reportsDir(t), dir)
	copyDir(t, filepath.Join("..", "..", "testdata", "malicious", "reject"), dir)

	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	before := snapshot(t, dir)

	res := runDir(t, dir, func(cfg *Config) {})
	if res.FilesParsed == 0 {
		t.Fatal("the run must still read a read-only directory")
	}
	if after := snapshot(t, dir); after != before {
		t.Fatalf("the directory changed:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

func TestRunMakesNoNetworkCallByDefault(t *testing.T) {
	var dials atomic.Int64
	restore := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dials.Add(1)
			return nil, errors.New("no resolver is reachable")
		},
	}
	t.Cleanup(func() { net.DefaultResolver = restore })

	res := runDir(t, reportsDir(t), func(cfg *Config) {})
	if res.FilesParsed == 0 {
		t.Fatal("the default run must succeed with an unreachable resolver")
	}
	if dials.Load() != 0 {
		t.Fatalf("the default run made %d DNS dials", dials.Load())
	}
	for _, s := range res.Sources {
		if s.Host != "" {
			t.Fatalf("%s carries a host without -resolve", s.IP)
		}
	}
}

func TestRunWithResolveSurvivesAnUnreachableResolver(t *testing.T) {
	var dials atomic.Int64
	restore := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dials.Add(1)
			return nil, errors.New("no resolver is reachable")
		},
	}
	t.Cleanup(func() { net.DefaultResolver = restore })

	res := runDir(t, reportsDir(t), func(cfg *Config) { cfg.Resolve = true })
	if res.FilesParsed == 0 {
		t.Fatal("a failed lookup must not fail the run")
	}
	if dials.Load() == 0 {
		t.Fatal("-resolve must attempt a lookup")
	}
	for _, s := range res.Sources {
		if s.Host != "" {
			t.Fatalf("%s got a host from a failed lookup", s.IP)
		}
	}
}

func TestRunFilters(t *testing.T) {
	dir := reportsDir(t)
	tests := []struct {
		name         string
		apply        func(*Config)
		wantParsed   int
		wantSkipped  int
		wantMinCount int64
	}{
		{"since drops the reports that end earlier",
			func(c *Config) { c.Since = time.Unix(1700170000, 0) }, 3, 1, 0},
		{"since before everything keeps all",
			func(c *Config) { c.Since = time.Unix(1, 0) }, 4, 0, 0},
		{"domain matches",
			func(c *Config) { c.Domain = "example.ca" }, 4, 0, 0},
		{"domain does not match",
			func(c *Config) { c.Domain = "other.ca" }, 0, 4, 0},
		{"min count hides the quiet sources",
			func(c *Config) { c.MinCount = 20 }, 4, 0, 20},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := runDir(t, dir, tc.apply)
			if res.FilesParsed != tc.wantParsed {
				t.Errorf("parsed = %d, want %d", res.FilesParsed, tc.wantParsed)
			}
			if res.FilesSkipped != tc.wantSkipped {
				t.Errorf("skipped = %d, want %d", res.FilesSkipped, tc.wantSkipped)
			}
			for _, s := range res.Sources {
				if s.Messages < tc.wantMinCount {
					t.Errorf("%s has %d messages, below -min-count %d",
						s.IP, s.Messages, tc.wantMinCount)
				}
			}
		})
	}
}

func TestRunStopsAtTheTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already past the budget

	cfg := DefaultConfig()
	cfg.Dir = reportsDir(t)
	res, err := Run(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.FilesParsed != 0 {
		t.Fatalf("parsed = %d, want none after the deadline", res.FilesParsed)
	}
	if len(res.Warnings) == 0 {
		t.Fatal("want a warning about the timeout")
	}
}

func TestRunRejectsAMissingDirectory(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Dir = filepath.Join(t.TempDir(), "absent")
	if _, err := Run(context.Background(), cfg); err == nil {
		t.Fatal("want an error for a missing directory")
	}
}

func TestRunRecurses(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "november")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	copyFile(t, filepath.Join(reportsDir(t), "multi-dkim.xml"), filepath.Join(sub, "r.xml"))

	flat := runDir(t, dir, func(c *Config) {})
	if flat.FilesFound != 0 {
		t.Fatalf("found %d files without -recurse", flat.FilesFound)
	}
	deep := runDir(t, dir, func(c *Config) { c.Recurse = true })
	if deep.FilesParsed != 1 {
		t.Fatalf("parsed %d files with -recurse", deep.FilesParsed)
	}
}

// --- helpers -------------------------------------------------------------

func runDir(t *testing.T, dir string, apply func(*Config)) *aggregate.Result {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Dir = dir
	apply(&cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := Run(ctx, cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return res
}

func reportsDir(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "testdata", "reports")
}

// writeGenerated adds the hostile samples that are too large or too awkward
// to keep in the repository.
func writeGenerated(t *testing.T, dir string) {
	t.Helper()
	var b strings.Builder
	b.WriteString("<feedback>")
	for i := range 1000 {
		fmt.Fprintf(&b, "<a%d>", i%10)
	}
	for i := 999; i >= 0; i-- {
		fmt.Fprintf(&b, "</a%d>", i%10)
	}
	b.WriteString("</feedback>")
	if err := os.WriteFile(filepath.Join(dir, "deep-nesting.xml"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

func copyDir(t *testing.T, from, to string) {
	t.Helper()
	entries, err := os.ReadDir(from)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		copyFile(t, filepath.Join(from, e.Name()), filepath.Join(to, e.Name()))
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	src, err := os.Open(from)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	dst, err := os.Create(to)
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	if _, err := io.Copy(dst, src); err != nil {
		t.Fatal(err)
	}
}

func snapshot(t *testing.T, dir string) string {
	t.Helper()
	var lines []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		lines = append(lines, fmt.Sprintf("%s %d %s", path, info.Size(), info.Mode()))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

func assertPrintable(t *testing.T, s string) {
	t.Helper()
	for i := range len(s) {
		if s[i] < 0x20 && s[i] != '\n' && s[i] != '\t' {
			t.Fatalf("control byte at %d in %q", i, s)
		}
	}
}
