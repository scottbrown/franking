package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func reportsDir() string { return filepath.Join("..", "..", "testdata", "reports") }

func TestExitCodes(t *testing.T) {
	empty := t.TempDir()
	tests := []struct {
		name string
		args []string
		want int
	}{
		{"no directory", nil, exitUsage},
		{"too many arguments", []string{reportsDir(), "extra"}, exitUsage},
		{"unknown flag", []string{"-nope", reportsDir()}, exitUsage},
		{"unknown format", []string{"-format", "yaml", reportsDir()}, exitUsage},
		{"bad since", []string{"-since", "yesterday", reportsDir()}, exitUsage},
		{"bad size", []string{"-max-file-size", "huge", reportsDir()}, exitUsage},
		{"negative min count", []string{"-min-count", "-1", reportsDir()}, exitUsage},
		{"missing directory", []string{filepath.Join(empty, "absent")}, exitFail},
		{"no file parsed", []string{empty}, exitFail},
		{"good run", []string{reportsDir()}, exitOK},
		{"good run as json", []string{"-format", "json", reportsDir()}, exitOK},
		{"good run as csv", []string{"-format", "csv", reportsDir()}, exitOK},
		{"verbose", []string{"-v", "-files", reportsDir()}, exitOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := franking(tc.args, &stdout, &stderr); got != tc.want {
				t.Fatalf("exit = %d, want %d\nstderr: %s", got, tc.want, stderr.String())
			}
		})
	}
}

func TestUsageGoesToStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := franking(nil, &stdout, &stderr); got != exitUsage {
		t.Fatalf("exit = %d", got)
	}
	if !strings.Contains(stderr.String(), "usage: franking") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("usage must not go to stdout, got %q", stdout.String())
	}
}

func TestJSONOutputIsMachineReadable(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := franking([]string{"-format", "json", reportsDir()}, &stdout, &stderr); got != exitOK {
		t.Fatalf("exit = %d: %s", got, stderr.String())
	}
	var doc struct {
		GeneratedAt string `json:"generated_at"`
		Totals      struct {
			Messages int64 `json:"messages"`
		} `json:"totals"`
		Sources []struct {
			IP    string `json:"ip"`
			Class string `json:"class"`
		} `json:"sources"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	if doc.GeneratedAt == "" || doc.Totals.Messages == 0 || len(doc.Sources) == 0 {
		t.Fatalf("JSON is missing content: %+v", doc)
	}
}

func TestCSVOutputIsMachineReadable(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := franking([]string{"-format", "csv", reportsDir()}, &stdout, &stderr); got != exitOK {
		t.Fatalf("exit = %d: %s", got, stderr.String())
	}
	rows, err := csv.NewReader(bytes.NewReader(stdout.Bytes())).ReadAll()
	if err != nil {
		t.Fatalf("stdout is not valid CSV: %v", err)
	}
	if len(rows) < 2 || rows[0][0] != "ip" {
		t.Fatalf("rows = %v", rows)
	}
}

func TestBrokenFileProducesOneWarningLine(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := franking([]string{reportsDir()}, &stdout, &stderr); got != exitOK {
		t.Fatalf("exit = %d: %s", got, stderr.String())
	}
	lines := 0
	for _, line := range strings.Split(stdout.String(), "\n") {
		if strings.Contains(line, "malformed.xml") {
			lines++
		}
	}
	if lines != 1 {
		t.Fatalf("malformed.xml appears on %d lines, want 1:\n%s", lines, stdout.String())
	}
}

func TestParseBytes(t *testing.T) {
	tests := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"1024", 1024, false},
		{"50MB", 50 << 20, false},
		{"64mb", 64 << 20, false},
		{"2GB", 2 << 30, false},
		{"8K", 8 << 10, false},
		{"512B", 512, false},
		{" 4 MB ", 4 << 20, false},
		{"0", 0, true},
		{"-5MB", 0, true},
		{"", 0, true},
		{"lots", 0, true},
		{"9223372036854775807GB", 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseBytes(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseBytes(%q) = %d, want an error", tc.in, got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("parseBytes(%q) = %d, %v; want %d", tc.in, got, err, tc.want)
			}
		})
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		in   int64
		want string
	}{
		{50 << 20, "50MB"},
		{64 << 20, "64MB"},
		{2 << 30, "2GB"},
		{4096, "4KB"},
		{999, "999"},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			if got := formatBytes(tc.in); got != tc.want {
				t.Fatalf("formatBytes(%d) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestFlagDefaults(t *testing.T) {
	var stderr bytes.Buffer
	cfg, err := parseArgs([]string{reportsDir()}, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Limits.MaxFileSize != 50<<20 {
		t.Errorf("max file size = %d", cfg.Limits.MaxFileSize)
	}
	if cfg.Limits.MaxXMLSize != 64<<20 {
		t.Errorf("max xml size = %d", cfg.Limits.MaxXMLSize)
	}
	if cfg.Limits.MaxRatio != 200 {
		t.Errorf("max ratio = %v", cfg.Limits.MaxRatio)
	}
	if cfg.Timeout.Minutes() != 5 {
		t.Errorf("timeout = %v", cfg.Timeout)
	}
	if cfg.MinCount != 1 {
		t.Errorf("min count = %d", cfg.MinCount)
	}
	if cfg.Resolve || cfg.ShowFiles || cfg.Recurse || cfg.Verbose {
		t.Errorf("a boolean flag defaults to true: %+v", cfg)
	}
	if cfg.Format != "text" {
		t.Errorf("format = %q", cfg.Format)
	}
}

func TestOutputGoesToTheGivenWriterOnly(t *testing.T) {
	dir := t.TempDir()
	before, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	franking([]string{reportsDir()}, &stdout, &stderr)
	after, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != len(after) {
		t.Fatal("the run created a file")
	}
	if stdout.Len() == 0 {
		t.Fatal("nothing was written to the given writer")
	}
}

func TestHTMLFlagWritesOnlyTheFileGiven(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "report.html")

	var stdout, stderr bytes.Buffer
	if got := franking([]string{"-html", out, reportsDir()}, &stdout, &stderr); got != exitOK {
		t.Fatalf("exit = %d: %s", got, stderr.String())
	}

	// Exactly one file, at the path the user named, and nothing else.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "report.html" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("directory holds %v, want only report.html", names)
	}

	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	html := string(b)
	if !strings.HasPrefix(html, "<!DOCTYPE html>") {
		t.Fatalf("not an HTML document: %.60q", html)
	}
	if !strings.Contains(html, "DMARC report") {
		t.Error("want the report title")
	}
	// stdout still carries the chosen format; the report is extra.
	if !strings.Contains(stdout.String(), "Run summary") {
		t.Error("-html must not replace the stdout report")
	}
	if !strings.Contains(stderr.String(), "wrote ") {
		t.Error("want the written path reported on stderr")
	}
}

func TestHTMLFlagReportsAnUnwritablePath(t *testing.T) {
	dir := t.TempDir()
	// A path whose parent is a file, not a directory.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	got := franking([]string{"-html", filepath.Join(blocker, "report.html"), reportsDir()}, &stdout, &stderr)
	if got != exitFail {
		t.Fatalf("exit = %d, want %d", got, exitFail)
	}
	if !strings.Contains(stderr.String(), "cannot write the HTML report") {
		t.Errorf("want a clear reason, got %q", stderr.String())
	}
}

func TestHTMLFlagRejectsABlankPath(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := franking([]string{"-html", "   ", reportsDir()}, &stdout, &stderr); got != exitUsage {
		t.Fatalf("exit = %d, want %d", got, exitUsage)
	}
}
