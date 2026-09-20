package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"franking/internal/archive"
	"franking/internal/output"
	"franking/internal/run"
)

// errUsage means the usage text has already been printed.
var errUsage = errors.New("usage")

const dateLayout = "2006-01-02"

func parseArgs(args []string, stderr io.Writer) (run.Config, error) {
	cfg := run.DefaultConfig()

	fs := flag.NewFlagSet("franking", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { usage(stderr, fs) }

	format := fs.String("format", string(output.FormatText), "output format: text, json, or csv")
	since := fs.String("since", "", "ignore reports whose range ends before this date (YYYY-MM-DD)")
	domain := fs.String("domain", "", "process only reports for this policy domain")
	minCount := fs.Int64("min-count", 1, "hide sources with fewer messages than this")
	resolve := fs.Bool("resolve", false, "do a reverse DNS lookup on each source IP")
	files := fs.Bool("files", false, "show the per-file table")
	recurse := fs.Bool("recurse", false, "read subdirectories, to a depth of 8")
	verbose := fs.Bool("v", false, "show parse warnings and skipped files")
	htmlPath := fs.String("html", "", "also write a self-contained HTML report to this `file`")
	timeout := fs.Duration("timeout", run.DefaultTimeout, "stop the whole run after this time")

	maxFile := byteSize(archive.DefaultMaxFileSize)
	maxXML := byteSize(archive.DefaultMaxXMLSize)
	fs.Var(&maxFile, "max-file-size", "reject an input file larger than this")
	fs.Var(&maxXML, "max-xml-size", "reject a report that expands beyond this")
	maxRatio := fs.Float64("max-ratio", archive.DefaultMaxRatio, "reject a compression ratio above this")

	if err := fs.Parse(args); err != nil {
		return cfg, errUsage
	}
	if fs.NArg() != 1 {
		usage(stderr, fs)
		return cfg, errUsage
	}

	f, err := output.ParseFormat(*format)
	if err != nil {
		return cfg, err
	}
	cfg.Format = f
	cfg.Dir = fs.Arg(0)
	cfg.Domain = *domain
	cfg.MinCount = *minCount
	cfg.Resolve = *resolve
	cfg.ShowFiles = *files
	cfg.Recurse = *recurse
	cfg.Verbose = *verbose
	cfg.Timeout = *timeout
	cfg.HTMLPath = strings.TrimSpace(*htmlPath)
	cfg.Limits = archive.Limits{
		MaxFileSize: int64(maxFile),
		MaxXMLSize:  int64(maxXML),
		MaxRatio:    *maxRatio,
	}

	if *since != "" {
		t, err := time.ParseInLocation(dateLayout, *since, time.Local)
		if err != nil {
			return cfg, fmt.Errorf("-since wants a date as YYYY-MM-DD")
		}
		cfg.Since = t
	}
	if cfg.MinCount < 0 {
		return cfg, errors.New("-min-count cannot be negative")
	}
	if cfg.Timeout <= 0 {
		return cfg, errors.New("-timeout must be positive")
	}
	if *maxRatio <= 0 {
		return cfg, errors.New("-max-ratio must be positive")
	}
	if *htmlPath != "" && cfg.HTMLPath == "" {
		return cfg, errors.New("-html wants a file path")
	}
	return cfg, nil
}

func usage(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprintf(w, "franking reads a directory of DMARC aggregate reports.\n\n")
	fmt.Fprintf(w, "usage: franking [flags] <directory>\n\nflags:\n")
	fs.PrintDefaults()
}

// byteSize is a flag value that accepts a plain number of bytes or a suffix
// such as 50MB.
type byteSize int64

func (b *byteSize) String() string {
	if b == nil {
		return "0"
	}
	return formatBytes(int64(*b))
}

func (b *byteSize) Set(v string) error {
	n, err := parseBytes(v)
	if err != nil {
		return err
	}
	*b = byteSize(n)
	return nil
}

var byteUnits = []struct {
	suffix string
	scale  int64
}{
	{"KB", 1 << 10}, {"MB", 1 << 20}, {"GB", 1 << 30},
	{"K", 1 << 10}, {"M", 1 << 20}, {"G", 1 << 30},
	{"B", 1},
}

func parseBytes(v string) (int64, error) {
	s := strings.ToUpper(strings.TrimSpace(v))
	if s == "" {
		return 0, errors.New("want a size such as 50MB")
	}
	scale := int64(1)
	for _, u := range byteUnits {
		if strings.HasSuffix(s, u.suffix) {
			s, scale = strings.TrimSpace(strings.TrimSuffix(s, u.suffix)), u.scale
			break
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return 0, errors.New("want a positive size such as 50MB")
	}
	if n > (1<<62)/scale {
		return 0, errors.New("size is too large")
	}
	return n * scale, nil
}

func formatBytes(n int64) string {
	switch {
	case n >= 1<<30 && n%(1<<30) == 0:
		return fmt.Sprintf("%dGB", n/(1<<30))
	case n >= 1<<20 && n%(1<<20) == 0:
		return fmt.Sprintf("%dMB", n/(1<<20))
	case n >= 1<<10 && n%(1<<10) == 0:
		return fmt.Sprintf("%dKB", n/(1<<10))
	}
	return strconv.FormatInt(n, 10)
}
