// Command franking reads a directory of DMARC aggregate reports and prints
// what each sending address needs.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"franking/internal/aggregate"
	"franking/internal/output"
	"franking/internal/run"
)

// Exit codes.
const (
	exitOK    = 0
	exitFail  = 1
	exitUsage = 2
)

func main() {
	os.Exit(franking(os.Args[1:], os.Stdout, os.Stderr))
}

func franking(args []string, stdout, stderr io.Writer) int {
	cfg, err := parseArgs(args, stderr)
	if err != nil {
		if errors.Is(err, errUsage) {
			return exitUsage
		}
		fmt.Fprintf(stderr, "franking: %s\n", err)
		return exitUsage
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	res, err := run.Run(ctx, cfg)
	if err != nil {
		fmt.Fprintf(stderr, "franking: %s\n", err)
		return exitFail
	}

	opt := output.Options{
		ShowFiles: cfg.ShowFiles,
		Resolve:   cfg.Resolve,
		Limits: output.LimitLabels{
			MaxFileSize: formatBytes(cfg.Limits.MaxFileSize),
			MaxXMLSize:  formatBytes(cfg.Limits.MaxXMLSize),
			MaxRatio:    fmt.Sprintf("%g:1", cfg.Limits.MaxRatio),
		},
	}
	if err := output.Write(stdout, cfg.Format, res, opt); err != nil {
		fmt.Fprintf(stderr, "franking: %s\n", err)
		return exitFail
	}

	// -html is the only path on which this tool writes a file, and it writes
	// only to the path the user named on the command line.
	if cfg.HTMLPath != "" {
		if err := writeHTMLReport(cfg.HTMLPath, res, opt); err != nil {
			fmt.Fprintf(stderr, "franking: %s\n", err)
			return exitFail
		}
		fmt.Fprintf(stderr, "wrote %s\n", cfg.HTMLPath)
	}

	if cfg.Verbose {
		for _, w := range res.Warnings {
			fmt.Fprintf(stderr, "warning: %s\n", w)
		}
		for _, f := range res.Files {
			if f.Status != aggregate.StatusOK {
				fmt.Fprintf(stderr, "%s: %s: %s\n", f.Status, f.Name, f.Reason)
			}
		}
	}

	if res.FilesParsed == 0 {
		return exitFail
	}
	return exitOK
}

// writeHTMLReport renders the report into memory first, so that a failure
// part way through never leaves a truncated file behind.
func writeHTMLReport(path string, res *aggregate.Result, opt output.Options) error {
	var buf bytes.Buffer
	if err := output.WriteHTML(&buf, res, opt); err != nil {
		return err
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("cannot write the HTML report: %w", err)
	}
	return nil
}
