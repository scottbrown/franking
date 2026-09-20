// Package run ties the walk, the archive readers, the parser, and the
// aggregates together for one invocation.
package run

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"franking/internal/aggregate"
	"franking/internal/archive"
	"franking/internal/output"
	"franking/internal/report"
	"franking/internal/safe"
)

// DefaultTimeout bounds the whole run.
const DefaultTimeout = 5 * time.Minute

// Config is one invocation of the tool.
type Config struct {
	Dir       string
	Format    output.Format
	Since     time.Time
	Domain    string
	MinCount  int64
	Resolve   bool
	ShowFiles bool
	Recurse   bool
	Limits    archive.Limits
	Parser    report.Limits
	Timeout   time.Duration
	Verbose   bool
}

// DefaultConfig returns a Config with every limit at its default.
func DefaultConfig() Config {
	return Config{
		Format:   output.FormatText,
		MinCount: 1,
		Limits:   archive.DefaultLimits(),
		Parser:   report.DefaultLimits(),
		Timeout:  DefaultTimeout,
	}
}

// ErrTimeout reports that the run hit its time budget.
var ErrTimeout = errors.New("run stopped at the timeout")

// Run reads the directory and returns the finished aggregates. A file that
// cannot be read is recorded against its name and the run continues.
func Run(ctx context.Context, cfg Config) (*aggregate.Result, error) {
	agg := aggregate.New()

	paths, warnings, err := archive.Walk(cfg.Dir, archive.WalkOptions{Recurse: cfg.Recurse})
	if err != nil {
		return nil, err
	}
	for _, w := range warnings {
		agg.Warn(w)
	}

	for _, path := range paths {
		if ctx.Err() != nil {
			agg.Warn(ErrTimeout.Error())
			break
		}
		agg.AddFile(readOne(path, cfg, agg))
	}

	res := agg.Result(cfg.MinCount)
	if cfg.Resolve && len(res.Sources) > 0 {
		resolveHosts(ctx, res.Sources)
	}
	return res, nil
}

// readOne reads one file. A panic anywhere below is recovered and recorded
// against the file, so that it can never end the run.
func readOne(path string, cfg Config, agg *aggregate.Aggregator) (res aggregate.FileResult) {
	name := filepath.Base(path)
	defer func() {
		if p := recover(); p != nil {
			res = failure(name, "internal error while parsing; file skipped")
		}
	}()

	src, err := archive.Open(path, cfg.Limits)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return skipped(name, "no read permission")
		}
		return failure(name, reason(err))
	}
	defer src.Close()

	rep, err := report.ParseWithLimits(src, cfg.Parser)
	if err != nil {
		return failure(name, reason(err))
	}

	if !cfg.Since.IsZero() && !rep.Metadata.Range.End.IsZero() &&
		rep.Metadata.Range.End.Before(cfg.Since) {
		return skipped(name, "report ends before the -since date")
	}
	if cfg.Domain != "" && rep.Policy.Domain != cfg.Domain {
		return skipped(name, "report is for another policy domain")
	}

	for _, w := range rep.Warnings {
		agg.Warn(fmt.Sprintf("%s: %s", safe.FileName(name), w))
	}
	return agg.AddReport(name, rep)
}

func skipped(name, why string) aggregate.FileResult {
	return aggregate.FileResult{Name: name, Status: aggregate.StatusSkipped, Reason: why}
}

func failure(name, why string) aggregate.FileResult {
	return aggregate.FileResult{Name: name, Status: aggregate.StatusError, Reason: why}
}

// reason turns an error into one short sentence with no input bytes in it.
func reason(err error) string {
	switch {
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		return "file ended before the document was complete"
	case errors.Is(err, os.ErrNotExist):
		return "file disappeared during the run"
	case errors.Is(err, os.ErrPermission):
		return "no read permission"
	}
	var perr *os.PathError
	if errors.As(err, &perr) {
		return safe.Reason(perr.Err.Error())
	}
	return safe.Reason(err.Error())
}
