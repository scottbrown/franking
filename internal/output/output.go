// Package output writes a finished Result as text, JSON, or CSV.
package output

import (
	"fmt"
	"io"
	"strings"
	"time"

	"franking/internal/aggregate"
)

// Format is an output format.
type Format string

// The supported formats.
const (
	FormatText Format = "text"
	FormatJSON Format = "json"
	FormatCSV  Format = "csv"
)

// Formats returns every format name.
func Formats() []string { return []string{string(FormatText), string(FormatJSON), string(FormatCSV)} }

// DefaultLimitLabels describes the built-in limits.
func DefaultLimitLabels() LimitLabels {
	return LimitLabels{MaxFileSize: "50MB", MaxXMLSize: "64MB", MaxRatio: "200:1"}
}

// ParseFormat maps a flag value onto a format.
func ParseFormat(s string) (Format, error) {
	switch Format(strings.ToLower(strings.TrimSpace(s))) {
	case FormatText:
		return FormatText, nil
	case FormatJSON:
		return FormatJSON, nil
	case FormatCSV:
		return FormatCSV, nil
	}
	return "", fmt.Errorf("unknown format %q, want one of %s", s, strings.Join(Formats(), ", "))
}

// Options changes what the writers show.
type Options struct {
	ShowFiles bool
	Resolve   bool
	Now       time.Time
	Limits    LimitLabels
}

// LimitLabels are the limits that were in effect, already formatted, for the
// provenance footer of the HTML report.
type LimitLabels struct {
	MaxFileSize string
	MaxXMLSize  string
	MaxRatio    string
}

// Write renders the result in the chosen format.
func Write(w io.Writer, format Format, res *aggregate.Result, opt Options) error {
	if opt.Now.IsZero() {
		opt.Now = time.Now()
	}
	switch format {
	case FormatJSON:
		return WriteJSON(w, res, opt)
	case FormatCSV:
		return WriteCSV(w, res, opt)
	default:
		return WriteText(w, res, opt)
	}
}

func timestamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Local().Format("2006-01-02 15:04")
}

func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Local().Format(time.RFC3339)
}

func percent(v float64) string { return fmt.Sprintf("%.1f%%", v*100) }
