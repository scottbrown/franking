// Package safe holds the sanitize, validate, and limit helpers. Every string
// that comes out of a report file or a directory listing passes through this
// package before it reaches stdout, a JSON value, or a CSV cell.
package safe

import (
	"errors"
	"math"
	"net"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Maximum kept length, in bytes, for each kind of untrusted string.
const (
	MaxDomainLen   = 253
	MaxOrgLen      = 128
	MaxReportIDLen = 64
	MaxFileNameLen = 255
	MaxHostLen     = 253
	MaxReasonLen   = 200
)

// InvalidIP is the literal recorded for a source address that does not parse.
const InvalidIP = "invalid"

// MaxCount is the largest message count accepted from one row.
const MaxCount = int64(1) << 31

// ErrBadCount reports a count field that is missing, negative, too large, or
// not a number.
var ErrBadCount = errors.New("count is not a valid non-negative integer")

const ellipsis = "…"

// Text removes control and bidirectional characters, replaces invalid UTF-8,
// and truncates to max bytes. A max of zero or less means no truncation.
func Text(s string, max int) string {
	return truncate(clean(s), max)
}

// OrgName sanitizes a reporting organization name.
func OrgName(s string) string { return Text(s, MaxOrgLen) }

// ReportID sanitizes a report identifier.
func ReportID(s string) string { return Text(s, MaxReportIDLen) }

// FileName sanitizes a file name for display. Only the final path element is
// ever kept, because a name from an archive or a listing is never a path.
func FileName(s string) string {
	if i := strings.LastIndexAny(s, `/\`); i >= 0 {
		s = s[i+1:]
	}
	return Text(s, MaxFileNameLen)
}

// Reason sanitizes an error reason for display.
func Reason(s string) string { return Text(s, MaxReasonLen) }

// Domain keeps only the characters a-z, A-Z, 0-9, '.', '-', and '_'. Anything
// else becomes '?'.
func Domain(s string) string {
	c := clean(strings.TrimSpace(s))
	var b strings.Builder
	b.Grow(len(c))
	for _, r := range c {
		if isDomainRune(r) {
			b.WriteRune(r)
		} else {
			b.WriteByte('?')
		}
	}
	return truncate(b.String(), MaxDomainLen)
}

// Host sanitizes a PTR record, which the owner of the address controls.
func Host(s string) string {
	return Domain(strings.TrimSuffix(s, "."))
}

// IP validates a source address. A value that does not parse becomes the
// literal InvalidIP, so that the raw bytes never reach the output.
func IP(s string) string {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return InvalidIP
	}
	return ip.String()
}

// Count parses a message count. A negative value, a value above 2^31, and a
// value that is not a number are all rejected.
func Count(s string) (int64, error) {
	v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, ErrBadCount
	}
	if v < 0 || v > MaxCount {
		return 0, ErrBadCount
	}
	return v, nil
}

// AddCount adds two non-negative counts and saturates at math.MaxInt64, so
// that a crafted set of reports cannot overflow a total.
func AddCount(a, b int64) int64 {
	if a < 0 || b < 0 {
		return a
	}
	if a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

// CSVCell prefixes a single quote to any cell that a spreadsheet would treat
// as a formula.
func CSVCell(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

func clean(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		// A range over a string yields U+FFFD for every invalid byte.
		if keep(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func keep(r rune) bool {
	switch {
	case r < 0x20: // C0, including NUL, BEL, TAB, LF, CR, and ESC
		return false
	case r == 0x7f: // DEL
		return false
	case r >= 0x80 && r <= 0x9f: // C1
		return false
	case r >= 0x202a && r <= 0x202e: // bidi embedding and override
		return false
	case r >= 0x2066 && r <= 0x2069: // bidi isolate
		return false
	}
	return true
}

func isDomainRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z':
		return true
	case r >= 'A' && r <= 'Z':
		return true
	case r >= '0' && r <= '9':
		return true
	case r == '.' || r == '-' || r == '_':
		return true
	}
	return false
}

func truncate(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	cut := max - len(ellipsis)
	if cut < 0 {
		cut = 0
	}
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + ellipsis
}
