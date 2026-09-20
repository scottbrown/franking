package safe

import (
	"math"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestText(t *testing.T) {
	tests := []struct {
		name string
		in   string
		max  int
		want string
	}{
		{"plain", "google.com", 0, "google.com"},
		{"strips escape", "\x1b[2J\x1b[1;1Hclear", 0, "[2J[1;1Hclear"},
		{"strips nul bel cr lf tab", "a\x00b\x07c\rd\ne\tf", 0, "abcdef"},
		{"strips c1", "a\u009bb", 0, "ab"},
		{"strips del", "a\x7fb", 0, "ab"},
		{"strips bidi override", "a‮b‬c⁦d⁩e", 0, "abcde"},
		{"keeps accents", "Société", 0, "Société"},
		{"replaces invalid utf8", "a\xffb", 0, "a�b"},
		{"truncates", "abcdefghij", 6, "abc…"},
		{"no truncation when short", "abc", 6, "abc"},
		{"empty", "", 10, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Text(tc.in, tc.max)
			if got != tc.want {
				t.Fatalf("Text(%q, %d) = %q, want %q", tc.in, tc.max, got, tc.want)
			}
			if !utf8.ValidString(got) {
				t.Fatalf("Text(%q) produced invalid UTF-8", tc.in)
			}
		})
	}
}

func TestTextTruncationStaysWithinLimit(t *testing.T) {
	long := strings.Repeat("é", 400) // two bytes per rune
	got := Text(long, MaxOrgLen)
	if len(got) > MaxOrgLen {
		t.Fatalf("length %d is above the limit %d", len(got), MaxOrgLen)
	}
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("a truncated value must end with an ellipsis, got %q", got)
	}
	if !utf8.ValidString(got) {
		t.Fatal("truncation split a rune")
	}
}

func TestDomain(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "mail.vendor.net", "mail.vendor.net"},
		{"underscore and dash", "_dmarc.example-sender.ca", "_dmarc.example-sender.ca"},
		{"spaces become question marks", "mail vendor.net", "mail?vendor.net"},
		{"shell metacharacters", "example.ca; rm -rf /", "example.ca??rm?-rf??"},
		{"control characters vanish", "exa\x1bmple.ca", "example.ca"},
		{"rtl override vanishes", "example‮.ca", "example.ca"},
		{"trims", "  example.ca  ", "example.ca"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Domain(tc.in); got != tc.want {
				t.Fatalf("Domain(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestDomainLength(t *testing.T) {
	got := Domain(strings.Repeat("a", 400))
	if len(got) > MaxDomainLen {
		t.Fatalf("length %d is above the limit %d", len(got), MaxDomainLen)
	}
}

func TestIP(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"ipv4", "203.0.113.10", "203.0.113.10"},
		{"ipv6", "2001:db8::1", "2001:db8::1"},
		{"ipv6 upper", "2001:DB8::1", "2001:db8::1"},
		{"padded", " 192.0.2.1 ", "192.0.2.1"},
		{"not an ip", "not-an-ip", InvalidIP},
		{"command injection", "127.0.0.1; rm -rf /", InvalidIP},
		{"escape sequence", "\x1b[2J", InvalidIP},
		{"empty", "", InvalidIP},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IP(tc.in); got != tc.want {
				t.Fatalf("IP(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestCount(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    int64
		wantErr bool
	}{
		{"zero", "0", 0, false},
		{"small", "42", 42, false},
		{"at the ceiling", "2147483648", MaxCount, false},
		{"above the ceiling", "2147483649", 0, true},
		{"negative", "-5", 0, true},
		{"huge", "99999999999999999999999999", 0, true},
		{"max int64", "9223372036854775807", 0, true},
		{"not a number", "not-a-number", 0, true},
		{"empty", "", 0, true},
		{"hex", "0x10", 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Count(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Count(%q) = %d, want an error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Count(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("Count(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

func TestAddCountSaturates(t *testing.T) {
	tests := []struct {
		name string
		a, b int64
		want int64
	}{
		{"normal", 10, 5, 15},
		{"at the top", math.MaxInt64, 1, math.MaxInt64},
		{"both large", math.MaxInt64, math.MaxInt64, math.MaxInt64},
		{"zero", 0, 0, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := AddCount(tc.a, tc.b); got != tc.want {
				t.Fatalf("AddCount(%d, %d) = %d, want %d", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestCSVCell(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "example.ca", "example.ca"},
		{"equals", "=cmd|' /c calc'!A0", "'=cmd|' /c calc'!A0"},
		{"plus", "+1234", "'+1234"},
		{"minus", "-rogue.example.ca", "'-rogue.example.ca"},
		{"at", "@SUM(1+1)", "'@SUM(1+1)"},
		{"tab", "\tvalue", "'\tvalue"},
		{"carriage return", "\rvalue", "'\rvalue"},
		{"empty", "", ""},
		{"number", "42", "42"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := CSVCell(tc.in); got != tc.want {
				t.Fatalf("CSVCell(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestFileNameKeepsOnlyTheFinalElement(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"traversal", "../../../etc/passwd", "passwd"},
		{"windows traversal", `..\..\windows\system32`, "system32"},
		{"plain", "report.xml", "report.xml"},
		{"escape in the name", "rep\x1b[2Jort.xml", "rep[2Jort.xml"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := FileName(tc.in); got != tc.want {
				t.Fatalf("FileName(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestHostDropsTrailingDot(t *testing.T) {
	if got := Host("mail.vendor.net."); got != "mail.vendor.net" {
		t.Fatalf("Host() = %q", got)
	}
}
