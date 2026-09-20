package report

import (
	"strings"
	"time"
)

// Disposition is the policy that the receiver applied to a group of messages.
type Disposition string

// The known dispositions. Any other value becomes DispositionUnknown.
const (
	DispositionNone       Disposition = "none"
	DispositionQuarantine Disposition = "quarantine"
	DispositionReject     Disposition = "reject"
	DispositionUnknown    Disposition = "unknown"
)

// ParseDisposition maps an untrusted disposition string onto the known set.
func ParseDisposition(s string) Disposition {
	switch Disposition(strings.ToLower(strings.TrimSpace(s))) {
	case DispositionNone:
		return DispositionNone
	case DispositionQuarantine:
		return DispositionQuarantine
	case DispositionReject:
		return DispositionReject
	}
	return DispositionUnknown
}

// AuthResult is a DKIM or SPF outcome.
type AuthResult string

// The known authentication results. Any other value becomes AuthUnknown.
const (
	AuthPass      AuthResult = "pass"
	AuthFail      AuthResult = "fail"
	AuthNone      AuthResult = "none"
	AuthNeutral   AuthResult = "neutral"
	AuthSoftFail  AuthResult = "softfail"
	AuthPolicy    AuthResult = "policy"
	AuthTempError AuthResult = "temperror"
	AuthPermError AuthResult = "permerror"
	AuthUnknown   AuthResult = "unknown"
)

// ParseAuthResult maps an untrusted result string onto the known set.
func ParseAuthResult(s string) AuthResult {
	switch AuthResult(strings.ToLower(strings.TrimSpace(s))) {
	case AuthPass:
		return AuthPass
	case AuthFail:
		return AuthFail
	case AuthNone:
		return AuthNone
	case AuthNeutral:
		return AuthNeutral
	case AuthSoftFail:
		return AuthSoftFail
	case AuthPolicy:
		return AuthPolicy
	case AuthTempError:
		return AuthTempError
	case AuthPermError:
		return AuthPermError
	}
	return AuthUnknown
}

// Passed reports whether the result is an aligned pass.
func (r AuthResult) Passed() bool { return r == AuthPass }

// DateRange is the period that a report covers.
type DateRange struct {
	Begin time.Time
	End   time.Time
}

// Metadata describes the report itself. Every string is sanitized.
type Metadata struct {
	Org      string
	Email    string
	ReportID string
	Range    DateRange
}

// Policy is the DMARC policy that the reporting receiver saw published.
type Policy struct {
	Domain          string
	ADKIM           string
	ASPF            string
	P               string
	SubdomainPolicy string
	Pct             string
}

// Record is one row of a report: one source address over one report period.
type Record struct {
	SourceIP    string
	Count       int64
	Disposition Disposition
	DKIM        AuthResult // aligned result from policy_evaluated
	SPF         AuthResult // aligned result from policy_evaluated
	HeaderFrom  string
	DKIMDomains []string // raw results from auth_results
	SPFDomains  []string // raw results from auth_results
}

// DMARCPass reports whether DKIM or SPF is aligned and passes.
func (r Record) DMARCPass() bool { return r.DKIM.Passed() || r.SPF.Passed() }

// Report is one parsed aggregate report.
type Report struct {
	Metadata Metadata
	Policy   Policy
	Records  []Record
	Warnings []string
}

// Messages is the total message count over all records, saturating.
func (r *Report) Messages() int64 {
	var total int64
	for _, rec := range r.Records {
		total = addCount(total, rec.Count)
	}
	return total
}
