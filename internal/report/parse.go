package report

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/scottbrown/franking/internal/safe"
)

// Limits bound the work that one document may cause.
type Limits struct {
	MaxDepth   int
	MaxRecords int
}

// The default parser limits.
const (
	DefaultMaxDepth   = 32
	DefaultMaxRecords = 200000
)

// DefaultLimits returns the limits that the command line uses.
func DefaultLimits() Limits {
	return Limits{MaxDepth: DefaultMaxDepth, MaxRecords: DefaultMaxRecords}
}

// Parser errors. Each message describes the problem in its own words and
// never holds a byte that came from the input.
var (
	ErrNotFeedback  = errors.New("xml: root element is not <feedback>")
	ErrEmpty        = errors.New("xml: document holds no element")
	ErrTooManyRecs  = errors.New("xml: report holds more records than the limit")
	errTooDeepBase  = "xml: element nesting deeper than %d levels"
	ErrSyntaxPrefix = "xml: syntax error"
)

// epochCeiling rejects a date_range value far outside any plausible report.
const epochCeiling = int64(1) << 34

// Parse reads one DMARC aggregate report. It walks the document as a token
// stream, so memory stays bounded and the record limit can stop the read.
func Parse(r io.Reader) (*Report, error) {
	return ParseWithLimits(r, DefaultLimits())
}

// ParseWithLimits is Parse with explicit limits.
func ParseWithLimits(r io.Reader, lim Limits) (rep *Report, err error) {
	if lim.MaxDepth <= 0 {
		lim.MaxDepth = DefaultMaxDepth
	}
	if lim.MaxRecords <= 0 {
		lim.MaxRecords = DefaultMaxRecords
	}

	// A panic inside encoding/xml must never end the run.
	defer func() {
		if p := recover(); p != nil {
			rep, err = nil, errors.New("xml: parser panic recovered")
		}
	}()

	inner := xml.NewDecoder(r)
	inner.Strict = true
	inner.Entity = map[string]string{} // no custom entity resolves
	inner.CharsetReader = charsetReader

	guard := &depthGuard{dec: inner, max: lim.MaxDepth}
	dec := xml.NewTokenDecoder(guard)

	root, err := findRoot(dec)
	if err != nil {
		return nil, err
	}
	if root.Name.Local != "feedback" {
		return nil, ErrNotFeedback
	}

	out := &Report{}
	badCounts, badIPs := 0, 0

	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, wrapXMLError(err)
		}
		switch t := tok.(type) {
		case xml.EndElement:
			if t.Name.Local == "feedback" {
				return finish(out, badCounts, badIPs), nil
			}
		case xml.StartElement:
			switch t.Name.Local {
			case "report_metadata":
				var m xmlMetadata
				if err := dec.DecodeElement(&m, &t); err != nil {
					return nil, wrapXMLError(err)
				}
				out.Metadata = m.metadata()
			case "policy_published":
				var p xmlPolicy
				if err := dec.DecodeElement(&p, &t); err != nil {
					return nil, wrapXMLError(err)
				}
				out.Policy = p.policy()
			case "record":
				if len(out.Records) >= lim.MaxRecords {
					return nil, ErrTooManyRecs
				}
				var xr xmlRecord
				if err := dec.DecodeElement(&xr, &t); err != nil {
					return nil, wrapXMLError(err)
				}
				rec, badCount, badIP := xr.record()
				if badCount {
					badCounts++
				}
				if badIP {
					badIPs++
				}
				out.Records = append(out.Records, rec)
			default:
				if err := dec.Skip(); err != nil {
					return nil, wrapXMLError(err)
				}
			}
		}
	}
	return finish(out, badCounts, badIPs), nil
}

func finish(out *Report, badCounts, badIPs int) *Report {
	if badCounts > 0 {
		out.Warnings = append(out.Warnings,
			fmt.Sprintf("%d record(s) with an unusable count were dropped", badCounts))
	}
	if badIPs > 0 {
		out.Warnings = append(out.Warnings,
			fmt.Sprintf("%d record(s) with an unparseable source address", badIPs))
	}
	return out
}

func findRoot(dec *xml.Decoder) (xml.StartElement, error) {
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return xml.StartElement{}, ErrEmpty
		}
		if err != nil {
			return xml.StartElement{}, wrapXMLError(err)
		}
		if se, ok := tok.(xml.StartElement); ok {
			return se, nil
		}
	}
}

// depthGuard counts element depth on the token stream, so the limit holds
// inside a subtree that DecodeElement consumes as well as at the top level.
type depthGuard struct {
	dec   *xml.Decoder
	depth int
	max   int
}

func (g *depthGuard) Token() (xml.Token, error) {
	tok, err := g.dec.Token()
	if err != nil {
		return nil, err
	}
	switch tok.(type) {
	case xml.StartElement:
		g.depth++
		if g.depth > g.max {
			return nil, fmt.Errorf(errTooDeepBase, g.max)
		}
	case xml.EndElement:
		g.depth--
	}
	// The decoder's buffers are reused, so hand on a copy.
	return xml.CopyToken(tok), nil
}

// wrapXMLError replaces a library error with a description of the problem.
// An encoding/xml error can quote the offending bytes, and those bytes come
// from the input.
func wrapXMLError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrCharset) {
		return ErrCharset
	}
	var se *xml.SyntaxError
	if errors.As(err, &se) {
		return fmt.Errorf("%s at line %d", ErrSyntaxPrefix, se.Line)
	}
	var te *xml.TagPathError
	if errors.As(err, &te) {
		return errors.New("xml: conflicting element path in record")
	}
	if strings.HasPrefix(err.Error(), "xml: element nesting deeper") {
		return err
	}
	return errors.New("xml: parse error")
}

type xmlDateRange struct {
	Begin string `xml:"begin"`
	End   string `xml:"end"`
}

type xmlMetadata struct {
	OrgName   string       `xml:"org_name"`
	Email     string       `xml:"email"`
	ReportID  string       `xml:"report_id"`
	DateRange xmlDateRange `xml:"date_range"`
}

func (m xmlMetadata) metadata() Metadata {
	return Metadata{
		Org:      safe.OrgName(m.OrgName),
		Email:    safe.Domain(m.Email),
		ReportID: safe.ReportID(m.ReportID),
		Range: DateRange{
			Begin: epoch(m.DateRange.Begin),
			End:   epoch(m.DateRange.End),
		},
	}
}

type xmlPolicy struct {
	Domain string `xml:"domain"`
	ADKIM  string `xml:"adkim"`
	ASPF   string `xml:"aspf"`
	P      string `xml:"p"`
	SP     string `xml:"sp"`
	Pct    string `xml:"pct"`
}

func (p xmlPolicy) policy() Policy {
	return Policy{
		Domain:          safe.Domain(p.Domain),
		ADKIM:           safe.Text(p.ADKIM, 16),
		ASPF:            safe.Text(p.ASPF, 16),
		P:               safe.Text(p.P, 16),
		SubdomainPolicy: safe.Text(p.SP, 16),
		Pct:             safe.Text(p.Pct, 8),
	}
}

type xmlAuthDKIM struct {
	Domain   string `xml:"domain"`
	Selector string `xml:"selector"`
	Result   string `xml:"result"`
}

type xmlAuthSPF struct {
	Domain string `xml:"domain"`
	Scope  string `xml:"scope"`
	Result string `xml:"result"`
}

type xmlRecord struct {
	Row struct {
		SourceIP        string `xml:"source_ip"`
		Count           string `xml:"count"`
		PolicyEvaluated struct {
			Disposition string `xml:"disposition"`
			DKIM        string `xml:"dkim"`
			SPF         string `xml:"spf"`
		} `xml:"policy_evaluated"`
	} `xml:"row"`
	Identifiers struct {
		HeaderFrom   string `xml:"header_from"`
		EnvelopeFrom string `xml:"envelope_from"`
	} `xml:"identifiers"`
	AuthResults struct {
		DKIM []xmlAuthDKIM `xml:"dkim"`
		SPF  []xmlAuthSPF  `xml:"spf"`
	} `xml:"auth_results"`
}

func (x xmlRecord) record() (rec Record, badCount, badIP bool) {
	count, err := safe.Count(x.Row.Count)
	if err != nil {
		badCount = true
		count = 0
	}
	ip := safe.IP(x.Row.SourceIP)
	if ip == safe.InvalidIP {
		badIP = true
	}
	rec = Record{
		SourceIP:    ip,
		Count:       count,
		Disposition: ParseDisposition(x.Row.PolicyEvaluated.Disposition),
		DKIM:        ParseAuthResult(x.Row.PolicyEvaluated.DKIM),
		SPF:         ParseAuthResult(x.Row.PolicyEvaluated.SPF),
		HeaderFrom:  safe.Domain(x.Identifiers.HeaderFrom),
	}
	for _, d := range x.AuthResults.DKIM {
		if s := safe.Domain(d.Domain); s != "" {
			rec.DKIMDomains = append(rec.DKIMDomains, s)
		}
	}
	for _, s := range x.AuthResults.SPF {
		if s := safe.Domain(s.Domain); s != "" {
			rec.SPFDomains = append(rec.SPFDomains, s)
		}
	}
	return rec, badCount, badIP
}

func epoch(s string) time.Time {
	v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || v <= 0 || v > epochCeiling {
		return time.Time{}
	}
	return time.Unix(v, 0)
}

func addCount(a, b int64) int64 { return safe.AddCount(a, b) }
