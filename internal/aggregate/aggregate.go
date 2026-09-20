// Package aggregate collects records across files, keys them by source
// address, and gives each source one classification.
package aggregate

import (
	"sort"
	"time"

	"franking/internal/report"
	"franking/internal/safe"
)

// MaxSources is the number of distinct source addresses held in memory.
const MaxSources = 100000

// FileStatus is the outcome of reading one input file.
type FileStatus string

// The file outcomes.
const (
	StatusOK      FileStatus = "ok"
	StatusSkipped FileStatus = "skipped"
	StatusError   FileStatus = "error"
)

// FileResult is the per-file aggregate.
type FileResult struct {
	Name     string
	Org      string
	ReportID string
	Domain   string
	Begin    time.Time
	End      time.Time
	Records  int
	Messages int64
	Status   FileStatus
	Reason   string
}

// Source is the per-address aggregate, keyed on the source IP across all
// input files.
type Source struct {
	IP        string
	Host      string
	Messages  int64
	DKIMPass  int64
	SPFPass   int64
	DMARCPass int64
	FirstSeen time.Time
	LastSeen  time.Time

	dkimDomains  set
	spfDomains   set
	dispositions set
	orgs         set
}

// DKIMDomains returns the DKIM domains seen in auth_results, sorted.
func (s *Source) DKIMDomains() []string { return s.dkimDomains.sorted() }

// SPFDomains returns the SPF domains seen in auth_results, sorted. This is
// the envelope domain, and it usually identifies the sending service.
func (s *Source) SPFDomains() []string { return s.spfDomains.sorted() }

// Dispositions returns the policies applied to this source, sorted.
func (s *Source) Dispositions() []string { return s.dispositions.sorted() }

// Orgs returns the reporting organizations that saw this source, sorted.
func (s *Source) Orgs() []string { return s.orgs.sorted() }

// PrimarySPFDomain returns the first SPF domain, or an empty string.
func (s *Source) PrimarySPFDomain() string {
	d := s.SPFDomains()
	if len(d) == 0 {
		return ""
	}
	return d[0]
}

// Rate returns part divided by the message total, or zero.
func (s *Source) Rate(part int64) float64 {
	if s.Messages <= 0 {
		return 0
	}
	return float64(part) / float64(s.Messages)
}

// Class returns the classification of this source.
func (s *Source) Class() Class { return Classify(s) }

// Totals is the run-wide message count.
type Totals struct {
	Messages  int64
	DMARCPass int64
}

// PassRate is the share of messages that passed DMARC.
func (t Totals) PassRate() float64 {
	if t.Messages <= 0 {
		return 0
	}
	return float64(t.DMARCPass) / float64(t.Messages)
}

// Result is everything one run produced.
type Result struct {
	Files        []FileResult
	Sources      []*Source
	Totals       Totals
	Begin        time.Time
	End          time.Time
	Policies     []string
	FilesFound   int
	FilesParsed  int
	FilesSkipped int
	FilesError   int
	Warnings     []string
	Truncated    bool
}

// Aggregator builds a Result from parsed reports.
type Aggregator struct {
	maxSources int
	sources    map[string]*Source
	files      []FileResult
	policies   set
	warnings   []string
	begin      time.Time
	end        time.Time
	truncated  bool
}

// New returns an Aggregator that holds at most MaxSources addresses.
func New() *Aggregator { return NewWithLimit(MaxSources) }

// NewWithLimit returns an Aggregator with an explicit address limit.
func NewWithLimit(maxSources int) *Aggregator {
	if maxSources <= 0 {
		maxSources = MaxSources
	}
	return &Aggregator{
		maxSources: maxSources,
		sources:    make(map[string]*Source),
		policies:   set{},
	}
}

// AddFile records the outcome of one input file.
func (a *Aggregator) AddFile(f FileResult) {
	f.Name = safe.FileName(f.Name)
	f.Reason = safe.Reason(f.Reason)
	a.files = append(a.files, f)
}

// Warn records a run-level warning.
func (a *Aggregator) Warn(msg string) { a.warnings = append(a.warnings, safe.Reason(msg)) }

// AddReport folds one parsed report into the aggregates and returns the
// per-file numbers for it.
func (a *Aggregator) AddReport(name string, rep *report.Report) FileResult {
	res := FileResult{
		Name:     safe.FileName(name),
		Org:      rep.Metadata.Org,
		ReportID: rep.Metadata.ReportID,
		Domain:   rep.Policy.Domain,
		Begin:    rep.Metadata.Range.Begin,
		End:      rep.Metadata.Range.End,
		Records:  len(rep.Records),
		Messages: rep.Messages(),
		Status:   StatusOK,
	}
	if rep.Policy.P != "" {
		a.policies.add(rep.Policy.P)
	}
	a.extendRange(rep.Metadata.Range.Begin, rep.Metadata.Range.End)

	for _, rec := range rep.Records {
		a.addRecord(rep, rec)
	}
	return res
}

func (a *Aggregator) addRecord(rep *report.Report, rec report.Record) {
	src, ok := a.sources[rec.SourceIP]
	if !ok {
		if len(a.sources) >= a.maxSources {
			if !a.truncated {
				a.truncated = true
				a.Warn("source address limit reached; later addresses were dropped")
			}
			return
		}
		src = &Source{
			IP:           rec.SourceIP,
			dkimDomains:  set{},
			spfDomains:   set{},
			dispositions: set{},
			orgs:         set{},
		}
		a.sources[rec.SourceIP] = src
	}

	src.Messages = safe.AddCount(src.Messages, rec.Count)
	if rec.DKIM.Passed() {
		src.DKIMPass = safe.AddCount(src.DKIMPass, rec.Count)
	}
	if rec.SPF.Passed() {
		src.SPFPass = safe.AddCount(src.SPFPass, rec.Count)
	}
	if rec.DMARCPass() {
		src.DMARCPass = safe.AddCount(src.DMARCPass, rec.Count)
	}
	for _, d := range rec.DKIMDomains {
		src.dkimDomains.add(d)
	}
	for _, d := range rec.SPFDomains {
		src.spfDomains.add(d)
	}
	src.dispositions.add(string(rec.Disposition))
	if rep.Metadata.Org != "" {
		src.orgs.add(rep.Metadata.Org)
	}
	src.FirstSeen = earliest(src.FirstSeen, rep.Metadata.Range.Begin)
	src.LastSeen = latest(src.LastSeen, rep.Metadata.Range.End)
}

func (a *Aggregator) extendRange(begin, end time.Time) {
	a.begin = earliest(a.begin, begin)
	a.end = latest(a.end, end)
}

// Result returns the finished aggregates. Sources with fewer messages than
// minCount are left out of the source table; the totals still count them.
func (a *Aggregator) Result(minCount int64) *Result {
	res := &Result{
		Files:     a.files,
		Begin:     a.begin,
		End:       a.end,
		Policies:  a.policies.sorted(),
		Warnings:  a.warnings,
		Truncated: a.truncated,
	}
	for _, f := range a.files {
		res.FilesFound++
		switch f.Status {
		case StatusOK:
			res.FilesParsed++
		case StatusSkipped:
			res.FilesSkipped++
		case StatusError:
			res.FilesError++
		}
	}
	for _, s := range a.sources {
		res.Totals.Messages = safe.AddCount(res.Totals.Messages, s.Messages)
		res.Totals.DMARCPass = safe.AddCount(res.Totals.DMARCPass, s.DMARCPass)
		if s.Messages < minCount {
			continue
		}
		res.Sources = append(res.Sources, s)
	}
	sort.Slice(res.Sources, func(i, j int) bool {
		if res.Sources[i].Messages != res.Sources[j].Messages {
			return res.Sources[i].Messages > res.Sources[j].Messages
		}
		return res.Sources[i].IP < res.Sources[j].IP
	})
	return res
}

type set map[string]struct{}

func (s set) add(v string) {
	if v == "" {
		return
	}
	s[v] = struct{}{}
}

func (s set) sorted() []string {
	if len(s) == 0 {
		return nil
	}
	out := make([]string, 0, len(s))
	for v := range s {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func earliest(a, b time.Time) time.Time {
	if b.IsZero() {
		return a
	}
	if a.IsZero() || b.Before(a) {
		return b
	}
	return a
}

func latest(a, b time.Time) time.Time {
	if b.IsZero() {
		return a
	}
	if a.IsZero() || b.After(a) {
		return b
	}
	return a
}
