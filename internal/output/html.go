package output

import (
	"fmt"
	"html/template"
	"io"
	"math"
	"strings"

	"github.com/scottbrown/franking/internal/aggregate"
	"github.com/scottbrown/franking/internal/diagnose"
)

// Version is the build stamp printed in the report footer.
const Version = "1.0.0"

// WriteHTML renders the run as one self-contained document: the CSS and the
// script are inlined, nothing is fetched, and no web font is used.
//
// Two rules hold this together and must not be relaxed:
//
//   - No untrusted string ever reaches a CSS or a JavaScript context. Class
//     colours are CSS class names chosen from a fixed set, never interpolated
//     colours, and the script reads its data from data- attributes on the
//     rows rather than from an embedded literal. html/template escapes
//     everything on top of that; it is the second line, not the first.
//   - The DMARC pass count is the union of aligned DKIM and aligned SPF. It
//     is carried through from the aggregate, never recomputed from the two
//     column percentages, which cannot express a union.
func WriteHTML(w io.Writer, res *aggregate.Result, opt Options) error {
	opt = opt.withDiagnosis(res)
	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("html: %w", err)
	}
	return tmpl.Execute(w, buildHTMLDoc(res, opt))
}

type htmlDoc struct {
	Domain        string
	RangeLabel    string
	GeneratedAt   string
	PassRate      string
	PassPercent   float64
	VerdictClass  string
	VerdictClause string
	Totals        aggregate.Totals
	FailMessages  int64
	SourceCount   int
	PolicyP       string
	PolicyAdvice  string
	Stats         []htmlStat
	Headline      string
	DiagGroups    []htmlDiagGroup
	Evidence      []string
	Todo          []htmlTodo
	OwnRate       string
	OwnDiffers    bool
	Groups        []htmlGroup
	NoActionNote  string
	Chips         []htmlChip
	Rows          []htmlRow
	RowNote       string
	ShowFiles     bool
	Files         []htmlFile
	FileErrors    []htmlFile
	FileRows      []htmlFile
	Resolve       bool
	Command       string
	Version       string
	Limits        htmlLimits
	Warnings      []string
}

type htmlDiagGroup struct {
	Label    string
	Slug     string
	Sources  string
	Messages int64
	Rate     string
}

type htmlTodo struct {
	Step   int
	Title  string
	Detail string
}

type htmlStat struct {
	Value string
	Label string
	Tone  string
}

type htmlGroup struct {
	Name    string
	Slug    string
	Tally   string
	Advice  string
	Sources []htmlActionSource
}

type htmlActionSource struct {
	IP        string
	MsgsLabel string
	SPFDomain string
}

type htmlChip struct {
	Label   string
	Key     string
	Active  bool
	Slug    string
	Pressed string
}

type htmlRow struct {
	IP         string
	Host       string
	Messages   int64
	ShareWidth float64
	DKIM       string
	SPF        string
	DKIMZero   bool
	SPFZero    bool
	SPFDomain  string
	Class      string
	Slug       string
	Search     string
}

type htmlFile struct {
	Name     string
	Org      string
	Records  int
	Messages int64
	Status   string
	Reason   string
}

type htmlLimits struct {
	MaxFileSize string
	MaxXMLSize  string
	MaxRatio    string
}

// classSlug maps a class onto a CSS class name from a fixed set, so that no
// value from a report can ever reach a stylesheet.
func classSlug(c aggregate.Class) string {
	switch c {
	case aggregate.ClassPass:
		return "pass"
	case aggregate.ClassDKIMOnly:
		return "dkim-only"
	case aggregate.ClassSPFOnly:
		return "spf-only"
	case aggregate.ClassPartial:
		return "partial"
	case aggregate.ClassFail:
		return "fail"
	}
	return "unknown"
}

// needsAction reports whether a class puts a source on the action list. PASS
// and DKIM-ONLY are both a correct end state, so they belong in the closing
// note rather than under a heading that says something must be done.
func needsAction(c aggregate.Class) bool {
	switch c {
	case aggregate.ClassFail, aggregate.ClassPartial, aggregate.ClassSPFOnly:
		return true
	}
	return false
}

var numberWords = []string{"No", "One", "Two", "Three", "Four", "Five",
	"Six", "Seven", "Eight", "Nine"}

func word(n int) string {
	if n >= 0 && n < len(numberWords) {
		return numberWords[n]
	}
	return fmt.Sprintf("%d", n)
}

func buildHTMLDoc(res *aggregate.Result, opt Options) htmlDoc {
	rate := res.Totals.PassRate()
	shown := float64(int64(rate*1000+0.5)) / 10 // one decimal, matching the label

	doc := htmlDoc{
		Domain:       policyDomainOf(res),
		RangeLabel:   rangeText(res),
		GeneratedAt:  timestamp(opt.Now),
		PassRate:     fmt.Sprintf("%.1f%%", shown),
		PassPercent:  clampPercent(shown),
		Totals:       res.Totals,
		FailMessages: res.Totals.Messages - res.Totals.DMARCPass,
		SourceCount:  sourcePopulation(res),
		PolicyP:      policyText(res),
		Resolve:      opt.Resolve,
		Command:      commandLine(opt),
		Version:      Version,
		Warnings:     res.Warnings,
		Limits: htmlLimits{
			MaxFileSize: opt.Limits.MaxFileSize,
			MaxXMLSize:  opt.Limits.MaxXMLSize,
			MaxRatio:    opt.Limits.MaxRatio,
		},
	}

	switch {
	case res.Totals.Messages <= 0:
		doc.VerdictClass = "unknown"
	case shown >= 100:
		doc.VerdictClass = "pass"
	case shown >= 90:
		doc.VerdictClass = "partial"
	default:
		doc.VerdictClass = "fail"
	}

	doc.Stats = []htmlStat{
		{Value: fmt.Sprint(res.FilesFound), Label: "files found", Tone: "ink"},
		{Value: fmt.Sprint(res.FilesParsed), Label: "parsed", Tone: "ink"},
		{Value: fmt.Sprint(res.FilesSkipped), Label: "skipped", Tone: "muted"},
		{Value: fmt.Sprint(res.FilesError), Label: "with errors", Tone: errorTone(res.FilesError)},
		{Value: fmt.Sprint(sourcePopulation(res)), Label: "source addresses", Tone: "ink"},
	}

	grouped := make(map[aggregate.Class][]*aggregate.Source)
	for _, s := range res.Sources {
		class := s.Class()
		grouped[class] = append(grouped[class], s)

		// The haystack indexes only what the reader can actually see, so
		// the hostname joins it only when -resolve put it on screen.
		fields := []string{s.IP}
		if opt.Resolve {
			fields = append(fields, s.Host)
		}
		fields = append(fields, s.SPFDomains()...)
		fields = append(fields, s.DKIMDomains()...)

		doc.Rows = append(doc.Rows, htmlRow{
			IP:         s.IP,
			Host:       s.Host,
			Messages:   s.Messages,
			ShareWidth: clampPercent(share(res, s.Messages) * 100),
			DKIM:       percent(s.Rate(s.DKIMPass)),
			SPF:        percent(s.Rate(s.SPFPass)),
			DKIMZero:   s.DKIMPass == 0,
			SPFZero:    s.SPFPass == 0,
			SPFDomain:  dash(s.PrimarySPFDomain()),
			Class:      string(class),
			Slug:       classSlug(class),
			Search:     haystack(fields...),
		})
	}
	// Chips: "all" plus every class actually present, worst first.
	doc.Chips = append(doc.Chips, htmlChip{
		Label: fmt.Sprintf("all %d", len(res.Sources)), Key: "all",
		Active: true, Slug: "all", Pressed: "true",
	})
	for _, class := range aggregate.Classes() {
		n := len(grouped[class])
		if n == 0 {
			continue
		}
		doc.Chips = append(doc.Chips, htmlChip{
			Label:   fmt.Sprintf("%s %d", class, n),
			Key:     classSlug(class),
			Slug:    classSlug(class),
			Pressed: "false",
		})
	}

	// Action groups, worst first, excluding the two classes that are done.
	needing := 0
	for _, class := range aggregate.Classes() {
		members := grouped[class]
		if len(members) == 0 || !needsAction(class) {
			continue
		}
		needing += len(members)

		var messages int64
		group := htmlGroup{
			Name:   string(class),
			Slug:   classSlug(class),
			Advice: class.Action(),
		}
		for _, s := range members {
			messages += s.Messages
			group.Sources = append(group.Sources, htmlActionSource{
				IP:        s.IP,
				MsgsLabel: fmt.Sprintf("%d msgs", s.Messages),
				SPFDomain: dash(s.PrimarySPFDomain()),
			})
		}
		group.Tally = fmt.Sprintf("%s · %d msgs", plural(len(members), "source"), messages)
		doc.Groups = append(doc.Groups, group)
	}

	d := opt.Diagnosis
	doc.Headline = d.Headline
	doc.VerdictClause = d.Headline
	doc.PolicyAdvice = policyAdviceFrom(d)
	doc.OwnRate = percent(d.OwnRate())
	doc.OwnDiffers = d.OwnMessages != res.Totals.Messages
	for _, k := range d.Order {
		g := d.Group(k)
		doc.DiagGroups = append(doc.DiagGroups, htmlDiagGroup{
			Label:    k.Label(),
			Slug:     kindSlug(k),
			Sources:  plural(g.Count(), "source"),
			Messages: g.Messages,
			Rate:     percent(g.Rate()),
		})
	}
	for i, a := range d.Actions {
		doc.Todo = append(doc.Todo, htmlTodo{Step: i + 1, Title: a.Title, Detail: a.Detail})
	}
	doc.Evidence = d.Evidence
	_ = needing
	// When everything passed, the all-clear block has already said so; a
	// note repeating it underneath is noise.
	dkimOnly := len(grouped[aggregate.ClassDKIMOnly])
	if len(doc.Groups) > 0 || dkimOnly > 0 {
		doc.NoActionNote = noActionNote(len(grouped[aggregate.ClassPass]), dkimOnly)
	}
	doc.RowNote = fmt.Sprintf("Showing all %s, busiest first.",
		plural(len(res.Sources), "address"))

	for _, f := range res.Files {
		row := htmlFile{
			Name: f.Name, Org: dash(f.Org), Records: f.Records,
			Messages: f.Messages, Status: string(f.Status), Reason: f.Reason,
		}
		doc.Files = append(doc.Files, row)
		if f.Status == aggregate.StatusError {
			doc.FileErrors = append(doc.FileErrors, row)
		}
	}
	doc.ShowFiles = opt.ShowFiles
	// Error rows always print; everything else only with -files.
	doc.FileRows = doc.FileErrors
	if opt.ShowFiles {
		doc.FileRows = doc.Files
	}

	return doc
}

// kindSlug maps a diagnosis kind onto a CSS class from a fixed set.
func kindSlug(k diagnose.Kind) string {
	switch k {
	case diagnose.KindPassing:
		return "pass"
	case diagnose.KindForwarded:
		return "dkim-only"
	case diagnose.KindUnsigned:
		return "spf-only"
	case diagnose.KindUnaligned:
		return "partial"
	case diagnose.KindForged:
		return "fail"
	}
	return "unknown"
}

// policyAdviceFrom states the policy position in the diagnosis's terms, so
// a forgery campaign never reads as the reader's own misconfiguration.
func policyAdviceFrom(d *diagnose.Diagnosis) string {
	r := d.Readiness
	out := sentenceOf(capitaliseFirst(r.Reason))
	switch {
	case r.Safe && r.Next != "":
		out += fmt.Sprintf(" Publish p=%s.", r.Next)
	case !r.Safe:
		out += " Leave the policy where it is until that is cleared."
	}
	for _, c := range r.Caveats {
		out += " Note that " + c + "."
	}
	return out
}

func sentenceOf(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasSuffix(s, ".") {
		return s
	}
	return s + "."
}

func capitaliseFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func verdictClause(res *aggregate.Result, needing int) string {
	if res.Totals.Messages <= 0 {
		return "No messages were reported in this range."
	}
	if needing == 0 {
		return "Nothing needs your attention."
	}
	if needing == 1 {
		return "One source needs attention."
	}
	return fmt.Sprintf("%s sources need attention.", word(needing))
}

func policyAdvice(res *aggregate.Result, shown float64) string {
	switch {
	case res.Totals.Messages <= 0:
		return "Nothing was reported, so the policy state cannot be judged from this run."
	case shown >= 100:
		return "Every message authenticated, so tightening the policy is safe."
	}
	return "Below 100 per cent, and some of what is failing is yours — at p=quarantine " +
		"it would land in spam, at p=reject it would be discarded. Clear the sources below first."
}

func noActionNote(passing, dkimOnly int) string {
	if passing == 0 && dkimOnly == 0 {
		return ""
	}
	var b strings.Builder
	if passing > 0 {
		verb := "pass"
		if passing == 1 {
			verb = "passes"
		}
		fmt.Fprintf(&b, "%s %s on both mechanisms.", word(passing), verb)
	}
	if dkimOnly > 0 {
		if b.Len() > 0 {
			b.WriteString(" ")
		}
		subject, verb, pronoun := word(dkimOnly), "are", "they have"
		if dkimOnly == 1 {
			verb, pronoun = "is", "it has"
		}
		if passing > 0 {
			// A new sentence follows the full stop above, so it keeps its
			// capital: "Four pass on both mechanisms. Two more are ..."
			subject += " more"
		}
		fmt.Fprintf(&b, "%s %s DKIM-aligned only, which is what forwarded mail looks like"+
			" — no action, though %s no margin left if signing breaks.", subject, verb, pronoun)
	}
	return b.String()
}

func policyDomainOf(res *aggregate.Result) string {
	for _, f := range res.Files {
		if f.Status == aggregate.StatusOK && f.Domain != "" {
			return f.Domain
		}
	}
	return "unknown domain"
}

func policyText(res *aggregate.Result) string {
	if len(res.Policies) == 0 {
		return "unknown"
	}
	return strings.Join(res.Policies, ", ")
}

func commandLine(opt Options) string {
	cmd := "franking -html report.html"
	if opt.Resolve {
		cmd += " -resolve"
	}
	if opt.ShowFiles {
		cmd += " -files"
	}
	return cmd + " <directory>"
}

// sourcePopulation is every address the run saw, not just the rows the
// table shows: -min-count hides rows, and the headline must not shrink
// because of a display filter.
func sourcePopulation(res *aggregate.Result) int {
	if n := len(res.AllSources); n > 0 {
		return n
	}
	return len(res.Sources)
}

func errorTone(n int) string {
	if n > 0 {
		return "fail"
	}
	return "muted"
}

func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	if noun == "address" {
		return fmt.Sprintf("%d addresses", n)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// clampPercent bounds a percentage to [0,100] and rounds it to one decimal,
// so that a width and the label beside it can never disagree.
func clampPercent(v float64) float64 {
	if v < 0 || math.IsNaN(v) {
		return 0
	}
	if v > 100 {
		return 100
	}
	return math.Round(v*10) / 10
}

// haystack is the lowercased substring index the filter box searches. Empty
// fields are dropped so the string never carries a run of spaces.
func haystack(parts ...string) string {
	kept := parts[:0:0]
	for _, p := range parts {
		if p != "" && p != "-" {
			kept = append(kept, p)
		}
	}
	return strings.ToLower(strings.Join(kept, " "))
}
