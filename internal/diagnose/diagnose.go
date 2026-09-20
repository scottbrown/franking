// Package diagnose reads the aggregates and works out what is actually
// happening to a domain's mail: whether the failures are senders of yours
// that are not aligned, or someone forging your domain, and what to do next.
//
// The distinction matters because the two look identical in a pass rate and
// call for opposite actions. An unaligned sender of yours is a reason NOT to
// tighten the policy, because tightening would start discarding your own
// mail. A forgery campaign is the reason TO tighten, and it drags the
// headline pass rate down while doing so.
package diagnose

import (
	"fmt"
	"sort"
	"strings"

	"franking/internal/aggregate"
)

// Kind is what one source appears to be.
type Kind string

// The kinds a source can take.
const (
	// KindPassing authenticates. Nothing to do.
	KindPassing Kind = "passing"
	// KindForwarded is DKIM-aligned with SPF broken by a forwarding hop.
	KindForwarded Kind = "forwarded"
	// KindUnsigned is SPF-aligned but never signed. It passes DMARC today
	// and has no margin left if SPF breaks.
	KindUnsigned Kind = "unsigned"
	// KindUnaligned fails, but identifies itself: it either attempted a
	// DKIM signature or used its own envelope domain. That is what a
	// sender of yours with a configuration gap looks like.
	KindUnaligned Kind = "unaligned"
	// KindForged fails, claims your domain, carries no signature, and is
	// one of many such sources each sending almost nothing.
	KindForged Kind = "forged"
	// KindUnidentified fails and claims your domain with no signature, but
	// the population is too small or too concentrated to call it forgery.
	// It may be a server of yours that was never added to SPF.
	KindUnidentified Kind = "unidentified"
)

// Thresholds for reading the shape of the unattributed population. These
// are judgement calls rather than anything standardised, so they live in one
// place where they can be argued with.
const (
	// A forgery fleet is many sources each sending almost nothing. A broken
	// sender of yours is one or two sources each sending a lot.
	dispersedMinSources = 8
	dispersedTinyMsgs   = 2
	dispersedTinyShare  = 0.6

	// Below this much evidence, say so rather than sounding certain.
	thinSampleDays     = 14
	thinSampleMessages = 100
)

// Finding is a headline conclusion about the run.
type Finding string

// The findings, most urgent first.
const (
	FindingForgery    Finding = "forgery"
	FindingUnaligned  Finding = "unaligned-senders"
	FindingUnknowns   Finding = "unidentified-sources"
	FindingForwarding Finding = "forwarding"
	FindingHealthy    Finding = "healthy"
	FindingNoData     Finding = "no-data"
)

// Group is one bucket of sources with its totals.
type Group struct {
	Kind     Kind
	Sources  []*aggregate.Source
	Messages int64
}

// Count returns the number of sources in the group.
func (g Group) Count() int { return len(g.Sources) }

// Pass returns the DMARC-passing message count in the group.
func (g Group) Pass() int64 {
	var n int64
	for _, s := range g.Sources {
		n += s.DMARCPass
	}
	return n
}

// Rate returns the group's DMARC pass rate.
func (g Group) Rate() float64 {
	if g.Messages <= 0 {
		return 0
	}
	return float64(g.Pass()) / float64(g.Messages)
}

// Action is one recommended step, in the order it should be taken.
type Action struct {
	Title  string
	Detail string
}

// Readiness is the advice about the published policy.
type Readiness struct {
	Current string // the p= value the reports carry
	Next    string // the value to move to, or "" when it should not move
	Safe    bool
	Reason  string
	Caveats []string
}

// Diagnosis is the whole assessment.
type Diagnosis struct {
	Findings []Finding
	Headline string

	Groups map[Kind]Group
	Order  []Kind

	// OwnMessages and OwnPass cover only the sources that look like yours,
	// so a forgery campaign cannot move the number.
	OwnMessages int64
	OwnPass     int64

	// HeadlineRate is the raw run-wide rate, which a forgery campaign can
	// and does move.
	HeadlineRate float64

	Evidence  []string
	Actions   []Action
	Readiness Readiness
	Days      int

	byIP map[string]Kind
}

// KindOf returns what a source was judged to be.
func (d *Diagnosis) KindOf(s *aggregate.Source) Kind {
	if s == nil || d.byIP == nil {
		return KindUnidentified
	}
	if k, ok := d.byIP[s.IP]; ok {
		return k
	}
	return KindUnidentified
}

// Label returns a short human name for a kind.
func (k Kind) Label() string {
	switch k {
	case KindPassing:
		return "your sender"
	case KindForwarded:
		return "forwarded"
	case KindUnsigned:
		return "unsigned"
	case KindUnaligned:
		return "not aligned"
	case KindForged:
		return "forged"
	}
	return "unidentified"
}

// OwnRate is the pass rate over the sources that look like yours.
func (d *Diagnosis) OwnRate() float64 {
	if d.OwnMessages <= 0 {
		return 0
	}
	return float64(d.OwnPass) / float64(d.OwnMessages)
}

// Has reports whether the diagnosis carries a finding.
func (d *Diagnosis) Has(f Finding) bool {
	for _, got := range d.Findings {
		if got == f {
			return true
		}
	}
	return false
}

// Group returns a bucket, which may be empty.
func (d *Diagnosis) Group(k Kind) Group { return d.Groups[k] }

// Run assesses a finished result.
func Run(res *aggregate.Result) *Diagnosis {
	d := &Diagnosis{
		Groups:       map[Kind]Group{},
		byIP:         map[string]Kind{},
		HeadlineRate: res.Totals.PassRate(),
		Days:         daysCovered(res),
	}
	// Always reason over every address: -min-count hides rows from the
	// table, and must not be able to change the conclusion.
	population := res.AllSources
	if len(population) == 0 {
		population = res.Sources
	}
	if len(population) == 0 || res.Totals.Messages == 0 {
		d.Findings = []Finding{FindingNoData}
		d.Headline = "Nothing was reported for this range, so there is nothing to judge yet."
		d.Readiness = Readiness{Current: policyOf(res), Reason: "no messages were reported"}
		return d
	}

	domains := res.Domains
	kinds := make(map[Kind][]*aggregate.Source)

	// First pass: everything except the unattributed, which needs the shape
	// of its own population before it can be called.
	var unattributed []*aggregate.Source
	for _, s := range population {
		switch classify(s, domains) {
		case KindPassing:
			kinds[KindPassing] = append(kinds[KindPassing], s)
		case KindForwarded:
			kinds[KindForwarded] = append(kinds[KindForwarded], s)
		case KindUnsigned:
			kinds[KindUnsigned] = append(kinds[KindUnsigned], s)
		case KindUnaligned:
			kinds[KindUnaligned] = append(kinds[KindUnaligned], s)
		default:
			unattributed = append(unattributed, s)
		}
	}

	// Second pass: many sources each sending almost nothing is a fleet, not
	// a misconfiguration. One or two sending a lot is the opposite.
	tiny := 0
	for _, s := range unattributed {
		if s.Messages <= dispersedTinyMsgs {
			tiny++
		}
	}
	dispersed := len(unattributed) >= dispersedMinSources &&
		float64(tiny)/float64(len(unattributed)) >= dispersedTinyShare
	unattributedKind := KindUnidentified
	if dispersed {
		unattributedKind = KindForged
	}
	kinds[unattributedKind] = append(kinds[unattributedKind], unattributed...)

	for _, k := range []Kind{KindPassing, KindForwarded, KindUnsigned, KindUnaligned, KindForged, KindUnidentified} {
		list := kinds[k]
		if len(list) == 0 {
			continue
		}
		var messages int64
		for _, s := range list {
			messages += s.Messages
		}
		d.Groups[k] = Group{Kind: k, Sources: list, Messages: messages}
		d.Order = append(d.Order, k)
		for _, src := range list {
			d.byIP[src.IP] = k
		}
	}

	// Your own mail is everything that is not a forgery.
	for _, k := range []Kind{KindPassing, KindForwarded, KindUnsigned, KindUnaligned, KindUnidentified} {
		g := d.Groups[k]
		d.OwnMessages += g.Messages
		for _, s := range g.Sources {
			d.OwnPass += s.DMARCPass
		}
	}

	d.Findings = findings(d)
	d.Headline = headline(d)
	d.Evidence = evidence(d, tiny, dispersed)
	d.Readiness = readiness(d, res)
	d.Actions = actions(d, res)
	return d
}

// classify reads one source. The unattributed case is resolved by Run,
// because it depends on the shape of the whole population.
func classify(s *aggregate.Source, policyDomains []string) Kind {
	switch s.Class() {
	case aggregate.ClassPass:
		return KindPassing
	case aggregate.ClassDKIMOnly:
		return KindForwarded
	case aggregate.ClassSPFOnly:
		return KindUnsigned
	case aggregate.ClassPartial:
		// Something from here authenticates, so something here is yours.
		return KindUnaligned
	}

	// Everything below fails outright. The question is whether it owns up
	// to who it is.
	if len(s.DKIMDomains()) > 0 {
		// Only a sender holding a key for your domain attempts a signature.
		// A failing one is a key or selector problem, not a stranger.
		return KindUnaligned
	}
	for _, envelope := range s.SPFDomains() {
		if envelope != "" && !aligns(envelope, policyDomains) {
			// It used its own bounce domain, the way a real service does.
			return KindUnaligned
		}
	}
	return KindUnidentified
}

// aligns reports whether an envelope domain is the policy domain or a
// subdomain of it, which is relaxed DMARC alignment.
func aligns(envelope string, policyDomains []string) bool {
	e := strings.ToLower(strings.TrimSuffix(envelope, "."))
	for _, d := range policyDomains {
		p := strings.ToLower(strings.TrimSuffix(d, "."))
		if p == "" {
			continue
		}
		if e == p || strings.HasSuffix(e, "."+p) {
			return true
		}
	}
	return false
}

func findings(d *Diagnosis) []Finding {
	var out []Finding
	if d.Groups[KindForged].Count() > 0 {
		out = append(out, FindingForgery)
	}
	if d.Groups[KindUnaligned].Count() > 0 {
		out = append(out, FindingUnaligned)
	}
	if d.Groups[KindUnidentified].Count() > 0 {
		out = append(out, FindingUnknowns)
	}
	if d.Groups[KindForwarded].Count() > 0 {
		out = append(out, FindingForwarding)
	}
	if len(out) == 0 {
		out = append(out, FindingHealthy)
	}
	return out
}

func headline(d *Diagnosis) string {
	forged := d.Groups[KindForged]
	unaligned := d.Groups[KindUnaligned]
	unknown := d.Groups[KindUnidentified]

	switch {
	case forged.Count() > 0 && unaligned.Count() > 0:
		return fmt.Sprintf("Someone is forging your domain, and %s of yours %s not aligned.",
			plural(unaligned.Count(), "sender"), isAre(unaligned.Count()))
	case forged.Count() > 0:
		return "Your own mail is healthy. Someone is forging your domain."
	case unaligned.Count() > 0:
		return fmt.Sprintf("%s of yours %s not aligned.",
			capitalise(plural(unaligned.Count(), "sender")), isAre(unaligned.Count()))
	case unknown.Count() > 0:
		return fmt.Sprintf("%s could not be identified from the reports alone.",
			capitalise(plural(unknown.Count(), "source")))
	case d.Groups[KindUnsigned].Count() > 0:
		return "Everything authenticates, though some of it rests on SPF alone."
	case d.Groups[KindForwarded].Count() > 0:
		return "Everything authenticates. Some of it arrives forwarded, which is normal."
	}
	return "Everything authenticates."
}

func evidence(d *Diagnosis, tiny int, dispersed bool) []string {
	var out []string
	if forged := d.Groups[KindForged]; forged.Count() > 0 {
		out = append(out, fmt.Sprintf(
			"%s carried no DKIM signature and used your own domain as the envelope — "+
				"the shape of a forgery, not a misconfiguration",
			plural(forged.Count(), "source")))
		if dispersed {
			out = append(out, fmt.Sprintf(
				"the volume is spread thin: %d of %d sent %d messages or fewer",
				tiny, forged.Count(), dispersedTinyMsgs))
		}
		out = append(out, fmt.Sprintf(
			"the headline pass rate of %s is set by that forged mail; over your own senders it is %s",
			pct(d.HeadlineRate), pct(d.OwnRate())))
	}
	if unaligned := d.Groups[KindUnaligned]; unaligned.Count() > 0 {
		for _, s := range topSources(unaligned.Sources, 4) {
			out = append(out, fmt.Sprintf("%s — %d messages, %s",
				s.IP, s.Messages, why(s)))
		}
	}
	if unknown := d.Groups[KindUnidentified]; unknown.Count() > 0 {
		out = append(out, fmt.Sprintf(
			"%s claimed your domain with no signature but sent too much, or are too few, "+
				"to call a forgery — one may be a server of yours that was never added to SPF",
			plural(unknown.Count(), "source")))
	}
	return out
}

// why says, in a few words, what is wrong with one unaligned sender.
func why(s *aggregate.Source) string {
	switch {
	case s.Class() == aggregate.ClassPartial:
		return "some of its mail authenticates and some does not"
	case len(s.DKIMDomains()) > 0 && s.SPFPass == 0:
		return "signs with a key that does not verify, and SPF does not cover it"
	case len(s.DKIMDomains()) > 0:
		return "signs with a key that does not verify"
	case s.PrimarySPFDomain() != "":
		return "sends as " + s.PrimarySPFDomain() + ", which is not aligned with your domain"
	}
	return "neither SPF nor DKIM is aligned"
}

func readiness(d *Diagnosis, res *aggregate.Result) Readiness {
	r := Readiness{Current: policyOf(res)}

	blocked := d.Groups[KindUnaligned].Count() > 0 || d.Groups[KindUnidentified].Count() > 0
	if blocked {
		r.Safe = false
		r.Reason = "mail that looks like yours is still failing, and tightening would start " +
			"acting on it"
		return r
	}
	if d.OwnRate() < 1 {
		r.Safe = false
		r.Reason = "not all of your own mail authenticates yet"
		return r
	}

	r.Safe = true
	r.Next = nextPolicy(r.Current)
	r.Reason = fmt.Sprintf("every one of your %s authenticates, so tightening acts only on "+
		"mail that is not yours", plural(ownSourceCount(d), "sender"))
	if r.Next == "" {
		r.Reason = "the policy is already at its strongest"
	}
	if d.Days > 0 && d.Days < thinSampleDays {
		r.Caveats = append(r.Caveats, fmt.Sprintf(
			"this is %s of data; a sender that did not send this week would not appear in it",
			plural(d.Days, "day")))
	}
	if d.OwnMessages < thinSampleMessages {
		r.Caveats = append(r.Caveats, fmt.Sprintf(
			"only %d messages of your own were reported, which is a thin sample", d.OwnMessages))
	}
	return r
}

func actions(d *Diagnosis, res *aggregate.Result) []Action {
	var out []Action

	for _, s := range topSources(d.Groups[KindUnaligned].Sources, 6) {
		out = append(out, Action{
			Title:  fmt.Sprintf("Fix %s (%d messages)", s.IP, s.Messages),
			Detail: sentence(capitalise(why(s))) + " " + fixHint(s),
		})
	}

	if g := d.Groups[KindUnsigned]; g.Count() > 0 {
		out = append(out, Action{
			Title: fmt.Sprintf("Add DKIM signing for %s", plural(g.Count(), "sender")),
			Detail: "These pass DMARC on SPF alone, so nothing breaks today, but they have " +
				"no margin left: one forwarding hop or one SPF change and their mail fails.",
		})
	}

	if n := d.Groups[KindUnidentified].Count(); n > 0 {
		out = append(out, Action{
			Title: fmt.Sprintf("Identify %s", plural(n, "source")),
			Detail: "These claim your domain and carry no signature. Re-run with -resolve to " +
				"see who owns the addresses: if one is yours, add it to SPF or sign it; if not, " +
				"it is forgery and the policy should tighten.",
		})
	}

	r := d.Readiness
	switch {
	case r.Safe && r.Next != "":
		detail := sentence(capitalise(r.Reason)) + fmt.Sprintf(" Publish p=%s.", r.Next)
		if d.Groups[KindForged].Count() > 0 {
			detail += fmt.Sprintf(" That is what stops the %s of forged mail from being delivered.",
				messagesLabel(d.Groups[KindForged].Messages))
		}
		for _, c := range r.Caveats {
			detail += " Note that " + c + "."
		}
		out = append(out, Action{
			Title:  fmt.Sprintf("Move the policy from p=%s to p=%s", r.Current, r.Next),
			Detail: detail,
		})
	case !r.Safe && r.Current != "" && r.Current != "unknown":
		out = append(out, Action{
			Title:  fmt.Sprintf("Leave the policy at p=%s for now", r.Current),
			Detail: sentence(capitalise(r.Reason)) + " Clear the sources above first.",
		})
	}

	if d.Groups[KindForged].Count() > 0 && strings.EqualFold(r.Current, "reject") {
		out = append(out, Action{
			Title: "Nothing further for the forged mail",
			Detail: "The policy already tells receivers to reject it. The volume in these " +
				"reports is what was refused, not what was delivered.",
		})
	}
	return out
}

func fixHint(s *aggregate.Source) string {
	switch {
	case len(s.DKIMDomains()) > 0:
		return "Check the selector and the published key for " +
			strings.Join(s.DKIMDomains(), ", ") + "."
	case s.PrimarySPFDomain() != "":
		return "Either add DKIM signing at that service, or have it send with an envelope " +
			"domain under yours so SPF aligns."
	}
	return "Add this sender to SPF, or sign its mail with DKIM."
}

func ownSourceCount(d *Diagnosis) int {
	n := 0
	for _, k := range []Kind{KindPassing, KindForwarded, KindUnsigned, KindUnaligned, KindUnidentified} {
		n += d.Groups[k].Count()
	}
	return n
}

func nextPolicy(current string) string {
	switch strings.ToLower(strings.TrimSpace(current)) {
	case "none":
		return "quarantine"
	case "quarantine":
		return "reject"
	case "reject":
		return ""
	}
	return "quarantine"
}

func policyOf(res *aggregate.Result) string {
	if len(res.Policies) == 0 {
		return "unknown"
	}
	return strings.Join(res.Policies, ", ")
}

func daysCovered(res *aggregate.Result) int {
	if res.Begin.IsZero() || res.End.IsZero() || !res.End.After(res.Begin) {
		return 0
	}
	d := int(res.End.Sub(res.Begin).Hours()/24 + 0.5)
	if d < 1 {
		return 1
	}
	return d
}

func topSources(list []*aggregate.Source, n int) []*aggregate.Source {
	out := make([]*aggregate.Source, len(list))
	copy(out, list)
	sort.Slice(out, func(i, j int) bool { return out[i].Messages > out[j].Messages })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func isAre(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}

// sentence ensures a clause ends as one.
func sentence(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasSuffix(s, ".") {
		return s
	}
	return s + "."
}

func capitalise(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func pct(v float64) string { return fmt.Sprintf("%.1f%%", v*100) }

func messagesLabel(n int64) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s + " messages"
	}
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	return b.String() + " messages"
}
