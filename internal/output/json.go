package output

import (
	"encoding/json"
	"io"

	"franking/internal/aggregate"
	"franking/internal/diagnose"
)

type jsonDocument struct {
	GeneratedAt string        `json:"generated_at"`
	Files       []jsonFile    `json:"files"`
	Range       jsonRange     `json:"range"`
	Totals      jsonTotals    `json:"totals"`
	Diagnosis   jsonDiagnosis `json:"diagnosis"`
	Sources     []jsonSource  `json:"sources"`
	Warnings    []string      `json:"warnings,omitempty"`
}

type jsonFile struct {
	Name     string `json:"name"`
	Org      string `json:"org"`
	ReportID string `json:"report_id"`
	Domain   string `json:"domain"`
	Begin    string `json:"begin"`
	End      string `json:"end"`
	Records  int    `json:"records"`
	Messages int64  `json:"messages"`
	Status   string `json:"status"`
	Reason   string `json:"reason,omitempty"`
}

type jsonRange struct {
	Begin string `json:"begin"`
	End   string `json:"end"`
}

type jsonTotals struct {
	Messages  int64    `json:"messages"`
	DMARCPass int64    `json:"dmarc_pass"`
	PassRate  float64  `json:"pass_rate"`
	Policies  []string `json:"policies"`
	Files     struct {
		Found   int `json:"found"`
		Parsed  int `json:"parsed"`
		Skipped int `json:"skipped"`
		Errors  int `json:"errors"`
	} `json:"files"`
}

type jsonDiagnosis struct {
	Headline  string        `json:"headline"`
	Findings  []string      `json:"findings"`
	Evidence  []string      `json:"evidence"`
	Groups    []jsonGroup   `json:"groups"`
	Actions   []jsonAction  `json:"actions"`
	Readiness jsonReadiness `json:"readiness"`
	// OwnMessages and OwnPassRate cover only the sources that look like
	// yours, so a forgery campaign cannot move them.
	OwnMessages int64   `json:"own_messages"`
	OwnPassRate float64 `json:"own_pass_rate"`
	DaysCovered int     `json:"days_covered"`
}

type jsonGroup struct {
	Kind     string  `json:"kind"`
	Label    string  `json:"label"`
	Sources  int     `json:"sources"`
	Messages int64   `json:"messages"`
	PassRate float64 `json:"pass_rate"`
}

type jsonAction struct {
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

type jsonReadiness struct {
	Current string   `json:"current_policy"`
	Next    string   `json:"next_policy,omitempty"`
	Safe    bool     `json:"safe_to_tighten"`
	Reason  string   `json:"reason"`
	Caveats []string `json:"caveats,omitempty"`
}

type jsonSource struct {
	IP           string   `json:"ip"`
	Kind         string   `json:"kind"`
	Host         string   `json:"host,omitempty"`
	Messages     int64    `json:"messages"`
	DKIMPass     int64    `json:"dkim_pass"`
	SPFPass      int64    `json:"spf_pass"`
	DMARCPass    int64    `json:"dmarc_pass"`
	Class        string   `json:"class"`
	DKIMDomains  []string `json:"dkim_domains"`
	SPFDomains   []string `json:"spf_domains"`
	Dispositions []string `json:"dispositions"`
	Orgs         []string `json:"orgs"`
	FirstSeen    string   `json:"first_seen"`
	LastSeen     string   `json:"last_seen"`
}

// WriteJSON prints one JSON object describing the whole run.
func WriteJSON(w io.Writer, res *aggregate.Result, opt Options) error {
	opt = opt.withDiagnosis(res)
	doc := jsonDocument{
		GeneratedAt: rfc3339(opt.Now),
		Files:       make([]jsonFile, 0, len(res.Files)),
		Range:       jsonRange{Begin: rfc3339(res.Begin), End: rfc3339(res.End)},
		Sources:     make([]jsonSource, 0, len(res.Sources)),
		Warnings:    res.Warnings,
	}
	for _, f := range res.Files {
		doc.Files = append(doc.Files, jsonFile{
			Name:     f.Name,
			Org:      f.Org,
			ReportID: f.ReportID,
			Domain:   f.Domain,
			Begin:    rfc3339(f.Begin),
			End:      rfc3339(f.End),
			Records:  f.Records,
			Messages: f.Messages,
			Status:   string(f.Status),
			Reason:   f.Reason,
		})
	}
	doc.Totals.Messages = res.Totals.Messages
	doc.Totals.DMARCPass = res.Totals.DMARCPass
	doc.Totals.PassRate = res.Totals.PassRate()
	doc.Totals.Policies = emptyIfNil(res.Policies)
	doc.Totals.Files.Found = res.FilesFound
	doc.Totals.Files.Parsed = res.FilesParsed
	doc.Totals.Files.Skipped = res.FilesSkipped
	doc.Totals.Files.Errors = res.FilesError

	for _, s := range res.Sources {
		doc.Sources = append(doc.Sources, jsonSource{
			IP:           s.IP,
			Kind:         string(opt.Diagnosis.KindOf(s)),
			Host:         s.Host,
			Messages:     s.Messages,
			DKIMPass:     s.DKIMPass,
			SPFPass:      s.SPFPass,
			DMARCPass:    s.DMARCPass,
			Class:        string(s.Class()),
			DKIMDomains:  emptyIfNil(s.DKIMDomains()),
			SPFDomains:   emptyIfNil(s.SPFDomains()),
			Dispositions: emptyIfNil(s.Dispositions()),
			Orgs:         emptyIfNil(s.Orgs()),
			FirstSeen:    rfc3339(s.FirstSeen),
			LastSeen:     rfc3339(s.LastSeen),
		})
	}

	d := opt.Diagnosis
	doc.Diagnosis = jsonDiagnosis{
		Headline:    d.Headline,
		Findings:    emptyIfNil(findingStrings(d)),
		Evidence:    emptyIfNil(d.Evidence),
		Groups:      make([]jsonGroup, 0, len(d.Order)),
		Actions:     make([]jsonAction, 0, len(d.Actions)),
		OwnMessages: d.OwnMessages,
		OwnPassRate: d.OwnRate(),
		DaysCovered: d.Days,
		Readiness: jsonReadiness{
			Current: d.Readiness.Current,
			Next:    d.Readiness.Next,
			Safe:    d.Readiness.Safe,
			Reason:  d.Readiness.Reason,
			Caveats: d.Readiness.Caveats,
		},
	}
	for _, k := range d.Order {
		g := d.Group(k)
		doc.Diagnosis.Groups = append(doc.Diagnosis.Groups, jsonGroup{
			Kind: string(k), Label: k.Label(),
			Sources: g.Count(), Messages: g.Messages, PassRate: g.Rate(),
		})
	}
	for _, a := range d.Actions {
		doc.Diagnosis.Actions = append(doc.Diagnosis.Actions, jsonAction{Title: a.Title, Detail: a.Detail})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func findingStrings(d *diagnose.Diagnosis) []string {
	out := make([]string, 0, len(d.Findings))
	for _, f := range d.Findings {
		out = append(out, string(f))
	}
	return out
}

func emptyIfNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}
