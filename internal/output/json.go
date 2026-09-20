package output

import (
	"encoding/json"
	"io"

	"franking/internal/aggregate"
)

type jsonDocument struct {
	GeneratedAt string       `json:"generated_at"`
	Files       []jsonFile   `json:"files"`
	Range       jsonRange    `json:"range"`
	Totals      jsonTotals   `json:"totals"`
	Sources     []jsonSource `json:"sources"`
	Warnings    []string     `json:"warnings,omitempty"`
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

type jsonSource struct {
	IP           string   `json:"ip"`
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

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func emptyIfNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}
