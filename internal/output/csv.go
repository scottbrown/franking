package output

import (
	"encoding/csv"
	"io"
	"strconv"
	"strings"

	"franking/internal/aggregate"
	"franking/internal/safe"
)

// WriteCSV prints the source table with a header row. Every cell passes
// through safe.CSVCell, so a spreadsheet never treats one as a formula.
func WriteCSV(w io.Writer, res *aggregate.Result, opt Options) error {
	opt = opt.withDiagnosis(res)
	cw := csv.NewWriter(w)

	header := []string{"ip"}
	if opt.Resolve {
		header = append(header, "host")
	}
	header = append(header,
		"messages", "share", "dkim_pass", "spf_pass", "dmarc_pass",
		"dkim_aligned_rate", "spf_aligned_rate", "dmarc_pass_rate",
		"spf_domains", "dkim_domains", "dispositions", "orgs",
		"first_seen", "last_seen", "class", "kind")
	if err := cw.Write(escapeRow(header)); err != nil {
		return err
	}

	for _, s := range res.Sources {
		row := []string{s.IP}
		if opt.Resolve {
			row = append(row, s.Host)
		}
		row = append(row,
			strconv.FormatInt(s.Messages, 10),
			rate(share(res, s.Messages)),
			strconv.FormatInt(s.DKIMPass, 10),
			strconv.FormatInt(s.SPFPass, 10),
			strconv.FormatInt(s.DMARCPass, 10),
			rate(s.Rate(s.DKIMPass)),
			rate(s.Rate(s.SPFPass)),
			rate(s.Rate(s.DMARCPass)),
			strings.Join(s.SPFDomains(), " "),
			strings.Join(s.DKIMDomains(), " "),
			strings.Join(s.Dispositions(), " "),
			strings.Join(s.Orgs(), " "),
			rfc3339(s.FirstSeen),
			rfc3339(s.LastSeen),
			string(s.Class()),
			string(opt.Diagnosis.KindOf(s)),
		)
		if err := cw.Write(escapeRow(row)); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func escapeRow(row []string) []string {
	out := make([]string, len(row))
	for i, cell := range row {
		out[i] = safe.CSVCell(cell)
	}
	return out
}

func rate(v float64) string { return strconv.FormatFloat(v, 'f', 4, 64) }
