package output

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"franking/internal/aggregate"
)

// WriteText prints the run summary, the per-file table, the source table,
// and the action list. No colour and no control bytes.
func WriteText(w io.Writer, res *aggregate.Result, opt Options) error {
	var b strings.Builder

	writeSummary(&b, res)
	writeFiles(&b, res, opt)
	writeSources(&b, res, opt)
	writeActions(&b, res)
	writePolicyLine(&b, res)

	_, err := io.WriteString(w, b.String())
	return err
}

func writeSummary(b *strings.Builder, res *aggregate.Result) {
	tw := tabwriter.NewWriter(b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(b, "Run summary")
	fmt.Fprintf(tw, "  files found\t%d\n", res.FilesFound)
	fmt.Fprintf(tw, "  files parsed\t%d\n", res.FilesParsed)
	fmt.Fprintf(tw, "  files skipped\t%d\n", res.FilesSkipped)
	fmt.Fprintf(tw, "  files with errors\t%d\n", res.FilesError)
	fmt.Fprintf(tw, "  date range\t%s\n", rangeText(res))
	fmt.Fprintf(tw, "  messages\t%d\n", res.Totals.Messages)
	fmt.Fprintf(tw, "  DMARC pass\t%d (%s)\n", res.Totals.DMARCPass, percent(res.Totals.PassRate()))
	fmt.Fprintf(tw, "  source addresses\t%d\n", len(res.Sources))
	tw.Flush()
}

func rangeText(res *aggregate.Result) string {
	if res.Begin.IsZero() && res.End.IsZero() {
		return "none"
	}
	return fmt.Sprintf("%s to %s", timestamp(res.Begin), timestamp(res.End))
}

func writeFiles(b *strings.Builder, res *aggregate.Result, opt Options) {
	rows := make([]aggregate.FileResult, 0, len(res.Files))
	for _, f := range res.Files {
		if opt.ShowFiles || f.Status == aggregate.StatusError {
			rows = append(rows, f)
		}
	}
	if len(rows) == 0 {
		return
	}
	fmt.Fprintf(b, "\nFiles\n")
	tw := tabwriter.NewWriter(b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  FILE\tORG\tREPORT ID\tDOMAIN\tFROM\tTO\tRECORDS\tMESSAGES\tSTATUS\tREASON")
	for _, f := range rows {
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\t%s\n",
			dash(f.Name), dash(f.Org), dash(f.ReportID), dash(f.Domain),
			dash(timestamp(f.Begin)), dash(timestamp(f.End)),
			f.Records, f.Messages, f.Status, dash(f.Reason))
	}
	tw.Flush()
}

func writeSources(b *strings.Builder, res *aggregate.Result, opt Options) {
	fmt.Fprintf(b, "\nSources\n")
	if len(res.Sources) == 0 {
		fmt.Fprintln(b, "  none")
		return
	}
	tw := tabwriter.NewWriter(b, 0, 0, 2, ' ', 0)
	header := "  IP\t"
	if opt.Resolve {
		header += "HOST\t"
	}
	header += "MESSAGES\tSHARE\tDKIM\tSPF\tSPF DOMAIN\tCLASS"
	fmt.Fprintln(tw, header)

	for _, s := range res.Sources {
		fmt.Fprintf(tw, "  %s\t", s.IP)
		if opt.Resolve {
			fmt.Fprintf(tw, "%s\t", dash(s.Host))
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\n",
			s.Messages,
			percent(share(res, s.Messages)),
			percent(s.Rate(s.DKIMPass)),
			percent(s.Rate(s.SPFPass)),
			dash(s.PrimarySPFDomain()),
			s.Class())
	}
	tw.Flush()
}

func writeActions(b *strings.Builder, res *aggregate.Result) {
	fmt.Fprintf(b, "\nActions\n")
	grouped := make(map[aggregate.Class][]*aggregate.Source)
	for _, s := range res.Sources {
		c := s.Class()
		grouped[c] = append(grouped[c], s)
	}
	printed := false
	for _, class := range aggregate.Classes() {
		sources := grouped[class]
		if len(sources) == 0 || class == aggregate.ClassPass {
			continue
		}
		printed = true
		var messages int64
		for _, s := range sources {
			messages += s.Messages
		}
		fmt.Fprintf(b, "  %s  %d source(s), %d message(s) — %s\n",
			class, len(sources), messages, class.Action())
		tw := tabwriter.NewWriter(b, 0, 0, 2, ' ', 0)
		for _, s := range sources {
			fmt.Fprintf(tw, "    %s\t%d message(s)\tspf: %s\n",
				s.IP, s.Messages, dash(s.PrimarySPFDomain()))
		}
		tw.Flush()
	}
	if n := len(grouped[aggregate.ClassPass]); n > 0 {
		fmt.Fprintf(b, "  PASS  %d source(s) need no action.\n", n)
	}
	if !printed && len(grouped[aggregate.ClassPass]) == 0 {
		fmt.Fprintln(b, "  none")
	}
}

func writePolicyLine(b *strings.Builder, res *aggregate.Result) {
	policy := "unknown"
	if len(res.Policies) > 0 {
		policy = strings.Join(res.Policies, ", ")
	}
	rate := res.Totals.PassRate()
	verdict := "below 100%; resolve the sources above before moving the policy forward"
	if res.Totals.Messages > 0 && res.Totals.DMARCPass >= res.Totals.Messages {
		verdict = "at 100% for the full range; the policy can move forward"
	}
	fmt.Fprintf(b, "\nPolicy: p=%s over %s — DMARC pass rate %s, %s.\n",
		policy, rangeText(res), percent(rate), verdict)
}

func share(res *aggregate.Result, messages int64) float64 {
	if res.Totals.Messages <= 0 {
		return 0
	}
	return float64(messages) / float64(res.Totals.Messages)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
