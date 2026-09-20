package output

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"franking/internal/aggregate"
	"franking/internal/diagnose"
)

// WriteText prints the run summary, the per-file table, the source table,
// and the action list. No colour and no control bytes.
func WriteText(w io.Writer, res *aggregate.Result, opt Options) error {
	opt = opt.withDiagnosis(res)
	var b strings.Builder

	writeSummary(&b, res)
	writeDiagnosis(&b, opt.Diagnosis)
	writeFiles(&b, res, opt)
	writeSources(&b, res, opt)
	writeTodo(&b, opt.Diagnosis)
	writePolicyLine(&b, res, opt.Diagnosis)

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
	fmt.Fprintf(tw, "  source addresses\t%d\n", sourcePopulation(res))
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

// writeDiagnosis prints what the run actually shows: the split between
// mail that looks like yours and mail that does not, and the evidence for
// calling it that way.
func writeDiagnosis(b *strings.Builder, d *diagnose.Diagnosis) {
	if d == nil {
		return
	}
	fmt.Fprintf(b, "\nDiagnosis\n  %s\n", d.Headline)
	if len(d.Order) > 0 {
		fmt.Fprintln(b)
		tw := tabwriter.NewWriter(b, 0, 0, 2, ' ', 0)
		for _, kind := range d.Order {
			g := d.Group(kind)
			fmt.Fprintf(tw, "  %s\t%s\t%d messages\t%s pass\n",
				kind.Label(), plural(g.Count(), "source"), g.Messages, percent(g.Rate()))
		}
		tw.Flush()
	}
	for _, line := range d.Evidence {
		fmt.Fprintf(b, "\n  %s\n", wrap(line, 74, "  "))
	}
}

// writeTodo prints the ordered steps, which is the whole point of the run.
func writeTodo(b *strings.Builder, d *diagnose.Diagnosis) {
	if d == nil || len(d.Actions) == 0 {
		return
	}
	fmt.Fprintf(b, "\nWhat to do\n")
	for i, a := range d.Actions {
		fmt.Fprintf(b, "  %d. %s\n", i+1, a.Title)
		fmt.Fprintf(b, "     %s\n", wrap(a.Detail, 71, "     "))
	}
}

func writePolicyLine(b *strings.Builder, res *aggregate.Result, d *diagnose.Diagnosis) {
	policy := "unknown"
	if len(res.Policies) > 0 {
		policy = strings.Join(res.Policies, ", ")
	}
	if res.Totals.Messages <= 0 {
		fmt.Fprintf(b, "\nPolicy: p=%s — no messages were reported, so the policy state is unknown.\n",
			policy)
		return
	}
	// The run-wide rate is whatever the senders — including a forger —
	// happen to produce. The rate over your own mail is the one to act on.
	rates := fmt.Sprintf("DMARC pass rate %s", percent(res.Totals.PassRate()))
	if d != nil && d.OwnMessages != res.Totals.Messages {
		rates += fmt.Sprintf(" overall, %s over your own senders", percent(d.OwnRate()))
	}
	verdict := "the policy should not move yet"
	if d != nil {
		switch {
		case d.Readiness.Safe && d.Readiness.Next != "":
			verdict = fmt.Sprintf("move to p=%s", d.Readiness.Next)
		case d.Readiness.Safe:
			verdict = "the policy is already at its strongest"
		default:
			verdict = "the policy should not move yet"
		}
	}
	fmt.Fprintf(b, "\nPolicy: p=%s over %s — %s; %s.\n",
		policy, rangeText(res), rates, verdict)
}

// wrap breaks a sentence onto lines of at most width runes, indenting every
// line after the first, so a long explanation stays readable in a terminal.
func wrap(text string, width int, indent string) string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return ""
	}
	var b strings.Builder
	line := 0
	for i, w := range words {
		switch {
		case i == 0:
			b.WriteString(w)
			line = len(w)
		case line+1+len(w) > width:
			b.WriteString("\n" + indent + w)
			line = len(w)
		default:
			b.WriteString(" " + w)
			line += 1 + len(w)
		}
	}
	return b.String()
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
