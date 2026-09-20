# franking

Local-first DMARC report processor.

A franking mark on a letter shows that the postage is paid and that the
sender is who they say they are. `franking` reads a local directory of DMARC
aggregate reports and tells you which senders carry a valid mark for your
domain.

It runs on demand, keeps no state between runs, makes no network call unless
you ask for one, and never modifies the files it reads.

## Build

```sh
task build          # writes .build/franking
```

Or without Go Task:

```sh
go build -o .build/franking ./cmd/franking
```

The tool needs Go 1.22 or later and no dependencies at all — standard
library only.

## Usage

```
franking [flags] <directory>
```

Download the aggregate reports from the mailbox at your `rua` address, put
them in a directory, and point `franking` at it. It reads `.zip`, `.gz`, and
plain `.xml` files.

### Example

```sh
$ franking -files ./reports
Run summary
  files found        6
  files parsed       4
  files skipped      0
  files with errors  2
  date range         2023-11-14 15:13 to 2023-11-18 15:13
  messages           199
  DMARC pass         181 (91.0%)
  source addresses   6

Files
  FILE                                     ORG                ...  RECORDS  MESSAGES  STATUS  REASON
  google.com!example.ca!1700000000!...zip  google.com         ...  3        155       ok      -
  malformed.xml                            -                  ...  0        0         error   xml: syntax error at line 9
  ...

Sources
  IP             MESSAGES  SHARE  DKIM    SPF     SPF DOMAIN                 CLASS
  192.0.2.25     100       50.3%  100.0%  100.0%  example.ca                 PASS
  203.0.113.10   50        25.1%  100.0%  0.0%    mail.vendor.net            DKIM-ONLY
  192.0.2.200    21        10.6%  100.0%  0.0%    bounce.example-sender.net  DKIM-ONLY
  198.51.100.77  18        9.0%   0.0%    0.0%    bulk.example-sender.net    FAIL
  203.0.113.99   7         3.5%   0.0%    100.0%  mail.vendor.net            SPF-ONLY
  2001:db8::1    3         1.5%   100.0%  100.0%  example.ca                 PASS

Actions
  FAIL  1 source(s), 18 message(s) — Unauthorized, or a sender of yours with no SPF or DKIM record. Identify the SPF domain first.
    198.51.100.77  18 message(s)  spf: bulk.example-sender.net
  SPF-ONLY  1 source(s), 7 message(s) — Sender does not sign. Add DKIM if the sender is yours.
    203.0.113.99  7 message(s)  spf: mail.vendor.net
  DKIM-ONLY  2 source(s), 71 message(s) — DKIM aligned, SPF not. Normal for forwarded mail. No action.
    203.0.113.10  50 message(s)  spf: mail.vendor.net
    192.0.2.200   21 message(s)  spf: bounce.example-sender.net
  PASS  2 source(s) need no action.

Policy: p=none over 2023-11-14 15:13 to 2023-11-18 15:13 — DMARC pass rate 91.0%, below 100%; resolve the sources above before moving the policy forward.
```

Machine-readable output:

```sh
franking -format json ./reports | jq '.sources[] | select(.class == "FAIL")'
franking -format csv  ./reports > sources.csv
```

## The five classes

Each sending address gets exactly one class. Sources are sorted by message
count, highest first, because volume shows which problem to solve first.

| Class | Rule | Meaning and action |
|---|---|---|
| `PASS` | DMARC pass rate 100% | Known good sender. No action. |
| `DKIM-ONLY` | DKIM aligned 100%, SPF aligned 0% | Normal for forwarded mail. No action. |
| `SPF-ONLY` | SPF aligned 100%, DKIM aligned 0% | The sender does not sign. Add DKIM if the sender is yours. |
| `PARTIAL` | DMARC pass rate above 0% and below 100% | The configuration is not complete. Investigate. |
| `FAIL` | DMARC pass rate 0% | Unauthorized, or a sender of yours with no SPF or DKIM record. Identify the SPF domain first. |

`DKIM-ONLY` and `SPF-ONLY` are checked before `PASS`, because both of them
also reach a 100% DMARC pass rate. The distinction matters: a sender that
passes on one mechanism only has no margin left if that mechanism breaks.

The `SPF DOMAIN` column is the envelope domain from `auth_results`. It
usually names the service that sent the mail, which is where the fix goes.

## Flags

| Flag | Default | Function |
|---|---|---|
| `-format` | `text` | Output format: `text`, `json`, or `csv` |
| `-since` | none | Ignore reports whose range ends before this date (`YYYY-MM-DD`) |
| `-domain` | none | Process only reports for this policy domain |
| `-min-count` | `1` | Hide sources with fewer messages than this |
| `-resolve` | `false` | Do a reverse DNS lookup on each source IP |
| `-files` | `false` | Show the per-file table |
| `-recurse` | `false` | Read subdirectories, to a depth of 8 |
| `-max-file-size` | `50MB` | Reject an input file larger than this |
| `-max-xml-size` | `64MB` | Reject a report that expands beyond this |
| `-max-ratio` | `200` | Reject a compression ratio above this |
| `-timeout` | `5m` | Stop the whole run after this time |
| `-v` | `false` | Show parse warnings and skipped files on stderr |

Sizes accept a plain byte count or a suffix: `1048576`, `1MB`, `512KB`,
`2GB`.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | At least one file parsed |
| `1` | No file parsed |
| `2` | Usage error |

A file that does not parse never stops the run. It gets one line in the
per-file table with the reason, and error rows always print even without
`-files`.

## Limits

Anyone on the internet can send a report to the address in your `rua` tag.
Every input file is treated as hostile. These limits hold on every run.

| Limit | Default | Flag |
|---|---|---|
| Input file size on disk | 50 MB | `-max-file-size` |
| Decompressed bytes for one report | 64 MB | `-max-xml-size` |
| Compression ratio (decompressed ÷ compressed) | 200:1 | `-max-ratio` |
| Total run time | 5 minutes | `-timeout` |
| Zip members examined for one file | 16 | — |
| Records accepted from one report | 200000 | — |
| Distinct source addresses held in memory | 100000 | — |
| XML element depth | 32 | — |
| Directory depth with `-recurse` | 8 | — |
| Files read in one run | 10000 | — |

## What the tool will not do

- It never writes a file. Archive members are parsed as a stream in memory,
  and an archive member name is never used as a path, so `zip slip` has
  nothing to work with. The input directory is opened read-only.
- It never starts another process or a shell.
- It never reads a file path out of the environment.
- It never resolves an XML entity, external or otherwise, and it rejects
  any character encoding other than `utf-8`, `us-ascii`, `iso-8859-1`, and
  `windows-1252`.
- It never follows a symlink in the input directory, so a link to
  `/dev/zero` or to a file elsewhere on the disk is skipped.
- It never prints a byte from a report that a terminal would act on.
  Control characters, C1 codes, and bidirectional overrides are removed
  from every untrusted string, and every CSV cell that a spreadsheet would
  treat as a formula is prefixed with a single quote.

### Network

By default `franking` makes **no network call**.

`-resolve` is the one exception: it does a PTR lookup for each source
address, which **sends those addresses to your DNS resolver**. If that
matters for your situation, leave it off. A PTR record is a string that the
owner of the address controls, so the answer is sanitized like any other
untrusted input. Lookups are capped at 2 seconds each, 30 seconds in total,
and 8 at a time.

## Development

```sh
task check          # gofmt, go vet, go test with coverage into .test/
task coverage       # coverage summary
task fuzz           # fuzz the parser for 60s
task clean          # remove .build/ and .test/
```

Layout:

```
cmd/franking/         CLI, flags, exit codes
internal/report/      XML structs, hardened parser, charset reader
internal/archive/     Container detection, limited zip and gzip readers,
                      directory walk
internal/aggregate/   Per-IP and per-file aggregation, classification
internal/safe/        Sanitize, validate, and limit helpers
internal/output/      text, json, and csv writers
internal/run/         Ties the walk, the readers, and the aggregates together
testdata/reports/     Sample reports
testdata/malicious/   Hostile samples: reject/ must be refused,
                      sanitize/ must be parsed with the nasty strings cleaned
```

All addresses and domains in `testdata/` are from the documentation ranges
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) and
`example.ca`. The large hostile samples — the gzip bomb, the zip with a
false declared size, the 5000-member zip, and the 1000-level document — are
built by generator functions in the tests, so the repository stays small.

## Licence

See [LICENSE](LICENSE).
