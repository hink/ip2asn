package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/term"
	"io"
	"os"
	"time"

	"ip2asn/internal/cymru"
	"ip2asn/internal/model"
	"ip2asn/internal/output"
	"ip2asn/internal/parser"
	"ip2asn/internal/proxycheck"
	"ip2asn/internal/sortutil"
	"ip2asn/internal/tui"
)

const (
	defaultTimeout = 8 * time.Second
)

func main() {
	// Flags
	var (
		outPath    string
		singleIP   string
		jsonFlag   bool
		csvFlag    bool
		enrichFlag bool
		tuiFlag    bool
	)

	// Flags + short aliases
	flag.BoolVar(&jsonFlag, "json", false, "output JSON (mutually exclusive with --csv)")
	flag.BoolVar(&jsonFlag, "j", false, "output JSON (mutually exclusive with -c)")
	flag.BoolVar(&csvFlag, "csv", false, "output CSV (mutually exclusive with --json)")
	flag.BoolVar(&csvFlag, "c", false, "output CSV (mutually exclusive with -j)")
	flag.StringVar(&outPath, "output", "", "optional output file for csv/json; defaults to stdout")
	flag.StringVar(&outPath, "o", "", "optional output file for csv/json; defaults to stdout")
	flag.StringVar(&singleIP, "ip", "", "single IP lookup (uses DNS interface)")
	flag.StringVar(&singleIP, "i", "", "single IP lookup (uses DNS interface)")
	flag.BoolVar(&enrichFlag, "enrich", false, "use proxycheck.io data (proxycheck-focused table/TUI; additive CSV/JSON)")
	flag.BoolVar(&enrichFlag, "e", false, "use proxycheck.io data (proxycheck-focused table/TUI; additive CSV/JSON)")
	flag.BoolVar(&tuiFlag, "tui", false, "open interactive table TUI mode")
	flag.BoolVar(&tuiFlag, "t", false, "open interactive table TUI mode")
	flag.Parse()

	// Mutually exclusive format flags
	if jsonFlag && csvFlag {
		fatalf("--json (-j) and --csv (-c) are mutually exclusive")
	}

	format := "table"
	if jsonFlag {
		format = "json"
	} else if csvFlag {
		format = "csv"
	}

	if err := validateTUIOptions(tuiFlag, format, outPath, isTerminal(os.Stdin), isTerminal(os.Stdout)); err != nil {
		fatalf("%v", err)
	}

	proxyCheckAPIKey := ""
	if enrichFlag {
		proxyCheckAPIKey = os.Getenv("PROXYCHECK_API_KEY")
		if proxyCheckAPIKey == "" {
			fatalf("--enrich (-e) requires PROXYCHECK_API_KEY in the environment")
		}
	}

	// Determine input mode
	var ips []string
	var err error
	if singleIP != "" {
		// Single IP flag path
		ips, err = parser.ParseIPsFromString(singleIP)
		if err != nil || len(ips) == 0 {
			fatalf("--ip is not a valid IPv4/IPv6 address: %v", singleIP)
		}
	} else {
		// Either positional file arg or stdin
		args := flag.Args()
		if len(args) > 1 {
			fatalf("expected at most one input file, got %d", len(args))
		}
		var r io.Reader
		if len(args) == 1 {
			f, err := os.Open(args[0])
			if err != nil {
				fatalf("failed to open input file: %v", err)
			}
			defer f.Close()
			r = bufio.NewReader(f)
		} else {
			// If stdin is not a terminal, read from stdin
			stat, _ := os.Stdin.Stat()
			if (stat.Mode() & os.ModeCharDevice) == 0 {
				r = bufio.NewReader(os.Stdin)
			} else {
				usage()
				os.Exit(2)
			}
		}
		ips, err = parser.ParseIPs(r)
		if err != nil {
			fatalf("failed to parse IPs: %v", err)
		}
		if len(ips) == 0 {
			fatalf("no IPv4/IPv6 addresses were found in the input")
		}
	}

	// Decide query method per guidelines
	var results []model.Result
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	if len(ips) == 1 {
		// Use DNS interface for a single IP
		results, err = cymru.LookupDNS(ctx, ips[0])
		if err != nil {
			// Be robust: if DNS fails, fall back to WHOIS single lookup in one TCP query
			fmt.Fprintf(os.Stderr, "DNS lookup failed (%v). Falling back to WHOIS.\n", err)
			results, err = cymru.LookupWhoisBulk(ctx, ips)
			if err != nil {
				fatalf("WHOIS fallback failed: %v", err)
			}
		}
	} else {
		// Use WHOIS (single TCP) bulk for 2+ IPs
		results, err = cymru.LookupWhoisBulk(ctx, ips)
		if err != nil {
			fatalf("WHOIS bulk lookup failed: %v", err)
		}
	}

	if len(results) == 0 {
		fmt.Fprintln(os.Stderr, "No results returned from Team Cymru.")
		os.Exit(1)
	}

	// Sort results: by ASN, then IP (numeric)
	sortutil.SortResults(results)

	var tableEnrichmentError string
	if enrichFlag {
		enrichmentCtx, enrichmentCancel := context.WithTimeout(context.Background(), defaultTimeout)
		defer enrichmentCancel()

		client := proxycheck.NewClient(proxyCheckAPIKey)
		enrichments, warningMessage, err := client.Lookup(enrichmentCtx, uniqueResultIPs(results))
		if err != nil {
			tableEnrichmentError = err.Error()
		} else {
			proxycheck.Apply(results, enrichments)
			if warningMessage != "" {
				fmt.Fprintf(os.Stderr, "Proxycheck enrichment warning: %s\n", warningMessage)
			}
		}
	}

	if outPath != "" && format == "table" {
		// Table only goes to stdout
		fmt.Fprintln(os.Stderr, "--output is ignored for table format; printing to stdout")
	}

	switch format {
	case "table":
		tableOpts := output.TableOptions{
			Mode:            chooseTableMode(enrichFlag),
			EnrichmentError: tableEnrichmentError,
		}
		if tuiFlag {
			if err := tui.Run(os.Stdin, os.Stdout, results, tableOpts); err != nil {
				fatalf("failed to start TUI: %v", err)
			}
			return
		}
		output.PrintTable(os.Stdout, results, output.TableOptions{
			Mode:            chooseTableMode(enrichFlag),
			EnrichmentError: tableEnrichmentError,
		})
	case "csv":
		if tableEnrichmentError != "" {
			fmt.Fprintf(os.Stderr, "Proxycheck enrichment failed: %s\n", tableEnrichmentError)
		}
		if outPath == "" {
			// stdout
			w := csv.NewWriter(os.Stdout)
			output.WriteCSV(w, results, enrichFlag)
			w.Flush()
			if err := w.Error(); err != nil {
				fatalf("failed to write CSV: %v", err)
			}
		} else {
			f, err := os.Create(outPath)
			if err != nil {
				fatalf("failed to create output file: %v", err)
			}
			defer f.Close()
			w := csv.NewWriter(f)
			output.WriteCSV(w, results, enrichFlag)
			w.Flush()
			if err := w.Error(); err != nil {
				fatalf("failed to write CSV: %v", err)
			}
		}
	case "json":
		if tableEnrichmentError != "" {
			fmt.Fprintf(os.Stderr, "Proxycheck enrichment failed: %s\n", tableEnrichmentError)
		}
		grouped := output.GroupResultsByASN(results, enrichFlag)
		if outPath == "" {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(grouped); err != nil {
				fatalf("failed to write JSON: %v", err)
			}
		} else {
			f, err := os.Create(outPath)
			if err != nil {
				fatalf("failed to create output file: %v", err)
			}
			defer f.Close()
			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			if err := enc.Encode(grouped); err != nil {
				fatalf("failed to write JSON: %v", err)
			}
		}
	default:
		fatalf("unknown format: %s", format)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: ip2asn [--json|-j | --csv|-c] [--output|-o path] [--enrich|-e] [--tui|-t] [--ip|-i IP] [file]\n")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "Examples:\n")
	fmt.Fprintf(os.Stderr, "  echo 'IPs: 8.8.8.8 and 1.1.1.1' | ip2asn\n")
	fmt.Fprintf(os.Stderr, "  ip2asn --ip 2001:4860:4860::8888 --json\n")
	fmt.Fprintf(os.Stderr, "  ip2asn --tui input.txt\n")
	fmt.Fprintf(os.Stderr, "  PROXYCHECK_API_KEY=... ip2asn --enrich input.txt  # proxycheck-focused table view\n")
	fmt.Fprintf(os.Stderr, "  PROXYCHECK_API_KEY=... ip2asn --tui --enrich input.txt\n")
	fmt.Fprintf(os.Stderr, "  ip2asn --csv --output out.csv input.txt\n")
}

func fatalf(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}

func uniqueResultIPs(results []model.Result) []string {
	seen := make(map[string]struct{}, len(results))
	ips := make([]string, 0, len(results))
	for _, result := range results {
		if _, exists := seen[result.IP]; exists {
			continue
		}
		seen[result.IP] = struct{}{}
		ips = append(ips, result.IP)
	}
	return ips
}

func chooseTableMode(enrichEnabled bool) output.TableMode {
	if enrichEnabled {
		return output.TableModeProxycheck
	}
	return output.TableModeBasic
}

func validateTUIOptions(enabled bool, format, outPath string, stdinTTY, stdoutTTY bool) error {
	if !enabled {
		return nil
	}
	if format != "table" {
		return fmt.Errorf("--tui (-t) is only supported with table output")
	}
	if outPath != "" {
		return fmt.Errorf("--output (-o) cannot be used with --tui (-t)")
	}
	if !stdinTTY || !stdoutTTY {
		return fmt.Errorf("--tui (-t) requires interactive stdin and stdout")
	}
	return nil
}

func isTerminal(file *os.File) bool {
	if file == nil {
		return false
	}
	return term.IsTerminal(int(file.Fd()))
}
