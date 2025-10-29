package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"ip2asn/internal/cymru"
	"ip2asn/internal/model"
	"ip2asn/internal/output"
	"ip2asn/internal/parser"
	"ip2asn/internal/sortutil"
)

const (
	defaultTimeout = 8 * time.Second
)

func main() {
	// Flags
	var (
		outPath  string
		singleIP string
		jsonFlag bool
		csvFlag  bool
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
	flag.Parse()

	// Mutually exclusive format flags
	if jsonFlag && csvFlag {
		fatalf("--json (-j) and --csv (-c) are mutually exclusive")
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

	// Output
	// Determine chosen format: table default
	format := "table"
	if jsonFlag {
		format = "json"
	} else if csvFlag {
		format = "csv"
	}

	if outPath != "" && format == "table" {
		// Table only goes to stdout
		fmt.Fprintln(os.Stderr, "--output is ignored for table format; printing to stdout")
	}

	switch format {
	case "table":
		output.PrintTable(os.Stdout, results)
	case "csv":
		if outPath == "" {
			// stdout
			w := csv.NewWriter(os.Stdout)
			output.WriteCSV(w, results)
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
			output.WriteCSV(w, results)
			w.Flush()
			if err := w.Error(); err != nil {
				fatalf("failed to write CSV: %v", err)
			}
		}
	case "json":
		grouped := output.GroupResultsByASN(results)
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
	fmt.Fprintf(os.Stderr, "Usage: ip2asn [--json|-j | --csv|-c] [--output|-o path] [--ip|-i IP] [file]\n")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "Examples:\n")
	fmt.Fprintf(os.Stderr, "  echo 'IPs: 8.8.8.8 and 1.1.1.1' | ip2asn\n")
	fmt.Fprintf(os.Stderr, "  ip2asn --ip 2001:4860:4860::8888 --json\n")
	fmt.Fprintf(os.Stderr, "  ip2asn --csv --output out.csv input.txt\n")
}

func fatalf(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}
