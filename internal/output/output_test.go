package output

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"

	"github.com/jedib0t/go-pretty/v6/text"

	"ip2asn/internal/model"
)

func TestWriteCSVWithEnrichment(t *testing.T) {
	trueValue := true
	falseValue := false
	riskValue := 64
	results := []model.Result{
		{
			ASN:       64500,
			IP:        "203.0.113.7",
			BGPPrefix: "203.0.113.0/24",
			CC:        "US",
			Registry:  "arin",
			Allocated: "2020-01-01",
			ASName:    "TEST-NET",
			ProxyCheck: &model.ProxyCheck{
				Proxy:       &falseValue,
				VPN:         &trueValue,
				Compromised: &falseValue,
				Hosting:     &trueValue,
				TOR:         &falseValue,
				Risk:        &riskValue,
				VPNProvider: "IVPN",
				City:        "Chicago",
				State:       "Illinois",
				Country:     "United States",
			},
		},
	}

	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)
	WriteCSV(writer, results, true)
	writer.Flush()

	output := buf.String()
	if !strings.Contains(output, "Proxy,VPN,Compromised,Hosting,TOR,Risk,VPN Provider,City,State,Country") {
		t.Fatalf("expected enrichment columns in CSV header, got %q", output)
	}
	if !strings.Contains(output, "false,true,false,true,false,64,IVPN,Chicago,Illinois,United States") {
		t.Fatalf("expected enrichment values in CSV output, got %q", output)
	}
}

func TestPrintTableWithFooterError(t *testing.T) {
	trueValue := true
	riskValue := 92
	results := []model.Result{
		{
			ASN:       64501,
			IP:        "198.51.100.9",
			BGPPrefix: "198.51.100.0/24",
			ASName:    "TEST-NET-2",
			ProxyCheck: &model.ProxyCheck{
				VPN:         &trueValue,
				Compromised: &trueValue,
				Risk:        &riskValue,
				VPNProvider: "Mullvad",
				City:        "Dallas",
				State:       "Texas",
				Country:     "United States",
			},
		},
	}

	var buf bytes.Buffer
	PrintTable(&buf, results, TableOptions{
		Mode:            TableModeProxycheck,
		EnrichmentError: "429 Too Many Requests",
	})

	rendered := buf.String()
	if !strings.Contains(rendered, "VPN Provider") {
		t.Fatalf("expected proxycheck columns in table, got %q", rendered)
	}
	if strings.Contains(rendered, "Allocated") || strings.Contains(rendered, "Registry") || strings.Contains(rendered, " CC ") {
		t.Fatalf("did not expect Cymru-only columns in proxycheck mode, got %q", rendered)
	}
	if !strings.Contains(rendered, "VPN") || !strings.Contains(rendered, "CMP") {
		t.Fatalf("expected status labels in table, got %q", rendered)
	}
	if !strings.Contains(rendered, "Proxycheck enrichment failed: 429 Too Many Requests") {
		t.Fatalf("expected trailing enrichment error, got %q", rendered)
	}
}

func TestPrintTableProxycheckModeKeepsSchemaOnLookupFailure(t *testing.T) {
	results := []model.Result{
		{
			ASN:       64502,
			IP:        "198.51.100.10",
			BGPPrefix: "198.51.100.0/24",
			CC:        "US",
			Registry:  "arin",
			Allocated: "2020-01-01",
			ASName:    "TEST-NET-3",
		},
	}

	var buf bytes.Buffer
	PrintTable(&buf, results, TableOptions{
		Mode:            TableModeProxycheck,
		EnrichmentError: "lookup timeout",
	})

	rendered := buf.String()
	if !strings.Contains(rendered, "VPN Provider") || !strings.Contains(rendered, "Risk") {
		t.Fatalf("expected proxycheck schema on lookup failure, got %q", rendered)
	}
	if strings.Contains(rendered, "Allocated") || strings.Contains(rendered, "Registry") || strings.Contains(rendered, " CC ") {
		t.Fatalf("did not expect Cymru-only columns in proxycheck mode, got %q", rendered)
	}
	if !strings.Contains(rendered, "·") {
		t.Fatalf("expected proxycheck placeholders on lookup failure, got %q", rendered)
	}
	if !strings.Contains(rendered, "Proxycheck enrichment failed: lookup timeout") {
		t.Fatalf("expected trailing enrichment error, got %q", rendered)
	}
}

func TestStatusLabelsReturnsEmptyWhenStatusDataIsClean(t *testing.T) {
	falseValue := false
	proxyCheck := &model.ProxyCheck{
		VPN:         &falseValue,
		Proxy:       &falseValue,
		Compromised: &falseValue,
		TOR:         &falseValue,
		Hosting:     &falseValue,
	}

	if got := statusLabels(proxyCheck); got != "" {
		t.Fatalf("expected empty status label for clean status data, got %q", got)
	}
}

func TestPrintTableProxycheckModeDoesNotRenderSCR(t *testing.T) {
	falseValue := false
	results := []model.Result{
		{
			ASN:       64503,
			IP:        "198.51.100.13",
			BGPPrefix: "198.51.100.0/24",
			ASName:    "TEST-NET-4",
			ProxyCheck: &model.ProxyCheck{
				VPN:         &falseValue,
				Proxy:       &falseValue,
				Compromised: &falseValue,
				TOR:         &falseValue,
				Hosting:     &falseValue,
			},
		},
	}

	var buf bytes.Buffer
	PrintTable(&buf, results, TableOptions{Mode: TableModeProxycheck})

	rendered := buf.String()
	if strings.Contains(rendered, "SCR") {
		t.Fatalf("did not expect SCR status label for clean status data, got %q", rendered)
	}
}

func TestPrintTableKeepsCompactWidthWhenContentFits(t *testing.T) {
	t.Setenv("COLUMNS", "100")

	results := []model.Result{
		{
			ASN:       64510,
			IP:        "198.51.100.11",
			BGPPrefix: "198.51.100.0/24",
			CC:        "US",
			Registry:  "arin",
			Allocated: "2020-01-01",
			ASName:    "TEST-NET",
		},
	}

	var buf bytes.Buffer
	PrintTable(&buf, results, TableOptions{})

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) == 0 {
		t.Fatal("expected rendered table output")
	}
	if width := text.StringWidthWithoutEscSequences(lines[0]); width >= 100 {
		t.Fatalf("expected compact top border width below 100, got %d: %q", width, lines[0])
	}
}

func TestPrintTableAvoidsTruncationWhenWidthAllows(t *testing.T) {
	t.Setenv("COLUMNS", "240")

	results := []model.Result{
		{
			ASN:       64511,
			IP:        "198.51.100.12",
			BGPPrefix: "198.51.100.0/24",
			ASName:    "A-VERY-LONG-AS-NAME-THAT-SHOULD-REMAIN-FULLY-VISIBLE-WHEN-THERE-IS-ENOUGH-WIDTH",
			ProxyCheck: &model.ProxyCheck{
				City:    "Salt Lake City",
				State:   "Utah",
				Country: "United States",
			},
		},
	}

	var buf bytes.Buffer
	PrintTable(&buf, results, TableOptions{Mode: TableModeProxycheck})

	rendered := buf.String()
	if !strings.Contains(rendered, "A-VERY-LONG-AS-NAME-THAT-SHOULD-REMAIN-FULLY-VISIBLE-WHEN-THERE-IS-ENOUGH-WIDTH") {
		t.Fatalf("expected AS name to remain untruncated, got %q", rendered)
	}
	if strings.Contains(rendered, "…") {
		t.Fatalf("did not expect truncation when enough width is available, got %q", rendered)
	}
	if width := firstRenderedLineWidth(rendered); width >= 240 {
		t.Fatalf("expected rendered table to stay narrower than the terminal, got width %d: %q", width, rendered)
	}
}

func TestRenderTableTruncatesASNameBeforeOtherColumns(t *testing.T) {
	asName := "AN-EXTREMELY-LONG-AUTONOMOUS-SYSTEM-NAME"

	rendered := RenderTable([]model.Result{
		{
			ASN:       64512,
			IP:        "198.51.100.123",
			BGPPrefix: "198.51.100.0/24",
			CC:        "US",
			Registry:  "arin",
			Allocated: "2020-01-01",
			ASName:    asName,
		},
	}, TableOptions{}, 95, false)

	if !strings.Contains(rendered, "198.51.100.123") {
		t.Fatalf("expected IP column to stay intact, got %q", rendered)
	}
	if !strings.Contains(rendered, "198.51.100.0/24") {
		t.Fatalf("expected BGP prefix column to stay intact, got %q", rendered)
	}
	if !strings.Contains(rendered, "arin") || !strings.Contains(rendered, "2020-01-01") {
		t.Fatalf("expected non-AS identity fields to stay intact, got %q", rendered)
	}
	if strings.Contains(rendered, asName) {
		t.Fatalf("expected AS name to truncate before other columns, got %q", rendered)
	}
	if !strings.Contains(rendered, "…") {
		t.Fatalf("expected AS name truncation ellipsis, got %q", rendered)
	}
}

func TestRenderTableHighlightsRiskRowsInProxycheckMode(t *testing.T) {
	mediumRisk := 50
	highRisk := 80

	rendered := RenderTable([]model.Result{
		{
			ASN:       64520,
			IP:        "198.51.100.20",
			BGPPrefix: "198.51.100.0/24",
			ASName:    "MEDIUM-RISK",
			ProxyCheck: &model.ProxyCheck{
				Risk: &mediumRisk,
			},
		},
		{
			ASN:       64521,
			IP:        "198.51.100.21",
			BGPPrefix: "198.51.100.0/24",
			ASName:    "HIGH-RISK",
			ProxyCheck: &model.ProxyCheck{
				Risk: &highRisk,
			},
		},
	}, TableOptions{Mode: TableModeProxycheck}, 180, true)

	if !strings.Contains(rendered, (text.Colors{text.BgHiYellow, text.FgBlack}).EscapeSeq()) {
		t.Fatalf("expected medium-risk row highlight, got %q", rendered)
	}
	if !strings.Contains(rendered, (text.Colors{text.BgHiRed, text.FgBlack}).EscapeSeq()) {
		t.Fatalf("expected high-risk row highlight, got %q", rendered)
	}
	if strings.Contains(rendered, "Ⓥ") || strings.Contains(rendered, "Ⓟ") || strings.Contains(rendered, "Ⓒ") || strings.Contains(rendered, "Ⓗ") || strings.Contains(rendered, "Ⓣ") || strings.Contains(rendered, "✓") {
		t.Fatalf("did not expect legacy status icons, got %q", rendered)
	}
	if strings.Contains(rendered, (text.Colors{text.Bold, text.FgHiBlue}).EscapeSeq()) || strings.Contains(rendered, (text.Colors{text.Bold, text.FgMagenta}).EscapeSeq()) || strings.Contains(rendered, (text.Colors{text.Bold, text.FgHiRed}).EscapeSeq()) || strings.Contains(rendered, (text.Colors{text.Bold, text.FgYellow}).EscapeSeq()) || strings.Contains(rendered, (text.Colors{text.Bold, text.FgHiGreen}).EscapeSeq()) || strings.Contains(rendered, (text.Colors{text.FgGreen}).EscapeSeq()) {
		t.Fatalf("did not expect status or risk text colors, got %q", rendered)
	}
}

func TestRenderTableOnlyHighlightsYellowAtRisk50AndAbove(t *testing.T) {
	justBelowYellow := 49
	atYellow := 50

	rendered := RenderTable([]model.Result{
		{
			ASN:       64523,
			IP:        "198.51.100.23",
			BGPPrefix: "198.51.100.0/24",
			ASName:    "BELOW-YELLOW",
			ProxyCheck: &model.ProxyCheck{
				Risk: &justBelowYellow,
			},
		},
		{
			ASN:       64524,
			IP:        "198.51.100.24",
			BGPPrefix: "198.51.100.0/24",
			ASName:    "AT-YELLOW",
			ProxyCheck: &model.ProxyCheck{
				Risk: &atYellow,
			},
		},
	}, TableOptions{Mode: TableModeProxycheck}, 180, true)

	yellow := (text.Colors{text.BgHiYellow, text.FgBlack}).EscapeSeq()
	highlightedRows := 0
	for _, line := range strings.Split(rendered, "\n") {
		if strings.Contains(line, yellow) {
			highlightedRows++
		}
	}
	if highlightedRows != 1 {
		t.Fatalf("expected exactly one yellow-highlighted row at the 50 threshold, got %q", rendered)
	}
}

func TestRenderTableDoesNotHighlightRiskRowsOutsideProxycheckMode(t *testing.T) {
	highRisk := 90
	result := []model.Result{
		{
			ASN:       64522,
			IP:        "198.51.100.22",
			BGPPrefix: "198.51.100.0/24",
			ASName:    "NO-HIGHLIGHT",
			ProxyCheck: &model.ProxyCheck{
				Risk: &highRisk,
			},
		},
	}

	noColorRendered := RenderTable(result, TableOptions{Mode: TableModeProxycheck}, 180, false)
	if strings.Contains(noColorRendered, (text.Colors{text.BgHiRed, text.FgBlack}).EscapeSeq()) || strings.Contains(noColorRendered, (text.Colors{text.BgHiYellow, text.FgBlack}).EscapeSeq()) {
		t.Fatalf("did not expect ANSI row highlights when color is disabled, got %q", noColorRendered)
	}

	basicRendered := RenderTable(result, TableOptions{}, 180, true)
	if strings.Contains(basicRendered, (text.Colors{text.BgHiRed, text.FgBlack}).EscapeSeq()) || strings.Contains(basicRendered, (text.Colors{text.BgHiYellow, text.FgBlack}).EscapeSeq()) {
		t.Fatalf("did not expect row highlights outside proxycheck mode, got %q", basicRendered)
	}
}

func firstRenderedLineWidth(rendered string) int {
	lines := strings.Split(strings.TrimRight(rendered, "\n"), "\n")
	if len(lines) == 0 {
		return 0
	}
	return text.StringWidthWithoutEscSequences(lines[0])
}
