package output

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"golang.org/x/term"

	"ip2asn/internal/model"
)

// TableMode controls which table schema is rendered.
type TableMode int

const (
	TableModeBasic TableMode = iota
	TableModeProxycheck
	compactTableExtraWidth = 2
)

// TableOptions controls how table output is rendered.
type TableOptions struct {
	Mode            TableMode
	EnrichmentError string
}

// RenderTable renders the current table output for a target width.
func RenderTable(results []model.Result, opts TableOptions, width int, enableColor bool) string {
	restoreTextColors := configureTextColors(enableColor)
	defer restoreTextColors()

	layout := newTableLayout(results, opts.Mode, enableColor, width)
	tw := table.NewWriter()
	tw.SetStyle(tableStyle(enableColor))
	tw.Style().Box.UnfinishedRow = "…"
	if layout.width > 0 {
		tw.Style().Size.WidthMax = layout.width
	}
	tw.SetColumnConfigs(layout.columnConfigs())
	tw.Style().Options.SeparateRows = false
	tw.SuppressTrailingSpaces()
	if opts.Mode == TableModeProxycheck && enableColor {
		tw.SetRowPainter(layout.rowPainter())
	}

	tw.AppendHeader(layout.header())
	for _, row := range layout.rows {
		tw.AppendRow(row)
	}

	rendered := tw.Render()
	if opts.EnrichmentError != "" {
		rendered += "\n" + coloredLine("Proxycheck enrichment failed: "+opts.EnrichmentError, enableColor, text.Colors{text.Bold, text.FgRed})
	}
	return rendered
}

// PrintTable writes a styled table to w.
func PrintTable(w io.Writer, results []model.Result, opts TableOptions) {
	fmt.Fprint(w, RenderTable(results, opts, terminalWidth(w), ColorEnabled(w)))
}

// WriteCSV writes CSV header + records using the provided writer.
func WriteCSV(w *csv.Writer, results []model.Result, includeEnrichment bool) {
	header := []string{"AS", "IP", "BGP Prefix", "CC", "Registry", "Allocated", "AS Name"}
	if includeEnrichment {
		header = append(header, "Proxy", "VPN", "Compromised", "Hosting", "TOR", "Risk", "VPN Provider", "City", "State", "Country")
	}
	_ = w.Write(header)

	for _, result := range results {
		row := []string{
			strconv.Itoa(result.ASN),
			result.IP,
			result.BGPPrefix,
			result.CC,
			result.Registry,
			result.Allocated,
			result.ASName,
		}
		if includeEnrichment {
			row = append(row,
				boolCell(result.ProxyCheck, func(proxyCheck *model.ProxyCheck) *bool { return proxyCheck.Proxy }),
				boolCell(result.ProxyCheck, func(proxyCheck *model.ProxyCheck) *bool { return proxyCheck.VPN }),
				boolCell(result.ProxyCheck, func(proxyCheck *model.ProxyCheck) *bool { return proxyCheck.Compromised }),
				boolCell(result.ProxyCheck, func(proxyCheck *model.ProxyCheck) *bool { return proxyCheck.Hosting }),
				boolCell(result.ProxyCheck, func(proxyCheck *model.ProxyCheck) *bool { return proxyCheck.TOR }),
				riskCSVCell(result.ProxyCheck),
				enrichmentString(result.ProxyCheck, func(proxyCheck *model.ProxyCheck) string { return proxyCheck.VPNProvider }),
				enrichmentString(result.ProxyCheck, func(proxyCheck *model.ProxyCheck) string { return proxyCheck.City }),
				enrichmentString(result.ProxyCheck, func(proxyCheck *model.ProxyCheck) string { return proxyCheck.State }),
				enrichmentString(result.ProxyCheck, func(proxyCheck *model.ProxyCheck) string { return proxyCheck.Country }),
			)
		}
		_ = w.Write(row)
	}
}

func tableStyle(enableColor bool) table.Style {
	style := table.StyleRounded
	style.Options.DrawBorder = true
	style.Options.SeparateColumns = true
	style.Options.SeparateHeader = true
	style.Options.SeparateFooter = false
	style.Options.SeparateRows = false
	style.Format.Header = text.FormatDefault
	style.Format.Row = text.FormatDefault
	if enableColor {
		style.Color.Header = text.Colors{text.Bold, text.FgHiCyan}
		style.Color.Border = text.Colors{text.FgHiBlack}
		style.Color.Separator = text.Colors{text.FgHiBlack}
	}
	return style
}

func configureTextColors(enableColor bool) func() {
	wasEnabled := text.FgRed.Sprint("x") != "x"
	if enableColor {
		text.EnableColors()
	} else {
		text.DisableColors()
	}

	return func() {
		if wasEnabled {
			text.EnableColors()
			return
		}
		text.DisableColors()
	}
}

// ColorEnabled reports whether ANSI color output should be used for w.
func ColorEnabled(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" || strings.EqualFold(os.Getenv("TERM"), "dumb") {
		return false
	}
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	stat, err := file.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}

func statusLabels(proxyCheck *model.ProxyCheck) string {
	if proxyCheck == nil {
		return placeholder(false)
	}

	labels := make([]string, 0, 5)
	labels = appendStatusLabel(labels, proxyCheck.VPN, "VPN")
	labels = appendStatusLabel(labels, proxyCheck.Proxy, "PXY")
	labels = appendStatusLabel(labels, proxyCheck.Compromised, "CMP")
	labels = appendStatusLabel(labels, proxyCheck.TOR, "TOR")
	labels = appendStatusLabel(labels, proxyCheck.Hosting, "HST")
	if len(labels) == 0 {
		if hasStatusData(proxyCheck) {
			return ""
		}
		return placeholder(false)
	}
	return strings.Join(labels, " ")
}

func appendStatusLabel(labels []string, value *bool, label string) []string {
	if value == nil || !*value {
		return labels
	}
	return append(labels, label)
}

func riskCell(proxyCheck *model.ProxyCheck, enableColor bool) string {
	if proxyCheck == nil || proxyCheck.Risk == nil {
		return placeholder(enableColor)
	}

	return strconv.Itoa(*proxyCheck.Risk)
}

func riskCSVCell(proxyCheck *model.ProxyCheck) string {
	if proxyCheck == nil || proxyCheck.Risk == nil {
		return ""
	}
	return strconv.Itoa(*proxyCheck.Risk)
}

func boolCell(proxyCheck *model.ProxyCheck, pick func(*model.ProxyCheck) *bool) string {
	if proxyCheck == nil {
		return ""
	}
	value := pick(proxyCheck)
	if value == nil {
		return ""
	}
	if *value {
		return "true"
	}
	return "false"
}

func enrichmentString(proxyCheck *model.ProxyCheck, pick func(*model.ProxyCheck) string) string {
	if proxyCheck == nil {
		return ""
	}
	return pick(proxyCheck)
}

func valueOrDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "·"
	}
	return value
}

func placeholder(enableColor bool) string {
	if !enableColor {
		return "·"
	}
	return text.Colors{text.FgHiBlack}.Sprint("·")
}

func coloredLine(line string, enableColor bool, colors text.Colors) string {
	if !enableColor {
		return line
	}
	return colors.Sprint(line)
}

func riskRowColors(proxyCheck *model.ProxyCheck) text.Colors {
	if proxyCheck == nil || proxyCheck.Risk == nil {
		return nil
	}

	switch {
	case *proxyCheck.Risk >= 75:
		return text.Colors{text.BgHiRed, text.FgBlack}
	case *proxyCheck.Risk >= 50:
		return text.Colors{text.BgHiYellow, text.FgBlack}
	default:
		return nil
	}
}

func hasStatusData(proxyCheck *model.ProxyCheck) bool {
	return proxyCheck.Proxy != nil ||
		proxyCheck.VPN != nil ||
		proxyCheck.Compromised != nil ||
		proxyCheck.Hosting != nil ||
		proxyCheck.TOR != nil
}

func terminalWidth(w io.Writer) int {
	if columnsEnv := os.Getenv("COLUMNS"); columnsEnv != "" {
		if width, err := strconv.Atoi(columnsEnv); err == nil && width > 0 {
			return width
		}
	}

	file, ok := w.(*os.File)
	if !ok {
		return 0
	}

	width, _, err := term.GetSize(int(file.Fd()))
	if err != nil || width <= 0 {
		return 0
	}
	return width
}

type tableLayout struct {
	width   int
	columns []tableColumn
	rows    []table.Row
	colors  []text.Colors
}

type tableColumn struct {
	name        string
	align       text.Align
	min         int
	grow        bool
	width       int
	natural     int
	preferExtra bool
	shrinkFirst bool
}

func newTableLayout(results []model.Result, mode TableMode, enableColor bool, width int) tableLayout {
	var columns []tableColumn
	var rows []table.Row
	var rowColors []text.Colors

	if mode == TableModeProxycheck {
		columns = buildProxycheckColumns(results)
		rows, rowColors = buildProxycheckRows(results, enableColor)
	} else {
		columns = buildBasicColumns(results)
		rows = buildBasicRows(results)
	}

	layout := tableLayout{
		width:   width,
		columns: columns,
		rows:    rows,
		colors:  rowColors,
	}
	layout.assignWidths()
	return layout
}

func buildProxycheckColumns(results []model.Result) []tableColumn {
	columns := []tableColumn{
		{name: "ASN", align: text.AlignRight, min: 3, grow: false},
		{name: "IP", min: 7, grow: true},
		{name: "BGP Prefix", min: 10, grow: true},
		{name: "AS Name", min: 12, grow: true, preferExtra: true, shrinkFirst: true},
		{name: "Status", align: text.AlignCenter, min: 6, grow: false},
		{name: "VPN Provider", min: 8, grow: true},
		{name: "City", min: 6, grow: true},
		{name: "State", min: 6, grow: true},
		{name: "Country", min: 7, grow: true},
		{name: "Risk", align: text.AlignCenter, min: 4, grow: false},
	}

	for _, result := range results {
		recordNatural(&columns[0], strconv.Itoa(result.ASN))
		recordNatural(&columns[1], result.IP)
		recordNatural(&columns[2], result.BGPPrefix)
		recordNatural(&columns[3], valueOrDash(result.ASName))
		recordNatural(&columns[4], statusLabels(result.ProxyCheck))
		recordNatural(&columns[5], tableValue(enrichmentString(result.ProxyCheck, func(proxyCheck *model.ProxyCheck) string { return proxyCheck.VPNProvider }), false))
		recordNatural(&columns[6], tableValue(enrichmentString(result.ProxyCheck, func(proxyCheck *model.ProxyCheck) string { return proxyCheck.City }), false))
		recordNatural(&columns[7], tableValue(enrichmentString(result.ProxyCheck, func(proxyCheck *model.ProxyCheck) string { return proxyCheck.State }), false))
		recordNatural(&columns[8], tableValue(enrichmentString(result.ProxyCheck, func(proxyCheck *model.ProxyCheck) string { return proxyCheck.Country }), false))
		recordNatural(&columns[9], riskCell(result.ProxyCheck, false))
	}
	return columns
}

func buildBasicColumns(results []model.Result) []tableColumn {
	columns := []tableColumn{
		{name: "ASN", align: text.AlignRight, min: 3, grow: false},
		{name: "IP", min: 7, grow: true},
		{name: "BGP Prefix", min: 10, grow: true},
		{name: "CC", align: text.AlignCenter, min: 2, grow: false},
		{name: "Registry", min: 8, grow: true},
		{name: "Allocated", align: text.AlignCenter, min: 10, grow: false},
		{name: "AS Name", min: 12, grow: true, preferExtra: true, shrinkFirst: true},
	}

	for _, result := range results {
		recordNatural(&columns[0], strconv.Itoa(result.ASN))
		recordNatural(&columns[1], result.IP)
		recordNatural(&columns[2], result.BGPPrefix)
		recordNatural(&columns[3], result.CC)
		recordNatural(&columns[4], result.Registry)
		recordNatural(&columns[5], result.Allocated)
		recordNatural(&columns[6], valueOrDash(result.ASName))
	}
	return columns
}

func buildProxycheckRows(results []model.Result, enableColor bool) ([]table.Row, []text.Colors) {
	rows := make([]table.Row, 0, len(results))
	rowColors := make([]text.Colors, 0, len(results))
	for _, result := range results {
		rows = append(rows, table.Row{
			strconv.Itoa(result.ASN),
			result.IP,
			result.BGPPrefix,
			valueOrDash(result.ASName),
			statusLabels(result.ProxyCheck),
			tableValue(enrichmentString(result.ProxyCheck, func(proxyCheck *model.ProxyCheck) string { return proxyCheck.VPNProvider }), enableColor),
			tableValue(enrichmentString(result.ProxyCheck, func(proxyCheck *model.ProxyCheck) string { return proxyCheck.City }), enableColor),
			tableValue(enrichmentString(result.ProxyCheck, func(proxyCheck *model.ProxyCheck) string { return proxyCheck.State }), enableColor),
			tableValue(enrichmentString(result.ProxyCheck, func(proxyCheck *model.ProxyCheck) string { return proxyCheck.Country }), enableColor),
			riskCell(result.ProxyCheck, enableColor),
		})
		rowColors = append(rowColors, riskRowColors(result.ProxyCheck))
	}
	return rows, rowColors
}

func buildBasicRows(results []model.Result) []table.Row {
	rows := make([]table.Row, 0, len(results))
	for _, result := range results {
		rows = append(rows, table.Row{
			strconv.Itoa(result.ASN),
			result.IP,
			result.BGPPrefix,
			result.CC,
			result.Registry,
			result.Allocated,
			valueOrDash(result.ASName),
		})
	}
	return rows
}

func (layout *tableLayout) assignWidths() {
	for idx := range layout.columns {
		if layout.columns[idx].natural == 0 {
			layout.columns[idx].natural = text.StringWidth(layout.columns[idx].name)
		}
		if layout.columns[idx].natural < layout.columns[idx].min {
			layout.columns[idx].natural = layout.columns[idx].min
		}
		layout.columns[idx].width = layout.columns[idx].natural
	}

	if layout.width <= 0 {
		return
	}

	available := layout.width - tableFrameWidth(len(layout.columns))
	if available <= 0 {
		return
	}

	total := totalWidths(layout.columns)
	if total <= available {
		layout.growPreferred(min(available-total, compactTableExtraWidth))
		return
	}

	layout.shrinkPreferred(total - available)
	if totalWidths(layout.columns) > available {
		layout.shrinkToWidth(totalWidths(layout.columns) - available)
	}

	minTotal := totalMinWidths(layout.columns)
	if minTotal > available {
		layout.forceShrinkToWidth(minTotal - available)
	}
}

func (layout *tableLayout) growPreferred(extra int) {
	if extra <= 0 {
		return
	}

	preferred := make([]int, 0, len(layout.columns))
	for idx, column := range layout.columns {
		if column.preferExtra {
			preferred = append(preferred, idx)
		}
	}
	if len(preferred) == 0 {
		return
	}

	for extra > 0 {
		for _, idx := range preferred {
			layout.columns[idx].width++
			extra--
			if extra == 0 {
				return
			}
		}
	}
}

func (layout *tableLayout) shrinkPreferred(overflow int) {
	for overflow > 0 {
		idx := layout.preferredShrinkableIndex()
		if idx == -1 {
			return
		}
		layout.columns[idx].width--
		overflow--
	}
}

func (layout *tableLayout) shrinkToWidth(overflow int) {
	for overflow > 0 {
		idx := layout.widestShrinkableIndex()
		if idx == -1 {
			return
		}
		layout.columns[idx].width--
		overflow--
	}
}

func (layout *tableLayout) forceShrinkToWidth(overflow int) {
	for overflow > 0 {
		idx := layout.widestColumnAboveOne()
		if idx == -1 {
			return
		}
		layout.columns[idx].width--
		overflow--
	}
}

func (layout tableLayout) preferredShrinkableIndex() int {
	best := -1
	bestSlack := -1
	for idx, column := range layout.columns {
		if !column.shrinkFirst {
			continue
		}
		slack := column.width - column.min
		if slack <= 0 {
			continue
		}
		if slack > bestSlack {
			best = idx
			bestSlack = slack
		}
	}
	return best
}

func (layout tableLayout) widestShrinkableIndex() int {
	best := -1
	bestSlack := -1
	bestWidth := -1
	for idx, column := range layout.columns {
		slack := column.width - column.min
		if slack <= 0 {
			continue
		}
		if slack > bestSlack || (slack == bestSlack && column.width > bestWidth) {
			best = idx
			bestSlack = slack
			bestWidth = column.width
		}
	}
	return best
}

func (layout tableLayout) widestColumnAboveOne() int {
	best := -1
	bestWidth := -1
	for idx, column := range layout.columns {
		if column.width <= 1 {
			continue
		}
		if column.width > bestWidth {
			best = idx
			bestWidth = column.width
		}
	}
	return best
}

func (layout tableLayout) header() table.Row {
	row := make(table.Row, 0, len(layout.columns))
	for _, column := range layout.columns {
		row = append(row, column.name)
	}
	return row
}

func (layout tableLayout) columnConfigs() []table.ColumnConfig {
	configs := make([]table.ColumnConfig, 0, len(layout.columns))
	for _, column := range layout.columns {
		config := table.ColumnConfig{
			Name:  column.name,
			Align: column.align,
		}
		if layout.width > 0 {
			config.WidthMin = column.width
			config.WidthMax = column.width
			config.WidthMaxEnforcer = snipCell
		}
		configs = append(configs, config)
	}
	return configs
}

func (layout tableLayout) rowPainter() table.RowPainterWithAttributes {
	return func(_ table.Row, attr table.RowAttributes) text.Colors {
		if attr.Number <= 0 || attr.Number > len(layout.colors) {
			return nil
		}
		return layout.colors[attr.Number-1]
	}
}

func totalWidths(columns []tableColumn) int {
	total := 0
	for _, column := range columns {
		total += column.width
	}
	return total
}

func totalMinWidths(columns []tableColumn) int {
	total := 0
	for _, column := range columns {
		total += column.min
	}
	return total
}

func recordNatural(column *tableColumn, value string) {
	width := text.StringWidthWithoutEscSequences(value)
	if width > column.natural {
		column.natural = width
	}
	headerWidth := text.StringWidth(column.name)
	if headerWidth > column.natural {
		column.natural = headerWidth
	}
}

func tableFrameWidth(columnCount int) int {
	if columnCount <= 0 {
		return 0
	}
	// Border + separators + left/right padding for each column.
	return 2 + (columnCount - 1) + (columnCount * 2)
}

func snipCell(value string, maxLen int) string {
	return text.Snip(value, maxLen, "…")
}

func tableValue(value string, enableColor bool) string {
	if strings.TrimSpace(value) == "" {
		return placeholder(enableColor)
	}
	return value
}
