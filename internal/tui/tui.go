package tui

import (
	"io"
	"strconv"
	"strings"

	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"github.com/jedib0t/go-pretty/v6/text"

	"ip2asn/internal/model"
	"ip2asn/internal/output"
)

// Run starts the interactive table TUI.
func Run(input io.Reader, out io.Writer, results []model.Result, opts output.TableOptions) error {
	program := tea.NewProgram(
		newModel(results, opts, output.ColorEnabled(out)),
		tea.WithInput(input),
		tea.WithOutput(out),
	)

	_, err := program.Run()
	return err
}

type screenModel struct {
	results     []model.Result
	opts        output.TableOptions
	viewport    viewport.Model
	width       int
	height      int
	ready       bool
	enableColor bool
}

func newModel(results []model.Result, opts output.TableOptions, enableColor bool) screenModel {
	vp := viewport.New()
	vp.MouseWheelEnabled = true

	return screenModel{
		results:     results,
		opts:        opts,
		viewport:    vp,
		enableColor: enableColor,
	}
}

func (m screenModel) Init() tea.Cmd {
	return nil
}

func (m screenModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.resize(msg.Width, msg.Height)
		return m, nil
	case tea.KeyPressMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "home":
			m.viewport.GotoTop()
			return m, nil
		case "end":
			m.viewport.GotoBottom()
			return m, nil
		}
	}

	var cmd tea.Cmd
	m.viewport, cmd = m.viewport.Update(msg)
	return m, cmd
}

func (m screenModel) View() tea.View {
	content := "Loading…"
	if m.ready {
		content = m.viewport.View() + "\n" + m.footer()
	}

	view := tea.NewView(content)
	view.AltScreen = true
	view.MouseMode = tea.MouseModeCellMotion
	return view
}

func (m *screenModel) resize(width, height int) {
	if width <= 0 || height <= 0 {
		return
	}

	bodyHeight := height - 1
	if bodyHeight < 1 {
		bodyHeight = 1
	}

	oldYOffset := 0
	wasAtBottom := false
	if m.ready {
		oldYOffset = m.viewport.YOffset()
		wasAtBottom = m.viewport.AtBottom()
	}

	if !m.ready {
		m.viewport = viewport.New(
			viewport.WithWidth(width),
			viewport.WithHeight(bodyHeight),
		)
		m.viewport.MouseWheelEnabled = true
		m.ready = true
	} else {
		m.viewport.SetWidth(width)
		m.viewport.SetHeight(bodyHeight)
	}

	m.width = width
	m.height = height

	content := output.RenderTable(m.results, m.opts, width, m.enableColor)
	m.viewport.SetContent(content)

	if wasAtBottom {
		m.viewport.GotoBottom()
		return
	}

	maxOffset := maxInt(0, lineCount(content)-bodyHeight)
	m.viewport.SetYOffset(minInt(oldYOffset, maxOffset))
}

func (m screenModel) footer() string {
	line := "q quit • ↑/↓ scroll • PgUp/PgDn page • Home/End"
	if len(m.results) > 0 {
		line += " • " + strconv.Itoa(len(m.results)) + " rows"
	}

	line = fitWidth(line, m.width)
	if m.enableColor {
		return text.Colors{text.FgHiBlack}.Sprint(line)
	}
	return line
}

func fitWidth(line string, width int) string {
	if width <= 0 {
		return line
	}

	lineWidth := text.StringWidth(line)
	if lineWidth > width {
		return text.Snip(line, width, "…")
	}
	if lineWidth < width {
		return line + strings.Repeat(" ", width-lineWidth)
	}
	return line
}

func lineCount(content string) int {
	if content == "" {
		return 0
	}
	return strings.Count(content, "\n") + 1
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
