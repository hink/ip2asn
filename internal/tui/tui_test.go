package tui

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"ip2asn/internal/model"
	"ip2asn/internal/output"
)

func TestModelResizeRendersTableAndFooter(t *testing.T) {
	trueValue := true
	riskValue := 72

	m := newModel([]model.Result{
		{
			ASN:       64500,
			IP:        "203.0.113.7",
			BGPPrefix: "203.0.113.0/24",
			ASName:    "TEST-NET",
			ProxyCheck: &model.ProxyCheck{
				VPN:         &trueValue,
				Risk:        &riskValue,
				VPNProvider: "IVPN",
				City:        "Chicago",
				State:       "Illinois",
				Country:     "United States",
			},
		},
	}, output.TableOptions{
		Mode:            output.TableModeProxycheck,
		EnrichmentError: "lookup timeout",
	}, false)

	updated, cmd := m.Update(tea.WindowSizeMsg{Width: 160, Height: 20})
	if cmd != nil {
		t.Fatalf("expected no command on resize, got %v", cmd)
	}

	resized, ok := updated.(screenModel)
	if !ok {
		t.Fatalf("expected screenModel, got %T", updated)
	}
	if !resized.ready {
		t.Fatal("expected model to be ready after initial resize")
	}
	if resized.width != 160 || resized.height != 20 {
		t.Fatalf("expected size 160x20, got %dx%d", resized.width, resized.height)
	}

	view := resized.View()
	if !view.AltScreen {
		t.Fatal("expected alt-screen mode to be enabled")
	}
	if !strings.Contains(view.Content, "VPN Provider") {
		t.Fatalf("expected rendered table content, got %q", view.Content)
	}
	if strings.Contains(view.Content, "Allocated") || strings.Contains(view.Content, "Registry") || strings.Contains(view.Content, " CC ") {
		t.Fatalf("did not expect Cymru-only columns in proxycheck mode, got %q", view.Content)
	}
	if !strings.Contains(view.Content, "Proxycheck enrichment failed: lookup timeout") {
		t.Fatalf("expected enrichment footer in view content, got %q", view.Content)
	}
	if !strings.Contains(view.Content, "q quit") {
		t.Fatalf("expected help footer in view content, got %q", view.Content)
	}
}

func TestModelQuitKeyReturnsQuitCommand(t *testing.T) {
	m := newModel(nil, output.TableOptions{}, false)

	updated, cmd := m.Update(tea.KeyPressMsg(tea.Key{Text: "q", Code: 'q'}))
	if cmd == nil {
		t.Fatal("expected quit command for q keypress")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatalf("expected tea.QuitMsg, got %T", cmd())
	}
	if _, ok := updated.(screenModel); !ok {
		t.Fatalf("expected screenModel, got %T", updated)
	}
}
