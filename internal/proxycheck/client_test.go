package proxycheck

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ip2asn/internal/model"
)

func TestLookupBatchesAndParsesV3Response(t *testing.T) {
	var requestCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if got := r.URL.Query().Get("key"); got != "test-key" {
			t.Fatalf("expected API key query parameter, got %q", got)
		}
		if got := r.URL.Query().Get("ver"); got != defaultVersion {
			t.Fatalf("expected version %q, got %q", defaultVersion, got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}

		switch requestCount {
		case 1:
			if got := string(body); got != "ips=198.51.100.1%2C198.51.100.2" {
				t.Fatalf("unexpected first request body %q", got)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"status":"warning",
				"message":"near daily query limit",
				"198.51.100.1":{
					"location":{"country_name":"United States","region_name":"Illinois","city_name":"Chicago"},
					"detections":{"proxy":false,"vpn":true,"compromised":true,"hosting":false,"tor":false,"risk":87},
					"operator":{"name":"IVPN"}
				},
				"198.51.100.2":{
					"location":{"country_name":null,"region_name":null,"city_name":null},
					"detections":{"proxy":null,"vpn":null,"compromised":null,"hosting":null,"tor":null,"risk":null},
					"operator":null
				}
			}`))
		case 2:
			if got := string(body); got != "ips=198.51.100.3" {
				t.Fatalf("unexpected second request body %q", got)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"status":"ok",
				"198.51.100.3":{
					"location":{"country_name":"Germany","region_name":"Berlin","city_name":"Berlin"},
					"detections":{"proxy":true,"vpn":false,"compromised":false,"hosting":true,"tor":true,"risk":52},
					"operator":{"name":"Mullvad"}
				}
			}`))
		default:
			t.Fatalf("unexpected request count %d", requestCount)
		}
	}))
	defer server.Close()

	client := NewClient("test-key")
	client.BaseURL = server.URL
	client.HTTPClient = server.Client()
	client.BatchSize = 2

	enrichments, warningMessage, err := client.Lookup(context.Background(), []string{
		"198.51.100.1",
		"198.51.100.2",
		"198.51.100.3",
	})
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}
	if warningMessage != "near daily query limit" {
		t.Fatalf("expected warning message, got %q", warningMessage)
	}
	if requestCount != 2 {
		t.Fatalf("expected 2 batched requests, got %d", requestCount)
	}

	first := enrichments["198.51.100.1"]
	if first.VPN == nil || !*first.VPN {
		t.Fatalf("expected VPN=true for first result")
	}
	if first.Compromised == nil || !*first.Compromised {
		t.Fatalf("expected Compromised=true for first result")
	}
	if first.Risk == nil || *first.Risk != 87 {
		t.Fatalf("expected risk 87, got %+v", first.Risk)
	}
	if first.VPNProvider != "IVPN" || first.City != "Chicago" || first.State != "Illinois" || first.Country != "United States" {
		t.Fatalf("unexpected first enrichment: %+v", first)
	}

	second := enrichments["198.51.100.2"]
	if !second.IsEmpty() {
		t.Fatalf("expected second enrichment to be empty, got %+v", second)
	}

	third := enrichments["198.51.100.3"]
	if third.Proxy == nil || !*third.Proxy {
		t.Fatalf("expected third proxy=true")
	}
	if third.Hosting == nil || !*third.Hosting {
		t.Fatalf("expected third hosting=true")
	}
	if third.TOR == nil || !*third.TOR {
		t.Fatalf("expected third tor=true")
	}
}

func TestLookupDeniedResponseReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"denied","message":"Daily queries exhausted"}`))
	}))
	defer server.Close()

	client := NewClient("test-key")
	client.BaseURL = server.URL
	client.HTTPClient = server.Client()

	_, _, err := client.Lookup(context.Background(), []string{"203.0.113.10"})
	if err == nil {
		t.Fatalf("expected denied response to return an error")
	}
	if !strings.Contains(err.Error(), `status "denied": Daily queries exhausted`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestApplyCopiesEnrichmentByIP(t *testing.T) {
	trueValue := true
	riskValue := 70
	results := []model.Result{
		{IP: "203.0.113.1"},
		{IP: "203.0.113.1"},
		{IP: "203.0.113.2"},
	}
	enrichments := map[string]model.ProxyCheck{
		"203.0.113.1": {
			VPN:         &trueValue,
			Risk:        &riskValue,
			VPNProvider: "IVPN",
		},
	}

	Apply(results, enrichments)

	if results[0].ProxyCheck == nil || results[1].ProxyCheck == nil {
		t.Fatalf("expected duplicate IP rows to both receive enrichment")
	}
	if results[2].ProxyCheck != nil {
		t.Fatalf("expected unmatched row to remain unenriched")
	}
	if results[0].ProxyCheck == results[1].ProxyCheck {
		t.Fatalf("expected enrichment to be copied per row, not shared by pointer")
	}
}
