package proxycheck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"ip2asn/internal/model"
)

const (
	defaultBaseURL = "https://proxycheck.io/v3/"
	defaultVersion = "11-February-2026"
	maxBatchSize   = 1000
	defaultTimeout = 8 * time.Second
)

// Client wraps proxycheck.io v3 lookups.
type Client struct {
	APIKey     string
	BaseURL    string
	Version    string
	BatchSize  int
	HTTPClient *http.Client
}

// NewClient builds a client with conservative defaults for the current v3 API.
func NewClient(apiKey string) *Client {
	return &Client{
		APIKey:    apiKey,
		BaseURL:   defaultBaseURL,
		Version:   defaultVersion,
		BatchSize: maxBatchSize,
		HTTPClient: &http.Client{
			Timeout: defaultTimeout,
		},
	}
}

// Lookup enriches the supplied IPs using proxycheck.io batch requests.
func (c *Client) Lookup(ctx context.Context, ips []string) (map[string]model.ProxyCheck, string, error) {
	uniqueIPs := uniqueStrings(ips)
	if len(uniqueIPs) == 0 {
		return nil, "", nil
	}

	batchSize := c.BatchSize
	if batchSize <= 0 || batchSize > maxBatchSize {
		batchSize = maxBatchSize
	}

	enrichments := make(map[string]model.ProxyCheck, len(uniqueIPs))
	warnings := make([]string, 0, 1)
	for start := 0; start < len(uniqueIPs); start += batchSize {
		end := start + batchSize
		if end > len(uniqueIPs) {
			end = len(uniqueIPs)
		}

		batchEnrichments, warningMessage, err := c.lookupBatch(ctx, uniqueIPs[start:end])
		if err != nil {
			return nil, "", err
		}
		for ip, enrichment := range batchEnrichments {
			enrichments[ip] = enrichment
		}
		if warningMessage != "" {
			warnings = appendUnique(warnings, warningMessage)
		}
	}

	return enrichments, strings.Join(warnings, "; "), nil
}

// Apply copies enrichment data onto matching results by IP string.
func Apply(results []model.Result, enrichments map[string]model.ProxyCheck) {
	for idx := range results {
		enrichment, ok := enrichments[results[idx].IP]
		if !ok || enrichment.IsEmpty() {
			continue
		}
		enrichmentCopy := enrichment
		results[idx].ProxyCheck = &enrichmentCopy
	}
}

func (c *Client) lookupBatch(ctx context.Context, ips []string) (map[string]model.ProxyCheck, string, error) {
	form := url.Values{}
	form.Set("ips", strings.Join(ips, ","))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpointURL(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, "", fmt.Errorf("read response: %w", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, "", fmt.Errorf("decode response: %w", err)
	}

	status := rawString(raw["status"])
	message := rawString(raw["message"])
	switch status {
	case "ok", "warning":
	case "":
		return nil, "", fmt.Errorf("unexpected proxycheck response (%s)", resp.Status)
	default:
		return nil, "", apiError(resp.StatusCode, status, message)
	}

	enrichments := make(map[string]model.ProxyCheck, len(ips))
	for _, ip := range ips {
		payload, ok := raw[ip]
		if !ok {
			continue
		}

		var entry apiEntry
		if err := json.Unmarshal(payload, &entry); err != nil {
			return nil, "", fmt.Errorf("decode response for %s: %w", ip, err)
		}

		enrichments[ip] = entry.toModel()
	}

	if status == "warning" {
		if message == "" {
			message = "proxycheck returned warning status"
		}
		return enrichments, message, nil
	}

	return enrichments, "", nil
}

func (c *Client) endpointURL() string {
	baseURL := c.BaseURL
	if baseURL == "" {
		baseURL = defaultBaseURL
	}

	version := c.Version
	if version == "" {
		version = defaultVersion
	}

	query := url.Values{}
	query.Set("key", c.APIKey)
	query.Set("vpn", "3")
	query.Set("asn", "1")
	query.Set("risk", "1")
	query.Set("tag", "0")
	query.Set("p", "0")
	query.Set("ver", version)

	return baseURL + "?" + query.Encode()
}

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: defaultTimeout}
}

func apiError(statusCode int, status, message string) error {
	if message == "" {
		if status == "" {
			return fmt.Errorf("proxycheck request failed with HTTP %d", statusCode)
		}
		return fmt.Errorf("proxycheck request failed with status %q", status)
	}
	if status == "" {
		return fmt.Errorf("proxycheck request failed with HTTP %d: %s", statusCode, message)
	}
	return fmt.Errorf("proxycheck request failed with status %q: %s", status, message)
}

func rawString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var value string
	if err := json.Unmarshal(raw, &value); err == nil {
		return strings.TrimSpace(value)
	}
	return ""
}

func appendUnique(items []string, value string) []string {
	for _, item := range items {
		if item == value {
			return items
		}
	}
	return append(items, value)
}

func uniqueStrings(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	unique := make([]string, 0, len(items))
	for _, item := range items {
		if _, exists := seen[item]; exists {
			continue
		}
		seen[item] = struct{}{}
		unique = append(unique, item)
	}
	return unique
}

type apiEntry struct {
	Location   apiLocation   `json:"location"`
	Detections apiDetections `json:"detections"`
	Operator   *apiOperator  `json:"operator"`
}

type apiLocation struct {
	CountryName *string `json:"country_name"`
	RegionName  *string `json:"region_name"`
	CityName    *string `json:"city_name"`
}

type apiDetections struct {
	Proxy       *bool `json:"proxy"`
	VPN         *bool `json:"vpn"`
	Compromised *bool `json:"compromised"`
	Hosting     *bool `json:"hosting"`
	TOR         *bool `json:"tor"`
	Risk        *int  `json:"risk"`
}

type apiOperator struct {
	Name *string `json:"name"`
}

func (entry apiEntry) toModel() model.ProxyCheck {
	enrichment := model.ProxyCheck{
		Proxy:       entry.Detections.Proxy,
		VPN:         entry.Detections.VPN,
		Compromised: entry.Detections.Compromised,
		Hosting:     entry.Detections.Hosting,
		TOR:         entry.Detections.TOR,
		Risk:        entry.Detections.Risk,
		Country:     derefString(entry.Location.CountryName),
		State:       derefString(entry.Location.RegionName),
		City:        derefString(entry.Location.CityName),
	}
	if entry.Operator != nil {
		enrichment.VPNProvider = derefString(entry.Operator.Name)
	}
	return enrichment
}

func derefString(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}
