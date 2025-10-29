package output

import (
	"fmt"
	"ip2asn/internal/model"
	"time"
)

// JSONASNGroup represents the JSON output structure grouped by ASN.
type JSONASNGroup struct {
	ASN    int           `json:"asn"`
	ASName string        `json:"as_name"`
	IPs    []JSONIPEntry `json:"ips"`
}

// JSONIPEntry contains per-IP metadata nested under an ASN group.
type JSONIPEntry struct {
	IP        string    `json:"ip"`
	BGPPrefix string    `json:"bgp_prefix"`
	CC        string    `json:"cc"`
	Registry  string    `json:"registry"`
	Allocated string    `json:"allocated"`
	Method    string    `json:"method"`
	Retrieved time.Time `json:"retrieved"`
}

// GroupResultsByASN transforms a flat list of results into ASN-grouped JSON structures.
func GroupResultsByASN(results []model.Result) []JSONASNGroup {
	if len(results) == 0 {
		return nil
	}

	grouped := make([]JSONASNGroup, 0)
	var currentGroup *JSONASNGroup
	var seen map[string]struct{}

	for _, r := range results {
		if currentGroup == nil || r.ASN != currentGroup.ASN {
			grouped = append(grouped, JSONASNGroup{
				ASN:    r.ASN,
				ASName: r.ASName,
				IPs:    make([]JSONIPEntry, 0, 1),
			})
			currentGroup = &grouped[len(grouped)-1]
			seen = make(map[string]struct{})
		}

		entry := JSONIPEntry{
			IP:        r.IP,
			BGPPrefix: r.BGPPrefix,
			CC:        r.CC,
			Registry:  r.Registry,
			Allocated: r.Allocated,
			Method:    r.Method,
			Retrieved: r.Retrieved,
		}
		key := makeEntryKey(entry)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		currentGroup.IPs = append(currentGroup.IPs, entry)
	}

	return grouped
}

func makeEntryKey(entry JSONIPEntry) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
		entry.IP,
		entry.BGPPrefix,
		entry.CC,
		entry.Registry,
		entry.Allocated,
		entry.Method,
		entry.Retrieved.Format(time.RFC3339Nano),
	)
}
