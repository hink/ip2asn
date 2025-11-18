package model

import (
	"net/netip"
	"time"
)

// Result is a normalized output row for an IP to ASN mapping.
//
// Fields align with Team Cymru outputs and the legacy tool.
type Result struct {
	ASN        int        `json:"asn"`
	IP         string     `json:"ip"`
	IPAddr     netip.Addr `json:"-"` // Parsed IP for sorting/logic
	BGPPrefix  string     `json:"bgp_prefix"`
	CC         string     `json:"cc"`
	Registry   string     `json:"registry"`
	Allocated  string     `json:"allocated"` // YYYY-MM-DD string per service output
	ASName     string     `json:"as_name"`
	Method     string     `json:"method"` // "dns" or "whois"
	Retrieved  time.Time  `json:"retrieved"`
}

