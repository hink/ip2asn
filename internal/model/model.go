package model

import (
	"net/netip"
	"time"
)

// Result is a normalized output row for an IP to ASN mapping.
//
// Fields align with Team Cymru outputs and the legacy tool.
type Result struct {
	ASN        int         `json:"asn"`
	IP         string      `json:"ip"`
	IPAddr     netip.Addr  `json:"-"` // Parsed IP for sorting/logic
	BGPPrefix  string      `json:"bgp_prefix"`
	CC         string      `json:"cc"`
	Registry   string      `json:"registry"`
	Allocated  string      `json:"allocated"` // YYYY-MM-DD string per service output
	ASName     string      `json:"as_name"`
	Method     string      `json:"method"` // "dns" or "whois"
	Retrieved  time.Time   `json:"retrieved"`
	ProxyCheck *ProxyCheck `json:"proxycheck,omitempty"`
}

// ProxyCheck contains optional enrichment data from proxycheck.io.
type ProxyCheck struct {
	Proxy       *bool  `json:"proxy,omitempty"`
	VPN         *bool  `json:"vpn,omitempty"`
	Compromised *bool  `json:"compromised,omitempty"`
	Hosting     *bool  `json:"hosting,omitempty"`
	TOR         *bool  `json:"tor,omitempty"`
	Risk        *int   `json:"risk,omitempty"`
	VPNProvider string `json:"vpn_provider,omitempty"`
	City        string `json:"city,omitempty"`
	State       string `json:"state,omitempty"`
	Country     string `json:"country,omitempty"`
}

// IsEmpty reports whether the enrichment contains any populated fields.
func (p ProxyCheck) IsEmpty() bool {
	return p.Proxy == nil &&
		p.VPN == nil &&
		p.Compromised == nil &&
		p.Hosting == nil &&
		p.TOR == nil &&
		p.Risk == nil &&
		p.VPNProvider == "" &&
		p.City == "" &&
		p.State == "" &&
		p.Country == ""
}
