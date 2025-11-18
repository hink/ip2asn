package sortutil

import (
	"net/netip"
	"testing"

	"ip2asn/internal/model"
)

func TestSortResults(t *testing.T) {
	// Helpers to create IPs
	mustIP := func(s string) netip.Addr {
		ip, err := netip.ParseAddr(s)
		if err != nil {
			panic(err)
		}
		return ip
	}

	tests := []struct {
		name  string
		input []model.Result
		want  []model.Result
	}{
		{
			name: "sort by asn",
			input: []model.Result{
				{ASN: 200, IP: "2.2.2.2", IPAddr: mustIP("2.2.2.2")},
				{ASN: 100, IP: "1.1.1.1", IPAddr: mustIP("1.1.1.1")},
			},
			want: []model.Result{
				{ASN: 100, IP: "1.1.1.1", IPAddr: mustIP("1.1.1.1")},
				{ASN: 200, IP: "2.2.2.2", IPAddr: mustIP("2.2.2.2")},
			},
		},
		{
			name: "sort by ip when asn same",
			input: []model.Result{
				{ASN: 100, IP: "10.0.0.2", IPAddr: mustIP("10.0.0.2")},
				{ASN: 100, IP: "10.0.0.1", IPAddr: mustIP("10.0.0.1")},
			},
			want: []model.Result{
				{ASN: 100, IP: "10.0.0.1", IPAddr: mustIP("10.0.0.1")},
				{ASN: 100, IP: "10.0.0.2", IPAddr: mustIP("10.0.0.2")},
			},
		},
        {
			name: "sort mixed ipv4 ipv6 same asn",
			input: []model.Result{
				{ASN: 100, IP: "2001::1", IPAddr: mustIP("2001::1")},
				{ASN: 100, IP: "1.1.1.1", IPAddr: mustIP("1.1.1.1")},
			},
			// IPv4 maps to ::ffff:1.1.1.1 or similar in comparison?
            // netip.Addr Compare: IPv4 compares less than IPv6.
			want: []model.Result{
				{ASN: 100, IP: "1.1.1.1", IPAddr: mustIP("1.1.1.1")},
				{ASN: 100, IP: "2001::1", IPAddr: mustIP("2001::1")},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Copy input so we don't mutate test case for debugging if needed
			got := make([]model.Result, len(tt.input))
			copy(got, tt.input)
			
			SortResults(got)

			for i := range got {
				if got[i].ASN != tt.want[i].ASN {
					t.Errorf("idx %d: ASN got %d, want %d", i, got[i].ASN, tt.want[i].ASN)
				}
				if got[i].IP != tt.want[i].IP {
					t.Errorf("idx %d: IP got %s, want %s", i, got[i].IP, tt.want[i].IP)
				}
			}
		})
	}
}
