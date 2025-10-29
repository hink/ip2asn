package output

import (
	"ip2asn/internal/model"
	"testing"
	"time"
)

func TestGroupResultsByASN(t *testing.T) {
	ts := time.Date(2024, 3, 14, 15, 9, 26, 0, time.UTC)
	input := []model.Result{
		{
			ASN:       13335,
			IP:        "1.1.1.1",
			BGPPrefix: "1.1.1.0/24",
			CC:        "AU",
			Registry:  "apnic",
			Allocated: "2011-01-01",
			ASName:    "CLOUDFLARENET",
			Method:    "dns",
			Retrieved: ts,
		},
		{
			ASN:       13335,
			IP:        "1.0.0.1",
			BGPPrefix: "1.0.0.0/24",
			CC:        "US",
			Registry:  "arin",
			Allocated: "2012-02-02",
			ASName:    "CLOUDFLARENET",
			Method:    "dns",
			Retrieved: ts.Add(time.Minute),
		},
		{
			ASN:       15169,
			IP:        "8.8.8.8",
			BGPPrefix: "8.8.8.0/24",
			CC:        "US",
			Registry:  "arin",
			Allocated: "1992-12-01",
			ASName:    "GOOGLE",
			Method:    "whois",
			Retrieved: ts.Add(2 * time.Minute),
		},
		{
			ASN:       15169,
			IP:        "8.8.4.4",
			BGPPrefix: "8.8.4.0/24",
			CC:        "US",
			Registry:  "arin",
			Allocated: "1992-12-01",
			ASName:    "GOOGLE",
			Method:    "whois",
			Retrieved: ts.Add(3 * time.Minute),
		},
		{
			ASN:       15169,
			IP:        "8.8.4.4",
			BGPPrefix: "8.8.4.0/24",
			CC:        "US",
			Registry:  "arin",
			Allocated: "1992-12-01",
			ASName:    "GOOGLE",
			Method:    "whois",
			Retrieved: ts.Add(3 * time.Minute),
		},
	}

	grouped := GroupResultsByASN(input)
	if len(grouped) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(grouped))
	}

	first := grouped[0]
	if first.ASN != 13335 {
		t.Fatalf("expected first ASN 13335, got %d", first.ASN)
	}
	if first.ASName != "CLOUDFLARENET" {
		t.Fatalf("expected first AS name CLOUDFLARENET, got %s", first.ASName)
	}
	if len(first.IPs) != 2 {
		t.Fatalf("expected 2 IPs for ASN 13335, got %d", len(first.IPs))
	}

	second := grouped[1]
	if second.ASN != 15169 {
		t.Fatalf("expected second ASN 15169, got %d", second.ASN)
	}
	if len(second.IPs) != 2 {
		t.Fatalf("expected deduplicated IP count of 2 for ASN 15169, got %d", len(second.IPs))
	}
}
