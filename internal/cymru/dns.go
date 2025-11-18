package cymru

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"ip2asn/internal/model"
)

// LookupDNS performs Team Cymru DNS interface lookup for a single IP.
// For IPv4 uses origin.asn.cymru.com with reversed octets; for IPv6 uses origin6.asn.cymru.com with nibble-reversed form.
// Returns one or more results (in case of multiple origin ASNs).
func LookupDNS(ctx context.Context, ip string) ([]model.Result, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, fmt.Errorf("invalid IP: %w", err)
	}

	var qname string
	if addr.Is4() {
		qname = fmt.Sprintf("%s.origin.asn.cymru.com", reverseIPv4(addr))
	} else {
		qname = fmt.Sprintf("%s.origin6.asn.cymru.com", nibbleReverseIPv6(addr))
	}

	// TXT response format (single record) generally:
	// "<ASN(s)> | <BGP Prefix> | <CC> | <Registry> | <Allocated>"
	txts, err := lookupTXT(ctx, qname)
	if err != nil {
		return nil, err
	}
	if len(txts) == 0 {
		return nil, fmt.Errorf("no TXT records for %s", qname)
	}
	// Combine all TXT strings (usually one)
	rec := strings.Join(txts, " ")
	fields := splitFields(rec)
	if len(fields) < 5 {
		return nil, fmt.Errorf("unexpected DNS TXT format for %s: %q", qname, rec)
	}

	asField := fields[0]
	bgpPrefix := fields[1]
	cc := fields[2]
	registry := fields[3]
	allocated := fields[4]

	// asField might contain multiple ASNs separated by spaces
	asns := strings.Fields(asField)
	// Sort for deterministic output
	sort.SliceStable(asns, func(i, j int) bool { return asns[i] < asns[j] })

	// Parallel lookup for AS Names
	var wg sync.WaitGroup
	asNameMap := make(map[string]string)
	var mu sync.Mutex

	for _, s := range asns {
		wg.Add(1)
		go func(asnStr string) {
			defer wg.Done()
			// Best effort; if it fails, we just get empty string which is fine
			name, _ := asNameLookup(ctx, asnStr)
			if name != "" {
				mu.Lock()
				asNameMap[asnStr] = name
				mu.Unlock()
			}
		}(s)
	}
	wg.Wait()

	now := time.Now().UTC()
	results := make([]model.Result, 0, len(asns))
	for _, s := range asns {
		results = append(results, model.Result{
			ASN:       atoiSafe(s),
			IP:        addr.String(),
			IPAddr:    addr,
			BGPPrefix: bgpPrefix,
			CC:        cc,
			Registry:  registry,
			Allocated: allocated,
			ASName:    asNameMap[s],
			Method:    "dns",
			Retrieved: now,
		})
	}
	return results, nil
}

func reverseIPv4(a netip.Addr) string {
	ip := a.As4()
	return fmt.Sprintf("%d.%d.%d.%d", ip[3], ip[2], ip[1], ip[0])
}

func nibbleReverseIPv6(a netip.Addr) string {
	b := a.As16()
	// Expand to 32 hex nibbles and reverse order with dots between
	const hexdigits = "0123456789abcdef"
	var nibbles [32]byte
	for i := 0; i < 16; i++ {
		nibbles[i*2] = hexdigits[int(b[i]>>4)]
		nibbles[i*2+1] = hexdigits[int(b[i]&0xF)]
	}
	// Reverse order into dotted string
	sb := strings.Builder{}
	for i := 31; i >= 0; i-- {
		sb.WriteByte(nibbles[i])
		if i != 0 {
			sb.WriteByte('.')
		}
	}
	return sb.String()
}

func lookupTXT(ctx context.Context, name string) ([]string, error) {
	return net.DefaultResolver.LookupTXT(ctx, name)
}

// AS name lookup: "AS<asn>.asn.cymru.com" returns TXT like:
// "<ASN> | <CC> | <Registry> | <Allocated> | <AS Name>"
func asNameLookup(ctx context.Context, asn string) (string, error) {
	name := fmt.Sprintf("AS%s.asn.cymru.com", strings.TrimSpace(asn))
	txts, err := lookupTXT(ctx, name)
	if err != nil {
		return "", err
	}
	if len(txts) == 0 {
		return "", fmt.Errorf("no TXT for %s", name)
	}
	rec := strings.Join(txts, " ")
	f := splitFields(rec)
	if len(f) < 5 {
		return "", fmt.Errorf("unexpected AS TXT: %q", rec)
	}
	// Last field is AS Name (can include spaces and commas)
	return f[len(f)-1], nil
}

var fieldSplitRe = regexp.MustCompile(`\s*\|\s*`)

func splitFields(line string) []string {
	parts := fieldSplitRe.Split(strings.TrimSpace(strings.Trim(line, `"`)), -1)
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func atoiSafe(s string) int {
	var n int
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return -1
		}
		n = n*10 + int(ch-'0')
	}
	return n
}