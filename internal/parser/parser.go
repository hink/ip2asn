package parser

import (
    "bufio"
    "io"
    "net/netip"
    "regexp"
    "strings"
)

// IPv4 regex (strict octet bounds)
var ipv4Re = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\b`)

// IPv6 regex captures typical and compressed forms (validation via netip afterwards).
// Note: We intentionally keep this moderately permissive; final validation is done via netip.
var ipv6Re = regexp.MustCompile(`(?i)\b(?:(?:[0-9a-f]{1,4}:){1,7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:|:(?::[0-9a-f]{1,4}){1,7}|::|(?:[0-9a-f]{1,4}:){6}(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9a-f]{1,4}:){0,5}:(?:\d{1,3}\.){3}\d{1,3})\b`)

// ParseIPs reads from r, extracts IPv4/IPv6 addresses using regex, validates with netip,
// de-duplicates while preserving first-seen order, and returns them as canonical strings.
func ParseIPs(r io.Reader) ([]string, error) {
    br := bufio.NewReader(r)
    var b strings.Builder
    const chunk = 32 * 1024
    tmp := make([]byte, chunk)
    for {
        n, err := br.Read(tmp)
        if n > 0 {
            b.Write(tmp[:n])
        }
        if err == io.EOF {
            break
        }
        if err != nil {
            return nil, err
        }
    }
    return ParseIPsFromString(b.String())
}

func ParseIPsFromString(s string) ([]string, error) {
    found := make([]string, 0, 16)
    seen := make(map[string]struct{}, 32)

    // IPv4 first
    for _, m := range ipv4Re.FindAllString(s, -1) {
        // Validate and canonicalize
        if addr, ok := parseAddr(m); ok {
            cs := addr.String()
            if _, exists := seen[cs]; !exists {
                seen[cs] = struct{}{}
                found = append(found, cs)
            }
        }
    }
    // IPv6
    for _, m := range ipv6Re.FindAllString(s, -1) {
        if addr, ok := parseAddr(m); ok {
            // Exclude cases that the IPv4 regex already captured via embedded IPv4
            cs := addr.String()
            if _, exists := seen[cs]; !exists {
                seen[cs] = struct{}{}
                found = append(found, cs)
            }
        }
    }
    return found, nil
}

func parseAddr(s string) (netip.Addr, bool) {
    // netip.ParseAddr requires brackets not present; just try parse direct
    addr, err := netip.ParseAddr(strings.TrimSpace(s))
    if err != nil {
        return netip.Addr{}, false
    }
    return addr, true
}

