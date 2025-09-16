package cymru

import (
    "bufio"
    "context"
    "fmt"
    "net"
    "strings"
    "time"

    "ip2asn/internal/model"
)

const (
    whoisHost = "whois.cymru.com"
    whoisPort = 43
)

// LookupWhoisBulk connects once to Team Cymru WHOIS, sends a bulk query in a single TCP session,
// and parses the verbose response.
func LookupWhoisBulk(ctx context.Context, ips []string) ([]model.Result, error) {
    if len(ips) == 0 { return nil, nil }

    d := net.Dialer{ Timeout: 6 * time.Second }
    conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", whoisHost, whoisPort))
    if err != nil { return nil, err }
    defer conn.Close()

    // Send begin/verbose, then IPs, then end
    if _, err := conn.Write([]byte("begin\nverbose\n")); err != nil { return nil, err }
    for _, ip := range ips {
        // Each on its own line
        if _, err := conn.Write([]byte(ip+"\n")); err != nil { return nil, err }
    }
    if _, err := conn.Write([]byte("end\n")); err != nil { return nil, err }

    _ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
    r := bufio.NewReader(conn)

    results := make([]model.Result, 0, len(ips))
    now := time.Now().UTC()
    for {
        line, err := r.ReadString('\n')
        if len(line) > 0 {
            line = strings.TrimSpace(line)
            if line == "" { continue }
            if strings.HasPrefix(line, "Bulk mode;") { continue }
            // Expect: AS | IP | BGP Prefix | CC | Registry | Allocated | [Updated?] | AS Name
            fields := splitFields(line)
            if len(fields) < 7 {
                // Might be an error line like "Error:..."; skip silently
                continue
            }
            res := model.Result{
                ASN:        atoiSafe(fields[0]),
                IP:         fields[1],
                BGPPrefix:  fields[2],
                CC:         fields[3],
                Registry:   fields[4],
                Allocated:  fields[5],
                ASName:     fields[len(fields)-1], // last field is AS Name
                Method:     "whois",
                Retrieved:  now,
            }
            results = append(results, res)
        }
        if err != nil { // EOF or timeout
            break
        }
    }
    return results, nil
}

