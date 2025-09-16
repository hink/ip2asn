package output

import (
    "encoding/csv"
    "fmt"
    "io"
    "ip2asn/internal/model"
)

// PrintTable writes a simple fixed-width table to w.
func PrintTable(w io.Writer, results []model.Result) {
    // Header
    fmt.Fprintf(w, "%-8s | %-39s | %-22s | %-2s | %-8s | %-10s | %s\n",
        "AS", "IP", "BGP Prefix", "CC", "Registry", "Allocated", "AS Name")
    for _, r := range results {
        fmt.Fprintf(w, "%-8d | %-39s | %-22s | %-2s | %-8s | %-10s | %s\n",
            r.ASN, r.IP, r.BGPPrefix, r.CC, r.Registry, r.Allocated, r.ASName)
    }
}

// WriteCSV writes CSV header + records using the provided writer.
func WriteCSV(w *csv.Writer, results []model.Result) {
    _ = w.Write([]string{"AS", "IP", "BGP Prefix", "CC", "Registry", "Allocated", "AS Name"})
    for _, r := range results {
        _ = w.Write([]string{
            fmt.Sprintf("%d", r.ASN),
            r.IP,
            r.BGPPrefix,
            r.CC,
            r.Registry,
            r.Allocated,
            r.ASName,
        })
    }
}

