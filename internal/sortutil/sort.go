package sortutil

import (
    "net/netip"
    "sort"

    "ip2asn/internal/model"
)

// SortResults sorts results by ASN ascending, then by IP numerically (IPv4/IPv6).
func SortResults(results []model.Result) {
    sort.SliceStable(results, func(i, j int) bool {
        ai, aj := results[i].ASN, results[j].ASN
        if ai != aj {
            return ai < aj
        }
        // Same ASN: compare IPs numerically
        ipi, errI := netip.ParseAddr(results[i].IP)
        ipj, errJ := netip.ParseAddr(results[j].IP)
        if errI == nil && errJ == nil {
            return ipi.Compare(ipj) < 0
        }
        if errI == nil && errJ != nil {
            return true
        }
        if errI != nil && errJ == nil {
            return false
        }
        // Fallback to lexicographic
        return results[i].IP < results[j].IP
    })
}

