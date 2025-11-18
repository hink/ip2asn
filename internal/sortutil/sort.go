package sortutil

import (
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
		// Same ASN: compare IPs numerically using pre-parsed IPAddr
		return results[i].IPAddr.Compare(results[j].IPAddr) < 0
	})
}