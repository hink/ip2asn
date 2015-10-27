package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// ASNResult TeamCymru result for an ip
type ASNResult struct {
	Allocated   *time.Time
	ASName      string
	ASNumber    int
	BGPPrefix   *net.IPNet
	CountryCode string
	IP          *net.IP
	Registry    string
	RawResult   string
}

// ByASNumber implements sort.Interface for []ASNResult based on ASNumber
type ByASNumber []*ASNResult

func (a ByASNumber) Len() int           { return len(a) }
func (a ByASNumber) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByASNumber) Less(i, j int) bool { return a[i].ASNumber < a[j].ASNumber }

func parseASNResultFromString(s string) (*ASNResult, error) {
	parts := strings.Split(s, "|")
	allocated, _ := time.Parse("2006-01-02", strings.TrimSpace(parts[5]))
	asName := ""
	if len(parts) > 6 {
		asName = strings.TrimSpace(parts[6])
	}
	asNumber, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		asNumber = -1
	}

	_, bgpPrefix, err := net.ParseCIDR(strings.TrimSpace(parts[2]))
	if err != nil {
		bgpPrefix = nil
	}
	countryCode := strings.TrimSpace(parts[3])
	ip := net.ParseIP(strings.TrimSpace(parts[1]))
	registry := strings.TrimSpace(parts[4])
	result := &ASNResult{
		Allocated:   &allocated,
		ASName:      asName,
		ASNumber:    asNumber,
		BGPPrefix:   bgpPrefix,
		CountryCode: countryCode,
		IP:          &ip,
		Registry:    registry,
		RawResult:   s,
	}

	return result, nil
}

func (a *ASNResult) String() string {
	return fmt.Sprintf("%-7v | %-16v | %-19v | %-2v | %-8v | %-10v | %v",
		a.ASNumber, a.IP, a.BGPPrefix, a.CountryCode, a.Registry,
		a.Allocated.Format("2006-01-02"), a.ASName)
}

// CSVRecord returns a CSV record of the ASNResult
func (a *ASNResult) CSVRecord() []string {
	asn := "NA"
	if a.ASNumber >= 0 {
		asn = strconv.Itoa(a.ASNumber)
	}

	bgpPrefix := "NA"
	if a.BGPPrefix != nil {
		bgpPrefix = a.BGPPrefix.String()
	}

	return []string{
		asn,
		a.IP.String(),
		bgpPrefix,
		a.CountryCode,
		a.Registry,
		a.Allocated.Format("2006-01-02"),
		a.ASName,
	}
}
