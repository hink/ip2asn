## Overview

Version: 2.2

`ip2asn` is a Go CLI that scans text for IPv4/IPv6 addresses and maps each IP to ASN metadata using Team Cymru's IP-to-ASN service.

- Single IP lookups use the DNS interface.
- Two or more IPs are sent in one bulk WHOIS query (single TCP session).
- Optional `proxycheck.io` data is available with `--enrich` / `-e` when `PROXYCHECK_API_KEY` is set.

Outputs: table (stdout, default), interactive TUI table (`--tui`/`-t`), CSV (`--csv`/`-c`), or JSON (`--json`/`-j`). CSV/JSON can optionally write to a file with `--output`/`-o`.

### Sample Output

Table (`ip2asn input.txt`):

```
╭───────┬──────────────────────┬─────────────────────┬────┬──────────┬────────────┬───────────────╮
│   ASN │ IP                   │ BGP Prefix          │ CC │ Registry │ Allocated  │ AS Name       │
├───────┼──────────────────────┼─────────────────────┼────┼──────────┼────────────┼───────────────┤
│ 13335 │ 1.1.1.1              │ 1.1.1.0/24          │ AU │ apnic    │ 2011-01-01 │ CLOUDFLARENET │
│ 15169 │ 2001:4860:4860::8888 │ 2001:4860:4860::/48 │ US │ arin     │ 2006-10-31 │ GOOGLE        │
╰───────┴──────────────────────┴─────────────────────┴────┴──────────┴────────────┴───────────────╯
```

Proxycheck table (`PROXYCHECK_API_KEY=... ip2asn --enrich input.txt`) switches table/TUI output into a proxycheck-focused view. It keeps `ASN`, `IP`, `BGP Prefix`, and `AS Name`, and replaces Cymru `CC`, `Registry`, and `Allocated` columns with plain status labels (`VPN`, `PXY`, `CMP`, `TOR`, `HST`), VPN provider, city, state, country, and risk. If proxycheck lookup fails after the Team Cymru lookup succeeds, the proxycheck-focused table still renders with placeholder values and a red error line appended below it.

CSV (`ip2asn --csv input.txt`):

```
AS,IP,BGP Prefix,CC,Registry,Allocated,AS Name
13335,1.1.1.1,1.1.1.0/24,AU,apnic,2011-01-01,CLOUDFLARENET
13335,1.0.0.1,1.0.0.0/24,US,arin,2012-02-02,CLOUDFLARENET
15169,8.8.8.8,8.8.8.0/24,US,arin,1992-12-01,GOOGLE
15169,2001:4860:4860::8888,2001:4860:4860::/48,US,arin,2006-10-31,GOOGLE
```

JSON (`ip2asn --json input.txt`), grouped by ASN:

```json
[
  {
    "asn": 13335,
    "as_name": "CLOUDFLARENET",
    "ips": [
      {
        "ip": "1.1.1.1",
        "bgp_prefix": "1.1.1.0/24",
        "cc": "AU",
        "registry": "apnic",
        "allocated": "2011-01-01",
        "method": "dns",
        "retrieved": "2024-03-14T15:09:26Z",
        "proxycheck": {
          "vpn": true,
          "compromised": true,
          "risk": 87,
          "vpn_provider": "IVPN",
          "city": "Sydney",
          "state": "NSW",
          "country": "Australia"
        }
      },
      {
        "ip": "1.0.0.1",
        "bgp_prefix": "1.0.0.0/24",
        "cc": "US",
        "registry": "arin",
        "allocated": "2012-02-02",
        "method": "dns",
        "retrieved": "2024-03-14T15:10:26Z"
      }
    ]
  },
  {
    "asn": 15169,
    "as_name": "GOOGLE",
    "ips": [
      {
        "ip": "8.8.8.8",
        "bgp_prefix": "8.8.8.0/24",
        "cc": "US",
        "registry": "arin",
        "allocated": "1992-12-01",
        "method": "whois",
        "retrieved": "2024-03-14T15:11:26Z"
      },
      {
        "ip": "2001:4860:4860::8888",
        "bgp_prefix": "2001:4860:4860::/48",
        "cc": "US",
        "registry": "arin",
        "allocated": "2006-10-31",
        "method": "whois",
        "retrieved": "2024-03-14T15:12:26Z"
      }
    ]
  }
]
```

Data source and usage guidelines: Team Cymru IP-to-ASN Mapping.

> IPs that are seen abusing the whois server with large numbers of individual queries instead of using the bulk netcat interface will be null routed. If at all possible you should consider using the DNS based query interface since it is much more efficient for individual queries. The netcat interface should be used for groups of IP lists at a time in one single TCP query.

This tool respects that guidance automatically.

## Usage

Parse IPs from a file (non-flag argument):

```
ip2asn input.txt
```

Parse IPs from stdin (piped):

```
cat input.txt | ip2asn
```

Single IP via DNS interface:

```
ip2asn --ip 8.8.8.8 --json
```

Proxycheck-focused table view:

```
PROXYCHECK_API_KEY=... ip2asn --enrich input.txt
```

Interactive TUI table:

```
ip2asn --tui input.txt
```

Interactive enriched TUI table:

```
PROXYCHECK_API_KEY=... ip2asn --tui --enrich input.txt
```

CSV to file:

```
ip2asn --csv --output out.csv input.txt
```

Flags:

- `--ip`, `-i` single IP (bypasses file/stdin and performs DNS lookup)
- `--enrich`, `-e` use proxycheck.io data (proxycheck-focused table/TUI; additive CSV/JSON)
- `--tui`, `-t` open an interactive, resize-aware full-screen table view
- `--json`, `-j` output JSON
- `--csv`, `-c` output CSV
- `--output`, `-o` path (CSV/JSON optional file; table always to stdout)

Notes: `--json` and `--csv` are mutually exclusive; if neither is set, table output is used. `--enrich` fails fast if `PROXYCHECK_API_KEY` is missing. With table/TUI output, `--enrich` selects a proxycheck-focused schema that replaces Cymru `CC`, `Registry`, and `Allocated` columns with proxycheck fields. With CSV/JSON output, `--enrich` keeps the full Cymru fields and adds proxycheck fields when available. If proxycheck itself fails, the proxycheck-focused table/TUI still renders with placeholders and an error footer, while CSV/JSON still return the base Cymru data. `--tui` is only supported with table output, requires interactive stdin/stdout, and is not compatible with `--output`.

## Sorting

Results are sorted by ASN (ascending) and then by IP address in numeric order (IPv4 and IPv6 aware).

## Build

Requires Go 1.25+

```
go build ./cmd/ip2asn
```

## Notes

- Single IP lookups use DNS (`origin.asn.cymru.com` / `origin6.asn.cymru.com`).
- Bulk lookups open one TCP connection to `whois.cymru.com:43` and send all IPs between `begin`/`end` with `verbose` enabled.
