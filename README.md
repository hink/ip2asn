## Overview

IP2ASN takes a list of domains and resolves their ASN information using [Team Cymru's IP to ASN Mapping Service](http://www.team-cymru.org/IP-ASN-mapping.html#whois)

## Usage

This application take a newline separated list of domains

__From a file__

```
./ip2asn input.txt
```

__From STDIN__

```
cat input.txt | ./ip2asn
```

__To CSV__

```
./ip2asn -o output.csv input.txt
```


## Build

In order to build, you must have a properly installed and configured installation of Go 1.4 or greater

```
git clone https://github.firehost.co/chinkley/ip2asn.git
cd ip2asn
go get "github.com/codegangsta/cli"
go build ip2asn.go result.go
```