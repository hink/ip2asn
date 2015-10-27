package main

import (
	"bufio"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"regexp"
	"sort"

	"github.com/codegangsta/cli"
)

// RemoteHost TeamCymru's remote WHOIS service FQDN
const RemoteHost = "whois.cymru.com"

// RemotePort TeamCymru's remote WHOIS service port
const RemotePort = 43

// CLIOptions command line options
type CLIOptions struct {
	Input  string
	Output string
}

func main() {
	app := initApp()

	app.Action = func(c *cli.Context) {
		opts, err := validateArgs(c)
		if err != nil {
			log.Fatalf("[!] %v", err)
		}

		header, results, err := sendAndReceive(opts.Input)
		if err != nil {
			log.Fatalf("[!] %v", err)
		}

		if len(results) < 1 {
			log.Println("No results!")
			os.Exit(0)
		}

		sort.Sort(ByASNumber(results))

		// Write to CSV if neecessary
		if opts.Output != "" {
			f, err := os.Create(opts.Output)
			if err != nil {
				log.Fatalf("[!] %v", err)
			}
			defer f.Close()

			w := csv.NewWriter(f)
			header := []string{"AS", "IP", "BGP Prefix", "CC", "Registry", "Allocated", "AS Name"}
			err = w.Write(header)
			if err != nil {
				log.Fatalf("[!] %v", err)
			}
			for _, res := range results {
				w.Write(res.CSVRecord())
			}
			w.Flush()
			log.Printf("Results save to %v", opts.Output)
		} else {
			fmt.Printf(header)
			for _, res := range results {
				fmt.Printf("%s\n", res.String())
			}
		}
	}

	app.Run(os.Args)
}

func initApp() *cli.App {
	app := cli.NewApp()
	app.Name = "ip2asn"
	app.Usage = "ip2asn <input_file>"
	app.Version = "1.0"

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "output, o",
			Usage: "CSV output file",
			Value: "",
		},
	}

	return app
}

func validateArgs(c *cli.Context) (*CLIOptions, error) {
	opts := new(CLIOptions)

	if len(c.Args()) != 1 {
		opts.Input = ""
	} else {
		opts.Input = c.Args()[0]
	}

	opts.Output = c.String("output")

	return opts, nil
}

func sendAndReceive(input string) (string, []*ASNResult, error) {
	var f *os.File
	results := []*ASNResult{}

	header := "AS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name\n"

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", RemoteHost, RemotePort))
	if err != nil {
		return "", nil, fmt.Errorf("Error connecting to %s:%d : %v", RemoteHost, RemotePort, err)
	}
	defer conn.Close()

	// Begin and Verbose
	connOpts := []byte("begin\nverbose\n")
	_, err = conn.Write(connOpts)
	if err != nil {
		return "", nil, errors.New("Unable to write to socket")
	}

	if input == "" {
		f = os.Stdin
		_, err = io.Copy(conn, f)
		if err != nil {
			return "", nil, errors.New("Unable to write to socket")
		}
	} else {
		contents, err := ioutil.ReadFile(input)
		if err != nil {
			return "", nil, fmt.Errorf("Error opening input file : %v", err)
		}
		_, err = conn.Write(contents)
	}
	_, err = conn.Write([]byte("end\n"))
	if err != nil {
		return "", nil, errors.New("Unable to write to socket")
	}

	rBulkMode := regexp.MustCompile("(Bulk mode;)")

	connbuf := bufio.NewReader(conn)
	for {
		str, err := connbuf.ReadString('\n')
		if len(str) > 0 {
			if !rBulkMode.MatchString(str) {
				res, err := parseASNResultFromString(str)
				if err != nil {
					return "", nil, err
				}
				results = append(results, res)
			}
		}
		if err != nil {
			break
		}
	}

	return header, results, nil
}
