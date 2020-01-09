package main

import (
	"bufio"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"sort"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

// ip2asn constants
const (
	RemoteHost = "whois.cymru.com" // RemoteHost TeamCymru's remote WHOIS service FQDN
	RemotePort = 43                // RemotePort TeamCymru's remote WHOIS service port
)

// CLIOptions command line options
type CLIOptions struct {
	Input  string
	Output string
}

func main() {
	app := initApp()

	app.Action = func(c *cli.Context) error {
		// Validate arguments
		opts, err := validateArgs(c)
		if err != nil {
			log.WithFields(log.Fields{
				"message": err,
			}).Fatal("invalid arguments")
		}

		// Parse input, send, and receieve results
		header, results, err := sendAndReceive(opts.Input)
		if err != nil {
			log.WithFields(log.Fields{
				"message": err,
			}).Fatal("error during send and receive")
		}

		// Check for empty results (not probable)
		if len(results) < 1 {
			log.Info("No results!")
			return nil
		}

		// Sort and output results
		sort.Sort(ByASNumber(results))

		// Write to CSV if neecessary
		if opts.Output != "" {
			f, err := os.Create(opts.Output)
			if err != nil {
				log.Fatal(err)
			}
			defer f.Close()

			w := csv.NewWriter(f)
			header := []string{"AS", "IP", "BGP Prefix", "CC", "Registry", "Allocated", "AS Name"}
			err = w.Write(header)
			if err != nil {
				log.Fatal(err)
			}
			for _, res := range results {
				w.Write(res.CSVRecord())
			}
			w.Flush()
			log.WithFields(log.Fields{
				"path": opts.Output,
			}).Info("results saved to csv")
		} else {
			fmt.Printf(header)
			for _, res := range results {
				fmt.Printf("%s\n", res.String())
			}
		}

		return nil
	}

	app.Run(os.Args)
}

func initApp() *cli.App {
	app := &cli.App{
		Name:  "ip2asn",
		Usage: "ip2asn <input_file>",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "output, o",
				Usage: "CSV output file",
				Value: "",
			},
		},
	}

	return app
}

func validateArgs(c *cli.Context) (opts *CLIOptions, err error) {
	opts = new(CLIOptions)
	if c.Args().Len() != 1 {
		opts.Input = ""
	} else {
		opts.Input = c.Args().Get(0)
	}

	opts.Output = c.String("output")

	return opts, err
}

func sendAndReceive(input string) (header string, results []*ASNResult, err error) {
	var f *os.File
	results = []*ASNResult{}
	header = "AS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name\n"

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", RemoteHost, RemotePort))
	if err != nil {
		return header, results, fmt.Errorf("Error connecting to %s:%d %v", RemoteHost, RemotePort, err)
	}
	defer conn.Close()

	// Begin and Verbose
	connOpts := []byte("begin\nverbose\n")
	_, err = conn.Write(connOpts)
	if err != nil {
		return header, results, errors.New("Unable to write to socket")
	}

	if input == "" {
		f = os.Stdin
		_, err = io.Copy(conn, f)
		if err != nil {
			return header, results, errors.New("Unable to write to socket")
		}
	} else {
		contents, err := ioutil.ReadFile(input)
		if err != nil {
			return header, results, fmt.Errorf("Error opening input file %v", err)
		}
		_, err = conn.Write(contents)
	}
	_, err = conn.Write([]byte("end\n"))
	if err != nil {
		return header, results, errors.New("Unable to write to socket")
	}

	rBulkMode := regexp.MustCompile("(Bulk mode;)")

	connbuf := bufio.NewReader(conn)
	for {
		str, err := connbuf.ReadString('\n')
		if len(str) > 0 {
			if !rBulkMode.MatchString(str) {
				res, err := parseASNResultFromString(str)
				if err != nil {
					return header, results, err
				}
				if res != nil {
					results = append(results, res)
				}
			}
		}
		if err != nil {
			err = nil
			break
		}
	}

	return header, results, err
}
