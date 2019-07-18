package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/getlantern/probe"
)

// Using baseline:
// 	min response time: 37.609275s
// 	max response time: 2m15.187502s
// 	response time standard deviation: 25.832489579s

var (
	addr     = flag.String("addr", "52.231.39.25:443", "address to hit")
	baseline = flag.String("baseline", "randomized-transport.baseline", "baseline file")
)

func main() {
	flag.Parse()

	f, err := os.Open(*baseline)
	if err != nil {
		fmt.Println("failed to open baseline file:", err)
		os.Exit(1)
	}
	defer f.Close()

	results, err := probe.ForRandomizedTransport(probe.Config{
		Network:      "tcp",
		Address:      *addr,
		Logger:       os.Stdout,
		BaselineData: f,
	})
	if err != nil {
		fmt.Println("error running test:", err)
		os.Exit(1)
	}
	if results.Success {
		fmt.Println(results.Explanation)
		os.Exit(2)
	}
	fmt.Printf("server at %s does not appear to be a randomized transport\n", *addr)
}
