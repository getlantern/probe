package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/getlantern/probe"
)

// baseline response:
// 	min response time: 37.609275s
// 	max response time: 2m15.187502s
// 	response time standard deviation: 25.832489579s

var (
	addr = flag.String("addr", "52.231.39.25:443", "address to hit")
)

func main() {

	// debugging
	min, err := time.ParseDuration("1m30.190914s")
	if err != nil {
		panic(err)
	}
	max, err := time.ParseDuration("2m15.263066s")
	if err != nil {
		panic(err)
	}
	stddev, err := time.ParseDuration("22.042394335s")
	if err != nil {
		panic(err)
	}
	err = probe.RTShortcut(probe.Config{
		Network: "tcp",
		Address: *addr,
	}, float64(min), float64(max), float64(stddev))

	// err := probe.ForRandomizedTransport(probe.Config{
	// 	Network: "tcp",
	// 	Address: *addr,
	// })
	if err == nil {
		fmt.Printf("server at %s does not appear to be a randomized transport\n", *addr)
		os.Exit(0)
	}
	switch err.(type) {
	case probe.FailedCheck:
		fmt.Println(err)
		os.Exit(2)
	default:
		fmt.Println("error running test:", err)
		os.Exit(1)
	}
}
