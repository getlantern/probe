package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/getlantern/probe"
)

var (
	addr            = flag.String("addr", "", "address to hit")
	baseline        = flag.String("baseline", "", "baseline file")
	writeBaseline   = flag.Bool("write-baseline", false, "overwrite the baseline file")
	maxParallelism  = flag.Int("max-parallelism", 100, "max goroutines spawned in parallel")
	responseTimeout = flag.Duration("resp-timeout", 5*time.Minute, "max time to wait for each server response")
)

func main() {
	flag.Parse()

	if *addr == "" {
		fmt.Fprintln(os.Stderr, "address must be specified")
		os.Exit(1)
	}

	cfg := probe.Config{
		Network:         "tcp",
		Address:         *addr,
		Logger:          os.Stderr,
		MaxParallelism:  *maxParallelism,
		ResponseTimeout: *responseTimeout,
	}

	if *baseline != "" && !(*writeBaseline) {
		f, err := os.Open(*baseline)
		if err != nil {
			fmt.Fprintln(os.Stderr, "failed to open baseline file:", err)
			os.Exit(1)
		}
		defer f.Close()
		cfg.BaselineData = f
	}

	results, err := probe.ForRandomizedTransport(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error running test:", err)
		os.Exit(1)
	}

	if *baseline != "" && *writeBaseline {
		f, err := os.Create(*baseline)
		if err != nil {
			fmt.Fprintln(os.Stderr, "failed to open baseline file:", err)
			os.Exit(1)
		}
		defer f.Close()
		if _, err := io.Copy(f, results.BaselineData); err != nil {
			fmt.Fprintln(os.Stderr, "failed to write baseline data:", err)
		}
	}

	if results.Success {
		fmt.Println("found evidence of randomized transport:")
		fmt.Println(results.Explanation)
		os.Exit(2)
	}
	fmt.Printf("server at %s does not appear to be a randomized transport\n", *addr)
}
