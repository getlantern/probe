package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/getlantern/probe"
)

var (
	addr          = flag.String("addr", "52.231.39.25:443", "address to hit")
	baseline      = flag.String("baseline", "", "baseline file")
	writeBaseline = flag.Bool("write-baseline", false, "overwrite the baseline file")
)

func main() {
	flag.Parse()

	cfg := probe.Config{
		Network:        "tcp",
		Address:        *addr,
		Logger:         os.Stderr,
		MaxParallelism: 100,
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
		fmt.Println(results.Explanation)
		os.Exit(2)
	}
	fmt.Printf("server at %s does not appear to be a randomized transport\n", *addr)
}
