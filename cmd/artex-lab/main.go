package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/Autumn-27/artex/lab"
)

func main() {
	out := flag.String("out", "", "write the JSON report to this file instead of stdout")
	flag.Parse()
	report, err := lab.Run(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, "lab:", err)
		os.Exit(1)
	}
	data, err := report.JSON()
	if err != nil {
		fmt.Fprintln(os.Stderr, "encode report:", err)
		os.Exit(1)
	}
	data = append(data, '\n')
	if *out == "" {
		_, _ = os.Stdout.Write(data)
		return
	}
	if err := os.WriteFile(*out, data, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "write report:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s\n", *out)
}
