package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Autumn-27/artex/lab"
)

func main() {
	out := flag.String("out", "", "write the JSON report to this file instead of stdout")
	full := flag.Bool("full", false, "run the isolated benign active-assessment fixture")
	flag.Parse()
	var data []byte
	var err error
	if *full {
		report, runErr := lab.RunFull()
		err = runErr
		if err == nil {
			data, err = json.MarshalIndent(report, "", "  ")
		}
	} else {
		report, runErr := lab.Run(context.Background())
		err = runErr
		if err == nil {
			data, err = report.JSON()
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "lab:", err)
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
