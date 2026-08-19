// reach-e2e runs the reachability analyzer against the directory passed via --module
// and prints the verdicts. Used to prove the static-reachability path works end-to-end.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/alphabravocompany/constellation/pkg/reachability"
)

func main() {
	module := flag.String("module", ".", "Go module path to analyze")
	flag.Parse()
	v, err := reachability.AnalyzeGo(context.Background(), *module)
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAILED:", err)
		os.Exit(1)
	}
	fmt.Printf("found %d reachability verdicts (module=%s)\n", len(v), *module)
	for _, r := range v {
		short := ""
		if len(r.CallStack) > 0 {
			short = r.CallStack[0]
		}
		fmt.Printf("  %-16s  reachable=%-5v  conf=%.2f  sym=%s  stack[0]=%s\n",
			r.VulnerabilityID, r.Reachable, r.Confidence, r.Symbol, short)
	}
}
