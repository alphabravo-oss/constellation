// sarif-tool post-processes SARIF produced by the security scanners in scripts/security-scan.sh.
//
//	sarif-tool normalize <report.sarif>                 dedupe identical govulncheck stacks
//	sarif-tool rebase-gosec <report.sarif> <gosec.json> restore module-relative paths from the JSON output
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "sarif-tool:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) < 2 {
		return errors.New("usage: sarif-tool normalize <sarif> | rebase-gosec <sarif> <gosec.json>")
	}
	switch args[0] {
	case "normalize":
		return rewrite(args[1], normalize)
	case "rebase-gosec":
		if len(args) < 3 {
			return errors.New("rebase-gosec needs <sarif> <gosec.json>")
		}
		src, err := os.ReadFile(args[2])
		if err != nil {
			return err
		}
		root, err := os.Getwd()
		if err != nil {
			return err
		}
		return rewrite(args[1], func(report map[string]any) error { return rebase(report, src, root) })
	}
	return fmt.Errorf("unknown subcommand %q", args[0])
}

func rewrite(path string, fn func(map[string]any) error) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var report map[string]any
	if err := json.Unmarshal(raw, &report); err != nil {
		return err
	}
	if err := fn(report); err != nil {
		return err
	}
	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(out, '\n'), 0o600)
}

// normalize removes duplicate stacks emitted by govulncheck, preserving every finding.
func normalize(report map[string]any) error {
	for _, result := range results(report) {
		stacks, ok := result["stacks"].([]any)
		if !ok {
			continue
		}
		seen := map[string]bool{}
		unique := make([]any, 0, len(stacks))
		for _, st := range stacks {
			key, _ := json.Marshal(st)
			if seen[string(key)] {
				continue
			}
			seen[string(key)] = true
			unique = append(unique, st)
		}
		result["stacks"] = unique
	}
	return nil
}

// rebase restores module-relative SARIF paths from the same gosec scan's JSON output. gosec
// uses each package directory as a SARIF root, flattening cmd/a/main.go and cmd/b/main.go to
// the same URI; both formatters iterate the same issue list, so identity is validated first.
func rebase(report map[string]any, gosecJSON []byte, root string) error {
	var src struct {
		Issues []struct {
			RuleID  string `json:"rule_id"`
			Details string `json:"details"`
			File    string `json:"file"`
			Line    string `json:"line"`
		} `json:"Issues"`
	}
	if err := json.Unmarshal(gosecJSON, &src); err != nil {
		return err
	}
	res := results(report)
	if len(res) != len(src.Issues) {
		return errors.New("gosec JSON/SARIF finding counts differ")
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	for i, result := range res {
		issue := src.Issues[i]
		locations, _ := result["locations"].([]any)
		if len(locations) != 1 {
			return errors.New("unexpected gosec location shape")
		}
		loc, _ := locations[0].(map[string]any)
		phys, _ := loc["physicalLocation"].(map[string]any)
		region, _ := phys["region"].(map[string]any)
		msg, _ := result["message"].(map[string]any)
		startLine, _ := strconv.Atoi(strings.SplitN(issue.Line, "-", 2)[0])
		if result["ruleId"] != issue.RuleID || msg["text"] != issue.Details || int(toFloat(region["startLine"])) != startLine {
			return errors.New("gosec JSON/SARIF finding identity differs")
		}
		abs, err := filepath.Abs(issue.File)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(absRoot, abs)
		if err != nil || strings.HasPrefix(rel, "..") {
			return fmt.Errorf("issue path %s is outside the module root", issue.File)
		}
		art, _ := phys["artifactLocation"].(map[string]any)
		if art == nil {
			art = map[string]any{}
			phys["artifactLocation"] = art
		}
		art["uri"] = url.PathEscape(filepath.ToSlash(rel))
		// PathEscape encodes "/" — restore it, matching Python's quote(safe="/").
		art["uri"] = strings.ReplaceAll(art["uri"].(string), "%2F", "/")
	}
	return nil
}

func results(report map[string]any) []map[string]any {
	var out []map[string]any
	runs, _ := report["runs"].([]any)
	for _, r := range runs {
		run, _ := r.(map[string]any)
		rs, _ := run["results"].([]any)
		for _, x := range rs {
			if m, ok := x.(map[string]any); ok {
				out = append(out, m)
			}
		}
	}
	return out
}

func toFloat(v any) float64 {
	f, _ := v.(float64)
	return f
}
