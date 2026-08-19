package falco

import "testing"

const sampleRules = `
- list: shell_binaries
  items: [sh, bash, csh, ksh, tcsh, zsh, dash]

- macro: container
  condition: container.id != host

- macro: spawned_process
  condition: evt.type = execve

- macro: shell_procs
  condition: proc.name in shell_binaries

- rule: Terminal shell in container
  desc: A shell was used as the entrypoint/exec point into a container with an attached terminal.
  condition: spawned_process and container and shell_procs
  output: "A shell was spawned in a container (user=%user.name container=%container.id shell=%proc.name)"
  priority: NOTICE
  tags: [container, shell, mitre_execution, T1059.004]

- rule: Reverse shell over HTTPS
  desc: Outbound HTTPS to a known C2 from a shell.
  condition: evt.type = connect
  output: "Reverse shell detected"
  priority: WARNING
  tags: [container, network, mitre_command_and_control]
`

func TestParse_RulesMacrosLists(t *testing.T) {
	doc, err := Parse([]byte(sampleRules))
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Rules) != 2 {
		t.Fatalf("rules: %d", len(doc.Rules))
	}
	if len(doc.Macros) != 3 {
		t.Fatalf("macros: %d", len(doc.Macros))
	}
	if len(doc.Lists) != 1 {
		t.Fatalf("lists: %d", len(doc.Lists))
	}
	shell := doc.Rules[0]
	// The rule's tags include T1059.004 + we infer it from name; should appear once after dedupe.
	found := false
	for _, id := range shell.AttackIDs {
		if id == "T1059.004" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected T1059.004 in attack ids: %v", shell.AttackIDs)
	}
}

func TestEvaluator_TerminalShellInContainerMatches(t *testing.T) {
	doc, err := Parse([]byte(sampleRules))
	if err != nil {
		t.Fatal(err)
	}
	e := NewEvaluator(doc)
	facts := map[string]any{
		"container.id": "abc123",
		"host":         "node-1",
		"evt.type":     "execve",
		"proc.name":    "bash",
	}
	matched := e.Match(facts)
	if len(matched) == 0 {
		t.Fatalf("expected terminal-shell rule to match: %+v", facts)
	}
	if matched[0].Name != "Terminal shell in container" {
		t.Fatalf("unexpected rule: %s", matched[0].Name)
	}
}

func TestEvaluator_NoMatchOutsideContainer(t *testing.T) {
	doc, err := Parse([]byte(sampleRules))
	if err != nil {
		t.Fatal(err)
	}
	e := NewEvaluator(doc)
	matched := e.Match(map[string]any{
		"container.id": "host", // == host → not a container
		"host":         "host",
		"evt.type":     "execve",
		"proc.name":    "bash",
	})
	if len(matched) != 0 {
		t.Fatalf("expected no match outside container; got %+v", matched)
	}
}
