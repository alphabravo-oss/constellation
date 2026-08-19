package waf

// BuiltinCRS returns a small OWASP-CRS-flavored sensor that covers SQLi, XSS, path
// traversal, and command injection. Rule IDs match CRS ranges (942xxx SQLi, 941xxx
// XSS, 930xxx LFI, 932xxx RCE) so customers' existing dashboards can correlate.
func BuiltinCRS() Sensor {
	return Sensor{
		Name:    "owasp-crs-core",
		Group:   "constellation-default",
		Type:    CfgPredefined,
		Comment: "Constellation default WAF rule pack (CRS-flavored subset).",
		Rules: []Rule{
			// --- SQL injection ---
			{
				ID: 942100, Msg: "SQL Injection Attempt (UNION SELECT)",
				Phase: "request", Severity: SevCritical, Action: "block",
				Transformations: []string{"lowercase", "urlDecode"},
				Target:          "ARGS",
				Operator: MatchExpr{Type: "rx", Value: `(?i)\bunion\b.+\bselect\b`},
				Tags:            []string{"sqli", "OWASP_CRS"},
			},
			{
				ID: 942110, Msg: "SQL Injection Attempt (OR/AND tautology)",
				Phase: "request", Severity: SevCritical, Action: "block",
				// NB: do NOT include removeWhitespace here — the \bor\b / \band\b
				// word-boundary checks require a non-word char on at least one side
				// of the keyword. An earlier revision stripped whitespace up-front
				// which silently neutered this rule for the canonical
				// `?id=1 OR 1=1--` payload (Wave H3 regression — see
				// deploy/e2e/threat-scenarios/05-waf-sqli/EVIDENCE.md).
				Transformations: []string{"lowercase", "urlDecode"},
				Target:          "ARGS",
				Operator: MatchExpr{Type: "rx", Value: `(?i)(\bor\b|\band\b).{0,8}['"]?\d+['"]?\s*=\s*['"]?\d+`},
				Tags:            []string{"sqli", "OWASP_CRS"},
			},
			// --- XSS ---
			{
				ID: 941100, Msg: "XSS Attempt (script tag)",
				Phase: "request", Severity: SevCritical, Action: "block",
				Transformations: []string{"lowercase", "urlDecode"},
				Target:          "ARGS",
				Operator: MatchExpr{Type: "rx", Value: `<\s*script[\s>]`},
				Tags:            []string{"xss", "OWASP_CRS"},
			},
			{
				ID: 941110, Msg: "XSS Attempt (javascript: URI)",
				Phase: "request", Severity: SevError, Action: "block",
				Transformations: []string{"lowercase", "urlDecode"},
				Target:          "ARGS",
				Operator: MatchExpr{Type: "rx", Value: `javascript\s*:`},
				Tags:            []string{"xss", "OWASP_CRS"},
			},
			{
				ID: 941120, Msg: "XSS Attempt (event handler)",
				Phase: "request", Severity: SevError, Action: "alert",
				Transformations: []string{"lowercase", "urlDecode"},
				Target:          "ARGS",
				Operator: MatchExpr{Type: "rx", Value: `on(error|load|click|mouse\w+)\s*=`},
				Tags:            []string{"xss", "OWASP_CRS"},
			},
			// --- Path traversal / LFI ---
			{
				ID: 930100, Msg: "Path Traversal Attempt",
				Phase: "request", Severity: SevCritical, Action: "block",
				Transformations: []string{"urlDecode"},
				Target:          "REQUEST_URI",
				Operator: MatchExpr{Type: "rx", Value: `(\.\./|\.\.\\)`},
				Tags:            []string{"lfi", "OWASP_CRS"},
			},
			{
				ID: 930110, Msg: "Sensitive file access (etc/passwd)",
				Phase: "request", Severity: SevCritical, Action: "block",
				Transformations: []string{"lowercase", "urlDecode"},
				Target:          "REQUEST_URI",
				Operator: MatchExpr{Type: "contains", Value: "/etc/passwd"},
				Tags:            []string{"lfi", "OWASP_CRS"},
			},
			// --- Command injection (RCE) ---
			{
				ID: 932100, Msg: "OS Command Injection (shell metachar)",
				Phase: "request", Severity: SevCritical, Action: "block",
				Transformations: []string{"urlDecode"},
				Target:          "ARGS",
				Operator: MatchExpr{Type: "rx", Value: "(?i)(;|\\|\\||&&|`).{0,3}(cat\\s|/bin/|nc\\s|bash\\s|sh\\s|wget\\s|curl\\s)"},
				Tags:            []string{"rce", "OWASP_CRS"},
			},
			{
				ID: 932110, Msg: "OS Command Injection (uname/id/whoami)",
				Phase: "request", Severity: SevError, Action: "alert",
				Transformations: []string{"lowercase", "urlDecode"},
				Target:          "ARGS",
				Operator: MatchExpr{Type: "rx", Value: `\b(uname\s*-a|whoami|id\s*;|cat\s+/etc/)`},
				Tags:            []string{"rce", "OWASP_CRS"},
			},
			// --- Suspicious User-Agent ---
			{
				ID: 913100, Msg: "Suspicious scanner User-Agent",
				Phase: "request", Severity: SevWarning, Action: "alert",
				Transformations: []string{"lowercase"},
				Target:          "REQUEST_HEADERS:User-Agent",
				Operator: MatchExpr{Type: "rx", Value: `(sqlmap|nikto|nessus|nmap|acunetix|wpscan|masscan)`},
				Tags:            []string{"reputation", "OWASP_CRS"},
			},
		},
	}
}
