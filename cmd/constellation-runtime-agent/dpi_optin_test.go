package main

import (
	"fmt"
	"testing"

	"github.com/alphabravocompany/constellation/internal/runtime/hostscan"
)

func TestDPIOptIn(t *testing.T) {
	cases := []struct {
		name     string
		labels   map[string]string
		waf, dlp bool
	}{
		{"none", nil, false, false},
		{"waf-label", map[string]string{labelDPIWaf: "true"}, true, false},
		{"dlp-label", map[string]string{labelDPIDlp: "enabled"}, false, true},
		{"both-labels", map[string]string{labelDPIWaf: "1", labelDPIDlp: "yes"}, true, true},
		{"inspect-all", map[string]string{labelDPIInspect: "all"}, true, true},
		{"inspect-waf", map[string]string{labelDPIInspect: "waf"}, true, false},
		{"inspect-both", map[string]string{labelDPIInspect: "waf,dlp"}, true, true},
		{"falsey", map[string]string{labelDPIWaf: "false"}, false, false},
		{"unrelated", map[string]string{"app": "api"}, false, false},
	}
	for _, c := range cases {
		waf, dlp, _ := dpiOptIn(c.labels)
		if waf != c.waf || dlp != c.dlp {
			t.Errorf("%s: dpiOptIn=%v,%v want %v,%v", c.name, waf, dlp, c.waf, c.dlp)
		}
	}
	// enforce label opts into inline (independent of waf/dlp).
	if _, _, enf := dpiOptIn(map[string]string{labelDPIEnforce: "true"}); !enf {
		t.Error("enforce label should set enforce=true")
	}
	if _, _, enf := dpiOptIn(map[string]string{labelDPIWaf: "true"}); enf {
		t.Error("no enforce label should leave enforce=false")
	}
}

func TestSplitByOptIn(t *testing.T) {
	set := map[string]bool{"aa": true, "cc": true}
	in, out := splitByOptIn([]string{"aa", "bb", "cc"}, set)
	if len(in) != 2 || len(out) != 1 || out[0] != "bb" {
		t.Fatalf("in=%v out=%v; want in=[aa cc] out=[bb]", in, out)
	}
}

func TestDPIEnforcementCannotOverrideSystemProtection(t *testing.T) {
	protected := newProtectedSet("custom-install", []string{"cnpg-system"})
	for _, ns := range []string{"custom-install", "cnpg-system", "kube-system", "kube-public", "kube-node-lease", "", "  ", "payments"} {
		for _, gate := range []bool{false, true} {
			for _, optedIn := range []bool{false, true} {
				t.Run(ns+"/"+fmt.Sprint(gate)+"/"+fmt.Sprint(optedIn), func(t *testing.T) {
					c := hostscan.RunningContainer{ID: "container", PodNS: ns, PodName: "api", PodUID: "uid", PID: 42,
						PodLabels: map[string]string{labelDPIInspect: "all", labelDPIEnforce: fmt.Sprint(optedIn), "app.kubernetes.io/name": "constellation"}}
					got := dpiRunningContainer(c, gate, protected)
					want := ns == "payments" && gate && optedIn
					if got.Enforce != want {
						t.Fatalf("Enforce=%v want %v", got.Enforce, want)
					}
					if !got.WAF || !got.DLP || got.Namespace != ns || got.PodUID != "uid" || got.ID != "container" || got.PID != 42 {
						t.Fatalf("passive inspection/identity lost: %+v", got)
					}
				})
			}
		}
	}
	c := hostscan.RunningContainer{ID: "container", PodNS: "payments", PodLabels: map[string]string{labelDPIEnforce: "true"}}
	if dpiRunningContainer(c, true, nil).Enforce {
		t.Fatal("missing protection must refuse inline enforcement")
	}
	c.ID = ""
	if dpiRunningContainer(c, true, protected).Enforce {
		t.Fatal("missing container identity must refuse inline enforcement")
	}
}
