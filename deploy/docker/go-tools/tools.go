//go:build tools

// Package gotools pins the source of the third-party Go CLIs bundled in role
// images (toolbox: age, kubectl; runtime-agent: crictl; kube-bench-runner:
// kube-bench). They are rebuilt on the go.mod toolchain with current
// golang.org/x modules because the upstream release binaries embed stale ones.
package gotools

import (
	_ "filippo.io/age/cmd/age"
	_ "filippo.io/age/cmd/age-keygen"
	_ "github.com/aquasecurity/kube-bench"
	_ "sigs.k8s.io/cri-tools/cmd/crictl"
)
