// Command kubectl is upstream kubectl (k8s.io/kubernetes cmd/kubectl) rebuilt on
// the repository Go toolchain so the toolbox image carries no stale stdlib.
package main

import (
	"k8s.io/component-base/cli"
	"k8s.io/kubectl/pkg/cmd"
	"k8s.io/kubectl/pkg/cmd/util"
)

func main() {
	command := cmd.NewDefaultKubectlCommand()
	if err := cli.RunNoErrOutput(command); err != nil {
		util.CheckErr(err)
	}
}
