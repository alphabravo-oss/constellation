//go:build !linux

package main

import "errors"

func openResponseProcess(int) (responseProcessHandle, error) {
	return nil, errors.New("pidfd process actions require Linux")
}
