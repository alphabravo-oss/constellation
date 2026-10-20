//go:build linux

package main

import "golang.org/x/sys/unix"

type responsePIDFD int

func (f responsePIDFD) Signal() error { return unix.PidfdSendSignal(int(f), unix.SIGKILL, nil, 0) }
func (f responsePIDFD) Close() error  { return unix.Close(int(f)) }
func openResponseProcess(pid int) (responseProcessHandle, error) {
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, err
	}
	return responsePIDFD(fd), nil
}
