package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

// commandOutput stops after the first failed write. In particular, a command
// must not report success after failing to deliver a one-time credential.
// Errors contain no formatted output or response bytes.
type commandOutput struct {
	ctx    context.Context
	writer io.Writer
	err    error
}

func (out *commandOutput) write(text string) {
	if out.err != nil {
		return
	}
	if err := out.ctx.Err(); err != nil {
		out.err = err
		return
	}
	written, err := io.WriteString(out.writer, text)
	if err == nil && written != len(text) {
		err = io.ErrShortWrite
	}
	out.err = err
}

func (out *commandOutput) printf(format string, args ...any) { out.write(fmt.Sprintf(format, args...)) }
func (out *commandOutput) println(args ...any)               { out.write(fmt.Sprintln(args...)) }
func (out *commandOutput) result() error {
	if out.err != nil {
		return fmt.Errorf("write command output: %w", out.err)
	}
	return nil
}

func readCommandResponse(response *http.Response) ([]byte, error) {
	body, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read API response: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close API response: %w", closeErr)
	}
	return body, nil
}
