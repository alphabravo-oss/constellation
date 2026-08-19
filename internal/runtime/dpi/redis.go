package dpi

import (
	"bytes"
	"strconv"
)

// parseRedis decodes one RESP (REdis Serialization Protocol) array command. We only
// look at the request shape (clients send arrays); replies are skipped.
//
// Example: *3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar\r\n
func parseRedis(flow Flow, dir Direction, payload []byte) *L7Event {
	if len(payload) == 0 || payload[0] != '*' {
		return nil
	}
	lines := bytes.Split(payload, []byte("\r\n"))
	if len(lines) < 2 {
		return nil
	}
	n, err := strconv.Atoi(string(lines[0][1:]))
	if err != nil || n <= 0 || n > 1024 {
		return nil
	}
	args := make([]string, 0, n)
	i := 1
	for range n {
		if i+1 >= len(lines) {
			return nil
		}
		// Expect $LEN \r\n DATA
		if len(lines[i]) == 0 || lines[i][0] != '$' {
			return nil
		}
		size, err := strconv.Atoi(string(lines[i][1:]))
		if err != nil || size < 0 || size > 1<<20 {
			return nil
		}
		args = append(args, string(lines[i+1][:min(size, len(lines[i+1]))]))
		i += 2
	}
	if len(args) == 0 {
		return nil
	}
	return &L7Event{
		Flow: flow, Protocol: "redis", Dir: dir,
		Redis: &RedisEvent{Command: args[0], Args: args[1:]},
	}
}
