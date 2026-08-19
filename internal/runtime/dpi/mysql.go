package dpi

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// MySQL wire-protocol parser. v1 handles:
//   - server handshake (packet seq=0 starting with protocol version 10)
//   - COM_QUERY (0x03)
//   - COM_INIT_DB (0x02)
//
// Reference: https://dev.mysql.com/doc/internals/en/mysql-packet.html
func parseMySQL(flow Flow, dir Direction, payload []byte) *L7Event {
	if len(payload) < 5 {
		return nil
	}
	length := int(payload[0]) | int(payload[1])<<8 | int(payload[2])<<16
	seq := payload[3]
	if length <= 0 || length > len(payload)-4 {
		return nil
	}
	body := payload[4 : 4+length]

	// Server handshake greeting: seq=0, first byte is protocol version (10) and the
	// next bytes are a NUL-terminated server-version string.
	if seq == 0 && len(body) >= 6 && body[0] == 0x0a {
		end := bytes.IndexByte(body[1:], 0)
		if end < 0 {
			return nil
		}
		return &L7Event{
			Flow: flow, Protocol: "mysql", Dir: dir,
			MySQL: &MySQLEvent{Command: "handshake"},
		}
	}

	// Command phase: first byte of body is the COM_* opcode.
	switch body[0] {
	case 0x03: // COM_QUERY
		return &L7Event{
			Flow: flow, Protocol: "mysql", Dir: dir,
			MySQL: &MySQLEvent{Command: "query", Query: strings.TrimRight(string(body[1:]), "\x00 ")},
		}
	case 0x02: // COM_INIT_DB
		return &L7Event{
			Flow: flow, Protocol: "mysql", Dir: dir,
			MySQL: &MySQLEvent{Command: "init-db", Schema: string(body[1:])},
		}
	}
	return nil
}

// silence unused import lint when binary not used in some build.
var _ = binary.LittleEndian
