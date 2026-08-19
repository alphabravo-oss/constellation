package dpi

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// parsePostgres handles the most common Postgres v3 frontend/backend messages:
//   - StartupMessage (no type byte, big-endian length, version 196608)
//   - Query (type='Q')
//   - Parse (type='P') — extended-query protocol
//
// Reference: https://www.postgresql.org/docs/current/protocol-message-formats.html
func parsePostgres(flow Flow, dir Direction, payload []byte) *L7Event {
	if len(payload) < 8 {
		return nil
	}
	// Untyped StartupMessage: length(4) + protocol(4=196608) + key/value pairs NUL-terminated.
	if len(payload) >= 8 {
		length := int(binary.BigEndian.Uint32(payload[0:4]))
		ver := binary.BigEndian.Uint32(payload[4:8])
		if length >= 8 && length <= len(payload) && ver == 196608 {
			kvs := bytes.Split(payload[8:length], []byte{0})
			user, db := "", ""
			for i := 0; i+1 < len(kvs); i += 2 {
				switch string(kvs[i]) {
				case "user":
					user = string(kvs[i+1])
				case "database":
					db = string(kvs[i+1])
				}
			}
			return &L7Event{
				Flow: flow, Protocol: "postgres", Dir: dir,
				Postgres: &PostgresEvent{Command: "startup", User: user, Schema: db},
			}
		}
	}

	// Typed message: type(1) length(4) body.
	t := payload[0]
	length := int(binary.BigEndian.Uint32(payload[1:5]))
	if length < 4 || 1+length > len(payload) {
		return nil
	}
	body := payload[5 : 1+length]
	switch t {
	case 'Q':
		return &L7Event{
			Flow: flow, Protocol: "postgres", Dir: dir,
			Postgres: &PostgresEvent{Command: "query", Query: strings.TrimRight(string(body), "\x00 ")},
		}
	case 'P':
		// Parse: name\0 query\0 int16 ...
		parts := bytes.SplitN(body, []byte{0}, 3)
		if len(parts) < 2 {
			return nil
		}
		return &L7Event{
			Flow: flow, Protocol: "postgres", Dir: dir,
			Postgres: &PostgresEvent{Command: "parse", Query: string(parts[1])},
		}
	}
	return nil
}
