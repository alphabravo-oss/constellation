package server

import (
	"net"
	"strings"
)

// Bound parsing even when a trusted proxy appends to an attacker-controlled
// header. On malformed or excessive input callers retain the socket address.
const (
	maxForwardedIPBytes = 8192
	maxForwardedIPHops  = 64
)

func forwardedClientIP(values []string, trusted []*net.IPNet) net.IP {
	bytes, hops := 0, 0
	for _, value := range values {
		bytes += len(value)
		hops += strings.Count(value, ",") + 1
		if bytes > maxForwardedIPBytes || hops > maxForwardedIPHops {
			return nil
		}
	}
	var client net.IP
	for i := len(values) - 1; i >= 0; i-- {
		parts := strings.Split(values[i], ",")
		for j := len(parts) - 1; j >= 0; j-- {
			client = net.ParseIP(strings.TrimSpace(parts[j]))
			if client == nil {
				return nil
			}
			if !ipInNets(client, trusted) {
				return client
			}
		}
	}
	return client
}
