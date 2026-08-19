package auth

import "crypto/sha256"

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
