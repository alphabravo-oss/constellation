package main

import (
	"errors"
	"math"
)

// networkPolicyWireID preserves legacy zero (no policy-id stamp) but never lets
// a database int64 alias another policy after conversion to the dp uint32 wire.
func networkPolicyWireID(id int64) (uint32, error) {
	if id < 0 || id > math.MaxUint32 {
		return 0, errors.New("network policy id is outside the uint32 wire range")
	}
	return uint32(id), nil
}

// signatureWireID requires an assigned positive database identity before the
// existing DLP/WAF range mapping. Truncating first would make 2^32+n alias n.
func signatureWireID(id int64) (uint32, error) {
	if id <= 0 || id > math.MaxUint32 {
		return 0, errors.New("signature rule id is outside the positive uint32 wire range")
	}
	return uint32(id), nil
}

func validateSignatureWireIDs(rules []dlpRuleWire) error {
	for _, rule := range rules {
		if _, err := signatureWireID(rule.DPRuleID); err != nil {
			return err
		}
	}
	return nil
}
