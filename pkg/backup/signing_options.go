package backup

import "errors"

// ResolveSignMode accepts only the wire enum, retaining the caller's explicit
// legacy default for an omitted/empty value. It never turns an unknown mode into
// an unsigned backup. Errors intentionally do not include untrusted input.
func ResolveSignMode(raw string, fallback SignMode) (SignMode, error) {
	mode := SignMode(raw)
	if mode == "" {
		mode = fallback
	}
	switch mode {
	case SignModeNone, SignModeStaticKey, SignModeKeyless:
		return mode, nil
	default:
		return "", errors.New("sign_mode must be none, static-key, or keyless")
	}
}
