package crypto

import "os"

func envOr(k string) string { return os.Getenv(k) }
