package main

import (
	"testing"
	"time"
)

func TestHostPackagesRetryInterval(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		configured time.Duration
		want       time.Duration
	}{
		{name: "default cadence retries promptly", configured: time.Hour, want: 30 * time.Second},
		{name: "short configured cadence is preserved", configured: 10 * time.Second, want: 10 * time.Second},
		{name: "unset cadence retries promptly", configured: 0, want: 30 * time.Second},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := hostPackagesRetryInterval(tc.configured); got != tc.want {
				t.Fatalf("hostPackagesRetryInterval(%s) = %s, want %s", tc.configured, got, tc.want)
			}
		})
	}
}
