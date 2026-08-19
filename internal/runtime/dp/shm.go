package dp

import (
	"fmt"
	"os"
)

// dpShmPath is the POSIX shared-memory segment that dp and its supervisor
// share. dp uses it as a per-thread heartbeat surface (dp_hb[MAX_DP_THREADS])
// so a supervisor can detect a wedged worker thread without trusting the
// process to log its own death. See third_party/neuvector/base.h:27-30
// (`typedef struct dp_mnt_shm_ { uint32_t dp_hb[4]; bool dp_active[4]; }`).
//
// On Linux POSIX shm names live under /dev/shm — i.e. shm_open("/dp_mnt.shm")
// resolves to "/dev/shm/dp_mnt.shm". The path is fixed in base.h:23 and we
// cannot change it without forking the C source.
const (
	dpShmPath = "/dev/shm/dp_mnt.shm"
	// dpShmSize matches sizeof(dp_mnt_shm_t) in base.h: 4*uint32 + 4*bool = 20.
	// MAX_DP_THREADS = 4 is hardcoded in base.h:25.
	dpShmSize = 20
)

// ensureSharedMemory creates the POSIX shm segment dp expects to find. dp
// opens it RDWR-without-O_CREAT (third_party/neuvector/dp/main.c:139) and
// bails with "Unable to get shared memory" if it doesn't exist. NeuVector's
// monitor creates the segment with O_CREAT|RDWR|TRUNC at monitor.c:215; we
// do the equivalent from the Go supervisor right before forking dp.
//
// The supervisor doesn't read the heartbeat surface yet — that's a polish
// item once we observe dp under load. Wave 2's job is just to satisfy dp's
// open-or-die check.
func ensureSharedMemory() error {
	f, err := os.OpenFile(dpShmPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", dpShmPath, err)
	}
	defer f.Close()
	if err := f.Truncate(dpShmSize); err != nil {
		return fmt.Errorf("ftruncate %s to %d: %w", dpShmPath, dpShmSize, err)
	}
	return nil
}

// removeSharedMemory unlinks the segment. Best-effort; called on supervisor
// shutdown so a stale segment doesn't confuse the next agent restart.
func removeSharedMemory() {
	_ = os.Remove(dpShmPath)
}
