package dp

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type netnsRestoreFixture struct {
	callerTID    int
	workerTID    int
	workerGID    string
	fallbackPath string
	unlocks      int
	events       []string
	openErrors   map[string]error
	enterError   error
	readError    error
	restoreErr   error
	panicValue   any
}

func (f *netnsRestoreFixture) check(t *testing.T, event string) {
	t.Helper()
	if tid := unix.Gettid(); tid != f.workerTID || tid == f.callerTID {
		t.Errorf("%s ran on tid %d; worker=%d caller=%d", event, tid, f.workerTID, f.callerTID)
	}
	f.events = append(f.events, event)
}

func (f *netnsRestoreFixture) open(t *testing.T, path string, flags int, mode uint32) (int, error) {
	t.Helper()
	eventPath := path
	if path != "/proc/thread-self/ns/net" && path != "/fake/target" {
		want := "/proc/self/task/" + strconv.Itoa(f.workerTID) + "/ns/net"
		if path != want {
			f.check(t, "open:"+path)
			t.Errorf("saved namespace fallback %q does not use actual worker TID %d", path, f.workerTID)
			return -1, fmt.Errorf("unexpected namespace fallback %q", path)
		}
		f.fallbackPath = path
		eventPath = "/proc/current-worker/ns/net"
	}
	f.check(t, "open:"+eventPath)
	if flags != unix.O_RDONLY|unix.O_CLOEXEC || mode != 0 {
		t.Errorf("unexpected open flags=%d mode=%d", flags, mode)
	}
	if err := f.openErrors[eventPath]; err != nil {
		return -1, err
	}
	if path == "/fake/target" {
		return 102, nil
	}
	return 101, nil
}

// Namespace operations are fake; thread locking and worker retirement are real.
// Every operation checks that it runs on the same worker, never the caller.
func (f *netnsRestoreFixture) operations(t *testing.T) containerNetnsOps {
	t.Helper()
	return containerNetnsOps{
		lock: func() {
			runtime.LockOSThread()
			f.workerTID = unix.Gettid()
			f.workerGID = netnsRestoreGoroutineID()
			f.check(t, "lock")
		},
		unlock: func() {
			f.check(t, "unlock")
			f.unlocks++
			runtime.UnlockOSThread()
		},
		open: func(path string, flags int, mode uint32) (int, error) {
			return f.open(t, path, flags, mode)
		},
		close: func(fd int) error {
			f.check(t, "close:"+strconv.Itoa(fd))
			return nil
		},
		setns: func(fd, kind int) error {
			f.check(t, "setns:"+strconv.Itoa(fd))
			if kind != unix.CLONE_NEWNET {
				t.Errorf("setns kind=%d", kind)
			}
			switch fd {
			case 102:
				return f.enterError
			case 101:
				return f.restoreErr
			default:
				return fmt.Errorf("unexpected namespace fd %d", fd)
			}
		},
		read: func() ([]netIface, error) {
			f.check(t, "read")
			if f.panicValue != nil {
				panic(f.panicValue)
			}
			if f.readError != nil {
				return nil, f.readError
			}
			return []netIface{{name: "eth0", mac: "02:00:00:00:00:01", ips: []string{"192.0.2.1"}}}, nil
		},
	}
}

func lockedNetnsCaller(t *testing.T) (int, string, func()) {
	t.Helper()
	runtime.LockOSThread()
	tid := unix.Gettid()
	ns, err := os.Readlink("/proc/thread-self/ns/net")
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatalf("read caller namespace: %v", err)
	}
	return tid, ns, runtime.UnlockOSThread
}

func assertNetnsCallerUnchanged(t *testing.T, tid int, namespace string) {
	t.Helper()
	if got := unix.Gettid(); got != tid {
		t.Errorf("locked caller migrated from tid %d to %d", tid, got)
	}
	got, err := os.Readlink("/proc/thread-self/ns/net")
	if err != nil || got != namespace {
		t.Errorf("caller namespace changed: got %q err=%v want %q", got, err, namespace)
	}
}

func netnsRestoreGoroutineID() string {
	buffer := make([]byte, 4096)
	n := runtime.Stack(buffer, false)
	fields := strings.Fields(string(buffer[:n]))
	if len(fields) < 2 || fields[0] != "goroutine" {
		return ""
	}
	if id, err := strconv.ParseUint(fields[1], 10, 64); err != nil || id == 0 {
		return ""
	}
	return fields[1]
}

func netnsRestoreProfileContains(profile []byte, complete bool, workerGID string) (bool, error) {
	if id, err := strconv.ParseUint(workerGID, 10, 64); err != nil || id == 0 {
		return false, fmt.Errorf("worker goroutine identity unavailable")
	}
	if !complete || len(profile) == 0 {
		return false, fmt.Errorf("worker goroutine profile incomplete")
	}
	found := false
	seen := make(map[string]bool)
	for _, stack := range strings.Split(string(profile), "\n\n") {
		if strings.TrimSpace(stack) == "" {
			continue
		}
		fields := strings.Fields(strings.SplitN(stack, "\n", 2)[0])
		if len(fields) < 3 || fields[0] != "goroutine" || !strings.HasPrefix(fields[2], "[") {
			return false, fmt.Errorf("unrecognized goroutine profile header")
		}
		if id, err := strconv.ParseUint(fields[1], 10, 64); err != nil || id == 0 || seen[fields[1]] {
			return false, fmt.Errorf("invalid goroutine profile identity")
		}
		seen[fields[1]] = true
		found = found || fields[1] == workerGID
	}
	if len(seen) == 0 {
		return false, fmt.Errorf("goroutine profile has no identities")
	}
	return found, nil
}

func assertNetnsWorkerRetired(t *testing.T, workerTID, callerTID int, workerGID string) {
	t.Helper()
	if workerTID <= 0 || workerTID == callerTID {
		t.Errorf("namespace worker must use a distinct thread: worker=%d caller=%d", workerTID, callerTID)
		return
	}
	path := "/proc/self/task/" + strconv.Itoa(workerTID)
	deadline := time.Now().Add(2 * time.Second)
	buffer := make([]byte, 2*1024*1024)
	for {
		n := runtime.Stack(buffer, true)
		alive, profileErr := netnsRestoreProfileContains(buffer[:n], n < len(buffer), workerGID)
		if profileErr != nil {
			t.Fatalf("observe worker goroutine: %v", profileErr)
		}
		_, taskErr := os.Stat(path)
		if taskErr != nil && !errors.Is(taskErr, os.ErrNotExist) {
			t.Fatalf("observe worker thread: %v", taskErr)
		}
		// Go parks m0 after its locked goroutine exits; it never returns that
		// OS thread to the pool. Other workers must lose their OS task too.
		if !alive && (workerTID == os.Getpid() || errors.Is(taskErr, os.ErrNotExist)) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("restore-failed worker did not retire: tid=%d m0=%t goroutine_alive=%t task_error=%v", workerTID, workerTID == os.Getpid(), alive, taskErr)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestInterfacesInNetnsRestoreFailureRetiresWorker(t *testing.T) {
	readFailure := errors.New("read failure")
	restoreFailure := errors.New("restore failure")
	for _, tc := range []struct {
		name    string
		readErr error
	}{{"successful-read", nil}, {"failed-read", readFailure}} {
		t.Run(tc.name, func(t *testing.T) {
			tid, namespace, unlock := lockedNetnsCaller(t)
			defer unlock()
			f := &netnsRestoreFixture{callerTID: tid, readError: tc.readErr, restoreErr: restoreFailure}
			ifaces, err := interfacesInNetnsWithOps("/fake/target", f.operations(t))
			if ifaces != nil || !errors.Is(err, restoreFailure) || (tc.readErr != nil && !errors.Is(err, tc.readErr)) {
				t.Errorf("restore failure/join lost: ifaces=%v err=%v", ifaces, err)
			}
			if f.unlocks != 0 {
				t.Errorf("restore-failed worker unlocked %d times", f.unlocks)
			}
			assertNetnsCallerUnchanged(t, tid, namespace)
			assertNetnsWorkerRetired(t, f.workerTID, tid, f.workerGID)
			want := []string{"lock", "open:/proc/thread-self/ns/net", "open:/fake/target", "setns:102", "close:102", "read", "setns:101", "close:101"}
			if !reflect.DeepEqual(f.events, want) {
				t.Errorf("restore/handle sequence got %v want %v", f.events, want)
			}
		})
	}
}

func assertNetnsSetupResult(t *testing.T, ifaces []netIface, err, failure error, wantError bool) {
	t.Helper()
	if wantError {
		if !errors.Is(err, failure) || ifaces != nil {
			t.Errorf("setup/read error lost: ifaces=%v err=%v", ifaces, err)
		}
	} else if err != nil || len(ifaces) != 1 || ifaces[0].name != "eth0" || ifaces[0].mac != "02:00:00:00:00:01" || !reflect.DeepEqual(ifaces[0].ips, []string{"192.0.2.1"}) {
		t.Errorf("successful interface discovery changed: ifaces=%v err=%v", ifaces, err)
	}
}

func TestInterfacesInNetnsSetupAndRestore(t *testing.T) {
	failure := errors.New("fixture failure")
	for _, tc := range []struct {
		name       string
		openErrors map[string]error
		enterError error
		readError  error
		wantError  bool
		wantEvents []string
	}{
		{"success", nil, nil, nil, false, []string{"lock", "open:/proc/thread-self/ns/net", "open:/fake/target", "setns:102", "close:102", "read", "setns:101", "close:101", "unlock"}},
		{"read-failure-restored", nil, nil, failure, true, []string{"lock", "open:/proc/thread-self/ns/net", "open:/fake/target", "setns:102", "close:102", "read", "setns:101", "close:101", "unlock"}},
		{"saved-open-fallback", map[string]error{"/proc/thread-self/ns/net": failure}, nil, nil, false, []string{"lock", "open:/proc/thread-self/ns/net", "open:/proc/current-worker/ns/net", "open:/fake/target", "setns:102", "close:102", "read", "setns:101", "close:101", "unlock"}},
		{"saved-open-failure", map[string]error{"/proc/thread-self/ns/net": failure, "/proc/current-worker/ns/net": failure}, nil, nil, true, []string{"lock", "open:/proc/thread-self/ns/net", "open:/proc/current-worker/ns/net", "unlock"}},
		{"target-open-failure", map[string]error{"/fake/target": failure}, nil, nil, true, []string{"lock", "open:/proc/thread-self/ns/net", "open:/fake/target", "close:101", "unlock"}},
		{"enter-failure", nil, failure, nil, true, []string{"lock", "open:/proc/thread-self/ns/net", "open:/fake/target", "setns:102", "close:102", "close:101", "unlock"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tid, namespace, unlock := lockedNetnsCaller(t)
			defer unlock()
			f := &netnsRestoreFixture{callerTID: tid, openErrors: tc.openErrors, enterError: tc.enterError, readError: tc.readError}
			ifaces, err := interfacesInNetnsWithOps("/fake/target", f.operations(t))
			assertNetnsSetupResult(t, ifaces, err, failure, tc.wantError)
			if f.unlocks != 1 || !reflect.DeepEqual(f.events, tc.wantEvents) {
				t.Errorf("cleanup unlocks=%d events=%v want %v", f.unlocks, f.events, tc.wantEvents)
			}
			if tc.name == "saved-open-fallback" || tc.name == "saved-open-failure" {
				want := "/proc/self/task/" + strconv.Itoa(f.workerTID) + "/ns/net"
				if f.fallbackPath != want {
					t.Errorf("actual fallback path got %q want worker path %q", f.fallbackPath, want)
				}
			} else if f.fallbackPath != "" {
				t.Errorf("unexpected saved namespace fallback %q", f.fallbackPath)
			}
			assertNetnsCallerUnchanged(t, tid, namespace)
		})
	}
}

func TestInterfacesInNetnsPanicCleanup(t *testing.T) {
	for _, restoreFails := range []bool{false, true} {
		t.Run(strconv.FormatBool(restoreFails), func(t *testing.T) {
			tid, namespace, unlock := lockedNetnsCaller(t)
			defer unlock()
			sentinel := &struct{ message string }{message: "reader panic"}
			f := &netnsRestoreFixture{callerTID: tid, panicValue: sentinel}
			if restoreFails {
				f.restoreErr = errors.New("restore failure")
			}
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				_, _ = interfacesInNetnsWithOps("/fake/target", f.operations(t))
			}()
			if recovered != sentinel {
				t.Errorf("caller panic changed: %v", recovered)
			}
			wantUnlocks := 1
			if restoreFails {
				wantUnlocks = 0
				assertNetnsWorkerRetired(t, f.workerTID, tid, f.workerGID)
			}
			if f.unlocks != wantUnlocks {
				t.Errorf("panic cleanup unlocks=%d want %d", f.unlocks, wantUnlocks)
			}
			want := []string{"lock", "open:/proc/thread-self/ns/net", "open:/fake/target", "setns:102", "close:102", "read", "setns:101", "close:101"}
			if !restoreFails {
				want = append(want, "unlock")
			}
			if !reflect.DeepEqual(f.events, want) {
				t.Errorf("panic restore/handle sequence got %v want %v", f.events, want)
			}
			assertNetnsCallerUnchanged(t, tid, namespace)
		})
	}
}

func TestNetnsRestoreProfileRejectsIncompleteEvidence(t *testing.T) {
	for _, tc := range []struct {
		name      string
		gid       string
		profile   string
		complete  bool
		wantAlive bool
		wantError bool
	}{
		{"unknown-identity", "", "goroutine 42 [running]:\nfixture()\n", true, false, true},
		{"invalid-identity", "not-a-gid", "goroutine 42 [running]:\nfixture()\n", true, false, true},
		{"truncated-profile", "42", "goroutine 43 [running]:\nfixture()\n", false, false, true},
		{"empty-profile", "42", " \n", true, false, true},
		{"live-worker", "42", "goroutine 42 [running, locked to thread]:\nfixture()\n", true, true, false},
		{"exited-worker", "42", "goroutine 43 [running]:\nfixture()\n", true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			alive, err := netnsRestoreProfileContains([]byte(tc.profile), tc.complete, tc.gid)
			if alive != tc.wantAlive || (err != nil) != tc.wantError {
				t.Errorf("profile result alive=%t err=%v; want alive=%t error=%t", alive, err, tc.wantAlive, tc.wantError)
			}
		})
	}
}
