package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
	"unsafe"

	"github.com/alphabravocompany/constellation/internal/runtime/hostscan"
	"golang.org/x/sys/unix"
)

type fileProfileEnforcerConfig struct {
	Disabled     bool
	NodeName     string
	Interval     time.Duration
	HostRoot     string
	CrictlBin    string
	RuleSync     *FileProfileRuleSyncWorker
	Workloads    *workloadResolver
	Status       *fileProfileEnforcementStatusStore
	Logger       *slog.Logger
	OnDeny       func(fanotifyDecisionEvent, string)
	MaxWalkDepth int

	// Protected is the non-overridable self/host/system guard. Protected containers
	// are never marked and their events are always allowed — Constellation's own
	// components, system namespaces, and the host can't be blocked by any rule.
	Protected *protectedSet

	// Sync is the per-workload process-baseline source. The exec enforcer uses it as
	// the learn-first gate: a zero-drift exec is only DENIED when the workload's
	// baseline mode is "enforce" (Discover/Monitor => observe only), mirroring
	// NeuVector's per-group Discover->Monitor->Protect progression. Optional: when
	// nil the exec enforcer falls back to the global enforce switch.
	Sync *ProcessBaselineSyncWorker

	// OnExecDeny records a P0-3 pre-exec zero-drift decision. Optional: when nil the
	// exec enforcer only logs. reason is the drift tag ("unanchored"|"image-drift");
	// denied is true only when the exec was actually blocked (enforce mode) vs merely
	// observed (monitor mode), so the recorder can mark the event blocked accurately.
	OnExecDeny func(event fanotifyDecisionEvent, reason string, denied bool)
}

type fileProfileEnforceRule struct {
	ID             string
	WorkloadID     string
	PodWorkloadIDs []string
	Filter         string
	Path           string
	Regex          string
	Recursive      bool
	Applications   []string
	Exceptions     []fileProfileEnforceException
	pathMatches    func(string) bool
	// baseMatches reports whether a bare filename matches the rule's filename
	// pattern, ignoring the directory. Used by the path-less fallback so a
	// host-overlay path (whose directory can't be textually matched) is still
	// gated on the rule's filename glob rather than blocking every sibling
	// under the marked directory.
	baseMatches func(string) bool
}

type fileProfileEnforceException struct {
	ID           string
	RuleID       string
	Filter       string
	Path         string
	Regex        string
	Recursive    bool
	Applications []string
	pathMatches  func(string) bool
}

type fanotifyPermissionEnforcer struct {
	fd int
}

type fanotifyDecisionEvent struct {
	Fd          int32
	Pid         int32
	Path        string
	Comm        string
	Exe         string
	ContainerID string
	WorkloadID  string
	RuleID      string
}

func fileProfileEnforcerLoop(ctx context.Context, cfg fileProfileEnforcerConfig) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	// P0-3 pre-exec block (FAN_OPEN_EXEC_PERM). Launched alongside the file
	// enforcer because main.go already starts this loop; it is independently
	// gated (default OFF) and monitor-first (default observe, no in-kernel deny).
	// Runs even when file-profile enforcement below is disabled.
	if execProfileEnforcerEnabledFromEnv(os.Getenv("CONSTELLATION_EXEC_ENFORCER")) {
		go execPermissionEnforcerLoop(ctx, cfg)
	}
	// Dry-run preview (opt-in, safe on any node): logs exactly which containers the
	// exec enforcer WOULD mark vs skip (host/protected/host-shared/unknown-device)
	// WITHOUT arming any fanotify mark. Lets an operator confirm the host and system
	// namespaces are excluded on this cluster BEFORE ever enabling enforce. Runs
	// regardless of enforce mode.
	if execProfileEnforcerEnabledFromEnv(os.Getenv("CONSTELLATION_EXEC_ENFORCER_DRYRUN")) {
		go execEnforcerDryRunPreview(ctx, cfg)
	}
	if cfg.Disabled {
		cfg.Logger.Info("file-profile-enforcer: disabled")
		return
	}
	if cfg.RuleSync == nil || cfg.Status == nil {
		cfg.Logger.Info("file-profile-enforcer: disabled (missing rule sync or status store)")
		return
	}
	if cfg.Interval <= 0 {
		cfg.Interval = time.Minute
	}
	if cfg.MaxWalkDepth <= 0 {
		cfg.MaxWalkDepth = fileProfileMaxWalkDepth()
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		rules, _ := cfg.RuleSync.RulesWithFingerprint()
		active := enforceableFileProfileRules(rules)
		if len(active) == 0 {
			cfg.Status.Replace(map[string]fileProfileEnforcementStatus{})
			if !sleepOrDone(ctx, cfg.Interval) {
				return
			}
			continue
		}

		watcher, err := newFanotifyPermissionEnforcer()
		if err != nil {
			cfg.Logger.Warn("file-profile-enforcer: fanotify unavailable", slog.String("err", err.Error()))
			cfg.Status.Replace(fileProfileEnforcementErrorStatuses(active))
			if !sleepOrDone(ctx, cfg.Interval) {
				return
			}
			continue
		}

		marked, markErrs := watcher.markRules(ctx, cfg, active)
		cfg.Status.Replace(fileProfileEnforcementStatuses(active, marked, markErrs))
		cfg.Logger.Info("file-profile-enforcer: refreshed marks",
			slog.Int("rules", len(active)),
			slog.Int("marked_rules", len(marked)),
			slog.Int("errors", markErrs))

		timer := time.NewTimer(cfg.Interval)
		watcher.serve(ctx, timer.C, cfg, active)
		timer.Stop()
		_ = watcher.Close()
	}
}

func newFanotifyPermissionEnforcer() (*fanotifyPermissionEnforcer, error) {
	// FAN_UNLIMITED_QUEUE + FAN_UNLIMITED_MARKS: a bounded permission-event queue is
	// a node-freeze risk — if the single-threaded drain falls behind, the kernel
	// queue fills and every waiting open() blocks indefinitely. Unlimited queue lets
	// events drop rather than wedge; unlimited marks removes the ~8192 mark cap.
	// Mirrors NeuVector (agent/probe/faccess_linux.go:169).
	fd, err := unix.FanotifyInit(unix.FAN_CLOEXEC|unix.FAN_CLASS_CONTENT|unix.FAN_NONBLOCK|unix.FAN_UNLIMITED_QUEUE|unix.FAN_UNLIMITED_MARKS, unix.O_RDONLY|unix.O_CLOEXEC)
	if err != nil {
		return nil, err
	}
	return &fanotifyPermissionEnforcer{fd: fd}, nil
}

func (e *fanotifyPermissionEnforcer) Close() error {
	if e == nil || e.fd < 0 {
		return nil
	}
	err := unix.Close(e.fd)
	e.fd = -1
	return err
}

func (e *fanotifyPermissionEnforcer) markRules(ctx context.Context, cfg fileProfileEnforcerConfig, rules []fileProfileEnforceRule) (map[string]int, int) {
	containers, err := hostscan.CollectContainers(ctx, hostscan.ContainersOptions{
		HostRoot:  cfg.HostRoot,
		NodeName:  cfg.NodeName,
		CrictlBin: cfg.CrictlBin,
	})
	if err != nil {
		cfg.Logger.Warn("file-profile-enforcer: container inventory failed", slog.String("err", err.Error()))
		return map[string]int{}, len(rules)
	}
	marked := map[string]int{}
	errs := 0
	for _, rule := range rules {
		for _, c := range containers.Items {
			// Never mark a protected container (own/system namespace or host).
			if cfg.Protected.protects(c.ID, c.PodNS) {
				continue
			}
			if !fileProfileEnforcerContainerMatchesRule(c, rule) {
				continue
			}
			root, err := hostscan.ContainerRoot(ctx, hostscan.ContainerRootOptions{
				HostRoot:  cfg.HostRoot,
				CrictlBin: cfg.CrictlBin,
			}, c)
			if err != nil {
				errs++
				continue
			}
			paths := fileProfileEnforcerMarkPaths(root, rule, cfg.MaxWalkDepth)
			for _, markPath := range paths {
				mask := uint64(unix.FAN_OPEN_PERM)
				if st, err := os.Stat(markPath); err == nil && st.IsDir() {
					mask |= unix.FAN_EVENT_ON_CHILD
				}
				if err := unix.FanotifyMark(e.fd, unix.FAN_MARK_ADD, mask, unix.AT_FDCWD, markPath); err != nil {
					errs++
					cfg.Logger.Debug("file-profile-enforcer: mark failed",
						slog.String("path", markPath),
						slog.String("rule", rule.ID),
						slog.String("err", err.Error()))
					continue
				}
				marked[rule.ID]++
			}
		}
	}
	return marked, errs
}

func (e *fanotifyPermissionEnforcer) serve(ctx context.Context, refresh <-chan time.Time, cfg fileProfileEnforcerConfig, rules []fileProfileEnforceRule) {
	buf := make([]byte, 64*1024)
	for {
		select {
		case <-ctx.Done():
			return
		case <-refresh:
			return
		default:
		}
		n, err := unix.Read(e.fd, buf)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			cfg.Logger.Warn("file-profile-enforcer: read failed", slog.String("err", err.Error()))
			return
		}
		e.handleEvents(cfg, rules, buf[:n])
	}
}

func (e *fanotifyPermissionEnforcer) handleEvents(cfg fileProfileEnforcerConfig, rules []fileProfileEnforceRule, buf []byte) {
	metaSize := int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))
	for len(buf) >= metaSize {
		meta := (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[0]))
		if meta.Event_len < uint32(metaSize) || int(meta.Event_len) > len(buf) {
			return
		}
		if meta.Vers != unix.FANOTIFY_METADATA_VERSION {
			return
		}
		if meta.Fd >= 0 && meta.Mask&unix.FAN_OPEN_PERM != 0 {
			event := cfg.fileProfileFanotifyDecisionEvent(meta.Fd, meta.Pid)
			// Defense in depth: even if a protected container slipped past mark-time,
			// never deny a host/own/system event.
			if cfg.protectedEvent(event) {
				_ = writeFanotifyResponse(e.fd, meta.Fd, false)
				_ = unix.Close(int(meta.Fd))
				buf = buf[int(meta.Event_len):]
				continue
			}
			deny, ruleID := fileProfileOpenDecision(event, rules)
			if deny {
				cfg.Logger.Info("file-profile-enforcer: denied open",
					slog.String("path", event.Path),
					slog.String("workload", event.WorkloadID),
					slog.String("rule", ruleID),
					slog.Int("pid", int(event.Pid)))
				if cfg.OnDeny != nil {
					cfg.OnDeny(event, ruleID)
				}
			}
			_ = writeFanotifyResponse(e.fd, meta.Fd, deny)
			_ = unix.Close(int(meta.Fd))
		}
		buf = buf[int(meta.Event_len):]
	}
}

func (cfg fileProfileEnforcerConfig) fileProfileFanotifyDecisionEvent(fd, pid int32) fanotifyDecisionEvent {
	procRoot := fileProfileEnforcerProcRoot(cfg.HostRoot)
	containerID := containerIDFromProcCgroup(procRoot, int(pid))
	ident := workloadIdentity{}
	if cfg.Workloads != nil {
		ident = cfg.Workloads.Resolve(containerID)
	}
	return fanotifyDecisionEvent{
		Fd:          fd,
		Pid:         pid,
		Path:        readlinkOrEmpty(fmt.Sprintf("/proc/self/fd/%d", fd)),
		Comm:        strings.TrimSpace(readFileOrEmpty(filepath.Join(procRoot, fmt.Sprint(pid), "comm"))),
		Exe:         readlinkOrEmpty(filepath.Join(procRoot, fmt.Sprint(pid), "exe")),
		ContainerID: containerID,
		WorkloadID:  ident.WorkloadID,
	}
}

// eventNamespace resolves an event's container to its Kubernetes namespace via the
// shared resolver. Empty for host processes or when the resolver is unwired.
func (cfg fileProfileEnforcerConfig) eventNamespace(event fanotifyDecisionEvent) string {
	if cfg.Workloads == nil || strings.TrimSpace(event.ContainerID) == "" {
		return ""
	}
	return cfg.Workloads.Resolve(event.ContainerID).Namespace
}

// protectedEvent reports whether this event's target is in the non-overridable
// protected set (host / own / system namespace). Used to short-circuit to ALLOW
// before the expensive decision path — a host or system exec must never be gated.
func (cfg fileProfileEnforcerConfig) protectedEvent(event fanotifyDecisionEvent) bool {
	return cfg.Protected.protects(event.ContainerID, cfg.eventNamespace(event))
}

// workloadEnforceArmed is the exec enforcer's learn-first gate: a zero-drift exec is
// only DENIED when the workload's process-baseline mode is "enforce". When the
// baseline source is unwired it returns true (the global switch governs, preserving
// legacy behavior); when wired but the workload has no enforce baseline it returns
// false, so blocking waits for a learned baseline (Discover/Monitor => observe).
func (cfg fileProfileEnforcerConfig) workloadEnforceArmed(workloadID string) bool {
	if cfg.Sync == nil {
		return true
	}
	workloadID = strings.TrimSpace(workloadID)
	if workloadID == "" {
		return false
	}
	row, ok := lookupProcessBaselineRow(cfg.Sync.Rows(), workloadID)
	return ok && row.Mode == "enforce"
}

func writeFanotifyResponse(fd int, eventFD int32, deny bool) error {
	response := uint32(unix.FAN_ALLOW)
	if deny {
		response = unix.FAN_DENY
	}
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, unix.FanotifyResponse{Fd: eventFD, Response: response}); err != nil {
		return err
	}
	_, err := unix.Write(fd, buf.Bytes())
	return err
}

func enforceableFileProfileRules(in []fileProfileRuleWire) []fileProfileEnforceRule {
	out := []fileProfileEnforceRule{}
	for _, rule := range in {
		if rule.Mode != "enforce" || rule.Behavior != "block_access" {
			continue
		}
		matcher, baseMatcher, err := compileFileProfileEnforcerMatcher(rule)
		if err != nil {
			continue
		}
		exceptions := enforceableFileProfileExceptions(rule.Exceptions)
		out = append(out, fileProfileEnforceRule{
			ID:             strings.TrimSpace(rule.ID),
			WorkloadID:     strings.TrimSpace(rule.WorkloadID),
			PodWorkloadIDs: append([]string(nil), rule.PodWorkloadIDs...),
			Filter:         strings.TrimSpace(rule.Filter),
			Path:           strings.TrimSpace(rule.Path),
			Regex:          strings.TrimSpace(rule.Regex),
			Recursive:      rule.Recursive,
			Applications:   append([]string(nil), rule.Applications...),
			Exceptions:     exceptions,
			pathMatches:    matcher,
			baseMatches:    baseMatcher,
		})
	}
	return out
}

func enforceableFileProfileExceptions(in []fileProfileExceptionWire) []fileProfileEnforceException {
	out := []fileProfileEnforceException{}
	for _, exception := range in {
		matcher, _, err := compileFileProfileEnforcerExceptionMatcher(exception)
		if err != nil {
			continue
		}
		out = append(out, fileProfileEnforceException{
			ID:           strings.TrimSpace(exception.ID),
			RuleID:       strings.TrimSpace(exception.RuleID),
			Filter:       strings.TrimSpace(exception.Filter),
			Path:         strings.TrimSpace(exception.Path),
			Regex:        strings.TrimSpace(exception.Regex),
			Recursive:    exception.Recursive,
			Applications: append([]string(nil), exception.Applications...),
			pathMatches:  matcher,
		})
	}
	return out
}

func fileProfileOpenDecision(event fanotifyDecisionEvent, rules []fileProfileEnforceRule) (bool, string) {
	workloadRules := []fileProfileEnforceRule{}
	for _, rule := range rules {
		if !fileProfileEnforcerRuleMatchesWorkload(rule, event.WorkloadID) {
			continue
		}
		workloadRules = append(workloadRules, rule)
		if event.Path != "" && !rule.pathMatches(event.Path) && !rule.pathMatches(path.Clean("/"+path.Base(event.Path))) {
			continue
		}
		if fileProfileEnforcerApplicationAllowed(rule.Applications, event.Comm, event.Exe) {
			continue
		}
		if fileProfileEnforcerExceptionAllowed(rule.Exceptions, event) {
			continue
		}
		return true, rule.ID
	}
	if len(workloadRules) == 0 {
		return false, ""
	}
	// Path-less fallback: fanotify can report a host-overlay path (containerized
	// workloads) whose directory doesn't textually contain the rule's prefix, so
	// the path-aware loop above skipped it. We can't verify the directory, but we
	// MUST still require the basename to match the rule's filename pattern —
	// otherwise an unrelated sibling under the marked directory (e.g. /etc/hosts
	// opened under an /etc/*shadow* mark) would be wrongly denied (over-block).
	// An empty/unresolvable path keeps the original behavior: decide on
	// application/exception alone.
	for _, rule := range workloadRules {
		if event.Path != "" && rule.baseMatches != nil && !rule.baseMatches(path.Base(event.Path)) {
			continue
		}
		if fileProfileEnforcerApplicationAllowed(rule.Applications, event.Comm, event.Exe) {
			continue
		}
		if fileProfileEnforcerExceptionAllowed(rule.Exceptions, event) {
			continue
		}
		return true, rule.ID
	}
	return false, ""
}

func fileProfileEnforcerApplicationAllowed(apps []string, comm, exe string) bool {
	if len(apps) == 0 {
		return false
	}
	candidates := []string{strings.TrimSpace(comm), path.Base(strings.TrimSpace(exe))}
	for _, app := range apps {
		app = strings.TrimSpace(app)
		if app == "" {
			continue
		}
		if slices.Contains(candidates, app) {
			return true
		}
	}
	return false
}

func compileFileProfileEnforcerMatcher(rule fileProfileRuleWire) (func(string) bool, func(string) bool, error) {
	return compileFileProfileEnforcerPathMatcher(rule.Filter, rule.Regex, rule.Recursive)
}

func compileFileProfileEnforcerExceptionMatcher(exception fileProfileExceptionWire) (func(string) bool, func(string) bool, error) {
	return compileFileProfileEnforcerPathMatcher(exception.Filter, exception.Regex, exception.Recursive)
}

// compileFileProfileEnforcerPathMatcher returns two predicates: a full-path
// matcher (directory + filename) and a basename-only matcher (filename pattern,
// ignoring the directory). The basename matcher backs the path-less fallback in
// fileProfileOpenDecision.
func compileFileProfileEnforcerPathMatcher(filterRaw, regexRaw string, recursive bool) (func(string) bool, func(string) bool, error) {
	filter := path.Clean(strings.TrimSpace(filterRaw))
	if !strings.Contains(filter, "*") {
		target := filter
		targetBase := path.Base(target)
		full := func(p string) bool { return path.Clean(p) == target || strings.HasSuffix(path.Clean(p), target) }
		base := func(b string) bool { return b == targetBase }
		return full, base, nil
	}
	scanRoot := literalFileProfileEnforcerScanRoot(filter)
	basePattern := strings.TrimSpace(regexRaw)
	if basePattern == "" {
		basePattern = ".*"
	}
	baseRE, err := regexp.Compile("^" + basePattern + "$")
	if err != nil {
		return nil, nil, err
	}
	baseMatch := func(b string) bool { return b != "" && baseRE.MatchString(b) }
	return func(p string) bool {
		p = path.Clean(p)
		idx := strings.LastIndex(p, "/")
		if idx < 0 {
			return false
		}
		dir := p[:idx]
		if dir == "" {
			dir = "/"
		}
		base := p[idx+1:]
		if base == "" || !baseRE.MatchString(base) {
			return false
		}
		if recursive {
			return dir == scanRoot ||
				strings.HasPrefix(dir, scanRoot+"/") ||
				strings.HasSuffix(dir, scanRoot) ||
				strings.Contains(dir, scanRoot+"/")
		}
		return dir == scanRoot || strings.HasSuffix(dir, scanRoot)
	}, baseMatch, nil
}

func fileProfileEnforcerExceptionAllowed(exceptions []fileProfileEnforceException, event fanotifyDecisionEvent) bool {
	for _, exception := range exceptions {
		if exception.pathMatches == nil {
			continue
		}
		if event.Path == "" || (!exception.pathMatches(event.Path) && !exception.pathMatches(path.Clean("/"+path.Base(event.Path)))) {
			continue
		}
		if len(exception.Applications) > 0 && !fileProfileEnforcerApplicationAllowed(exception.Applications, event.Comm, event.Exe) {
			continue
		}
		return true
	}
	return false
}

func fileProfileEnforcerMarkPaths(root string, rule fileProfileEnforceRule, maxDepth int) []string {
	filter := path.Clean(rule.Filter)
	if !strings.Contains(filter, "*") {
		full := filepath.Join(root, strings.TrimPrefix(filter, "/"))
		if _, err := os.Stat(full); err == nil {
			return []string{full}
		}
		return nil
	}
	scanRoot := literalFileProfileEnforcerScanRoot(filter)
	hostRoot := filepath.Join(root, strings.TrimPrefix(scanRoot, "/"))
	if st, err := os.Stat(hostRoot); err != nil || !st.IsDir() {
		return nil
	}
	out := []string{hostRoot}
	if !rule.Recursive {
		return out
	}
	rootDepth := fileProfileEnforcerDepth(scanRoot)
	_ = filepath.WalkDir(hostRoot, func(full string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() || full == hostRoot {
			return nil
		}
		rel, err := filepath.Rel(root, full)
		if err != nil {
			return filepath.SkipDir
		}
		containerPath := "/" + filepath.ToSlash(rel)
		if fileProfileEnforcerDepth(containerPath)-rootDepth > maxDepth {
			return filepath.SkipDir
		}
		out = append(out, full)
		return nil
	})
	return out
}

func literalFileProfileEnforcerScanRoot(filter string) string {
	idx := strings.Index(filter, "*")
	if idx < 0 {
		return path.Clean(filter)
	}
	dir := path.Dir(filter[:idx])
	if dir == "." || dir == "" {
		return "/"
	}
	return path.Clean(dir)
}

func fileProfileEnforcerContainerMatchesRule(c hostscan.Container, rule fileProfileEnforceRule) bool {
	podID := workloadIDFromPod(c.PodNS, c.PodName)
	if podID == "" {
		return false
	}
	if podID == rule.WorkloadID {
		return true
	}
	return slices.Contains(rule.PodWorkloadIDs, podID)
}

func fileProfileEnforcerRuleMatchesWorkload(rule fileProfileEnforceRule, workloadID string) bool {
	workloadID = strings.TrimSpace(workloadID)
	if workloadID == "" {
		return false
	}
	if workloadID == rule.WorkloadID {
		return true
	}
	return slices.Contains(rule.PodWorkloadIDs, workloadID)
}

func fileProfileEnforcementStatuses(rules []fileProfileEnforceRule, marked map[string]int, markErrs int) map[string]fileProfileEnforcementStatus {
	out := map[string]fileProfileEnforcementStatus{}
	for _, rule := range rules {
		if marked[rule.ID] > 0 {
			out[rule.ID] = fileProfileEnforcementStatus{Protect: true, State: "enforced"}
			continue
		}
		state := "unsupported"
		if markErrs > 0 {
			state = "error"
		}
		out[rule.ID] = fileProfileEnforcementStatus{Protect: false, State: state}
	}
	return out
}

func fileProfileEnforcementErrorStatuses(rules []fileProfileEnforceRule) map[string]fileProfileEnforcementStatus {
	out := map[string]fileProfileEnforcementStatus{}
	for _, rule := range rules {
		out[rule.ID] = fileProfileEnforcementStatus{State: "error"}
	}
	return out
}

func fileProfileEnforcerEnabledFromEnv(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return true
	}
}

// ----- P0-3 pre-exec block (FAN_OPEN_EXEC_PERM) ------------------------------
//
// NeuVector denies out-of-profile execs IN-KERNEL: its FileAccessCtrl marks the
// container mount with FAN_OPEN_EXEC_PERM and returns FAN_DENY for a disallowed
// binary (agent/probe/faccess_linux.go processEvent). Our file enforcer already
// runs the FAN_*_PERM machinery for FILES; this reuses it for EXECS. The decision
// applied here is the P0-4 zero-drift invariant (image provenance + lineage
// anchor), which needs no server-side profile bundle to be useful.
//
// DEFAULT-OFF / opt-in (CONSTELLATION_EXEC_ENFORCER) and MONITOR-FIRST: even when
// enabled, it only observes (returns FAN_ALLOW) unless CONSTELLATION_EXEC_ENFORCER_MODE
// =enforce is ALSO set. Blocking every exec in a container is destructive, so the
// enforce path is doubly gated.
//
// ponytail: FAN_OPEN_EXEC_PERM + FAN_MARK_MOUNT is a kernel feature (Linux 5.0+ for
// EXEC_PERM). On a kernel without it, newFanotifyExecEnforcer / the mount mark fail
// and the loop degrades to a periodic warning — it never silently pretends to block.

func execProfileEnforcerEnabledFromEnv(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false // default OFF — pre-exec block is opt-in
	}
}

// execProfileEnforceModeFromEnv reports whether to actually FAN_DENY (enforce) vs
// observe-only (monitor). Default monitor.
func execProfileEnforceModeFromEnv(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "enforce", "block", "protect", "1", "true", "on":
		return true
	default:
		return false // default MONITOR — observe, do not deny
	}
}

type fanotifyExecEnforcer struct {
	fd int
}

func newFanotifyExecEnforcer() (*fanotifyExecEnforcer, error) {
	// FAN_UNLIMITED_QUEUE + FAN_UNLIMITED_MARKS — see newFanotifyPermissionEnforcer.
	// Critical for the exec enforcer: exec permission events on a busy node are
	// high-volume, so a bounded queue is exactly what wedged the node before.
	fd, err := unix.FanotifyInit(unix.FAN_CLOEXEC|unix.FAN_CLASS_CONTENT|unix.FAN_NONBLOCK|unix.FAN_UNLIMITED_QUEUE|unix.FAN_UNLIMITED_MARKS, unix.O_RDONLY|unix.O_CLOEXEC)
	if err != nil {
		return nil, err
	}
	return &fanotifyExecEnforcer{fd: fd}, nil
}

func (e *fanotifyExecEnforcer) Close() error {
	if e == nil || e.fd < 0 {
		return nil
	}
	err := unix.Close(e.fd)
	e.fd = -1
	return err
}

func execPermissionEnforcerLoop(ctx context.Context, cfg fileProfileEnforcerConfig) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	interval := cfg.Interval
	if interval <= 0 {
		interval = time.Minute
	}
	enforce := execProfileEnforceModeFromEnv(os.Getenv("CONSTELLATION_EXEC_ENFORCER_MODE"))
	cfg.Logger.Info("exec-enforcer: started (P0-3 pre-exec block)",
		slog.Bool("enforce", enforce))

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		watcher, err := newFanotifyExecEnforcer()
		if err != nil {
			cfg.Logger.Warn("exec-enforcer: fanotify unavailable", slog.String("err", err.Error()))
			if !sleepOrDone(ctx, interval) {
				return
			}
			continue
		}

		marked, markErrs := watcher.markContainerMounts(ctx, cfg)
		cfg.Logger.Info("exec-enforcer: marked container mounts",
			slog.Int("marked", marked), slog.Int("errors", markErrs))
		if marked == 0 {
			_ = watcher.Close()
			if !sleepOrDone(ctx, interval) {
				return
			}
			continue
		}

		timer := time.NewTimer(interval)
		watcher.serve(ctx, timer.C, cfg, enforce)
		timer.Stop()
		_ = watcher.Close()
	}
}

// markContainerMounts marks each running container's root mount with
// FAN_OPEN_EXEC_PERM|FAN_MARK_MOUNT so every exec on that mount raises a permission
// event. Returns (markedMounts, errors).
func (e *fanotifyExecEnforcer) markContainerMounts(ctx context.Context, cfg fileProfileEnforcerConfig) (int, int) {
	containers, err := hostscan.CollectContainers(ctx, hostscan.ContainersOptions{
		HostRoot:  cfg.HostRoot,
		NodeName:  cfg.NodeName,
		CrictlBin: cfg.CrictlBin,
	})
	if err != nil {
		cfg.Logger.Warn("exec-enforcer: container inventory failed", slog.String("err", err.Error()))
		return 0, 1
	}
	// The device id of the host root filesystem. Any container whose resolved root
	// sits on THIS device is not a private overlay — it shares the host mount, so a
	// FAN_MARK_MOUNT there would arm every exec on the node (kubelet, k3s, sshd) and
	// wedge it. That host-shared spread is exactly what hard-reset the box, so we
	// skip those containers entirely. hostDevOK=false (can't stat) => be safe and
	// skip host-mount detection's negative (mark nothing we can't prove is private).
	hostRoot := strings.TrimSpace(cfg.HostRoot)
	if hostRoot == "" {
		hostRoot = "/"
	}
	hostDev, hostDevOK := statDev(hostRoot)

	marked, errs, skipped := 0, 0, 0
	seen := map[string]struct{}{}
	for _, c := range containers.Items {
		// Never mark a protected container (own/system namespace or host).
		if cfg.Protected.protects(c.ID, c.PodNS) {
			skipped++
			continue
		}
		root, err := hostscan.ContainerRoot(ctx, hostscan.ContainerRootOptions{
			HostRoot:  cfg.HostRoot,
			CrictlBin: cfg.CrictlBin,
		}, c)
		if err != nil || strings.TrimSpace(root) == "" {
			errs++
			continue
		}
		if _, dup := seen[root]; dup {
			continue
		}
		seen[root] = struct{}{}
		// Host-shared-mount guard: only mark a container root that is its OWN mount,
		// distinct from the host root device. The pure decision (protected + device
		// check) lives in execEnforcerShouldMarkRoot so it is unit-tested.
		dev, devOK := statDev(root)
		if !execEnforcerShouldMarkRoot(cfg.Protected, c.ID, c.PodNS, dev, devOK, hostDev, hostDevOK) {
			skipped++
			cfg.Logger.Debug("exec-enforcer: skipping host-shared/protected/unstattable root",
				slog.String("root", root), slog.String("container", c.ID), slog.String("ns", c.PodNS))
			continue
		}
		if err := unix.FanotifyMark(e.fd, unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT,
			uint64(unix.FAN_OPEN_EXEC_PERM), unix.AT_FDCWD, root); err != nil {
			errs++
			cfg.Logger.Debug("exec-enforcer: mount mark failed",
				slog.String("root", root), slog.String("err", err.Error()))
			continue
		}
		marked++
	}
	// The mark plan is the safety-critical fact: this line lets an operator CONFIRM,
	// in monitor mode, that the host and protected namespaces are excluded on THIS
	// cluster before ever arming enforce.
	cfg.Logger.Info("exec-enforcer: mark plan",
		slog.Int("marked", marked), slog.Int("skipped_protected_or_host", skipped),
		slog.Int("errors", errs), slog.Bool("host_dev_known", hostDevOK))
	return marked, errs
}

// execEnforcerShouldMarkRoot is the pure, testable guard deciding whether the exec
// enforcer may arm a FAN_MARK_MOUNT on a container root. It returns false — never
// mark — when ANY of these hold, so the host and platform can't be caught:
//
//   - the container is in the non-overridable protected set (own/system ns, or host);
//   - the container's root device is unknown (can't prove it's a private mount);
//   - the root shares the host root device (marking it would arm the whole node).
//
// Only a container with its OWN private mount, outside the protected set, is marked.
func execEnforcerShouldMarkRoot(protected *protectedSet, containerID, namespace string, rootDev uint64, rootDevOK bool, hostDev uint64, hostDevOK bool) bool {
	if protected.protects(containerID, namespace) {
		return false
	}
	if !rootDevOK {
		return false // unknown device -> never risk it
	}
	if hostDevOK && rootDev == hostDev {
		return false // shares the host mount -> would freeze the node
	}
	return true
}

// execEnforcerDryRunPreview logs the exec enforcer's mark plan WITHOUT arming any
// fanotify mark — a pre-flight so an operator can confirm, on this real cluster,
// that the host and protected namespaces are excluded before enabling enforce. It
// uses the exact same decision (execEnforcerShouldMarkRoot) the live path uses.
func execEnforcerDryRunPreview(ctx context.Context, cfg fileProfileEnforcerConfig) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	interval := cfg.Interval
	if interval <= 0 {
		interval = time.Minute
	}
	hostRoot := strings.TrimSpace(cfg.HostRoot)
	if hostRoot == "" {
		hostRoot = "/"
	}
	cfg.Logger.Info("exec-enforcer[dry-run]: preview only — NO marks armed")
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		containers, err := hostscan.CollectContainers(ctx, hostscan.ContainersOptions{
			HostRoot:  cfg.HostRoot,
			NodeName:  cfg.NodeName,
			CrictlBin: cfg.CrictlBin,
		})
		if err != nil {
			cfg.Logger.Warn("exec-enforcer[dry-run]: container inventory failed", slog.String("err", err.Error()))
			if !sleepOrDone(ctx, interval) {
				return
			}
			continue
		}
		hostDev, hostDevOK := statDev(hostRoot)
		wouldMark, wouldSkip := 0, 0
		for _, c := range containers.Items {
			reason, root, dev, devOK := execDryRunClassify(ctx, cfg, c, hostDev, hostDevOK)
			if reason == "" {
				wouldMark++
				cfg.Logger.Info("exec-enforcer[dry-run]: WOULD MARK",
					slog.String("ns", c.PodNS), slog.String("pod", c.PodName),
					slog.String("root", root), slog.Uint64("dev", dev))
			} else {
				wouldSkip++
				cfg.Logger.Info("exec-enforcer[dry-run]: skip",
					slog.String("ns", c.PodNS), slog.String("pod", c.PodName),
					slog.String("reason", reason), slog.Bool("dev_known", devOK))
			}
		}
		cfg.Logger.Info("exec-enforcer[dry-run]: PLAN",
			slog.Int("would_mark", wouldMark), slog.Int("would_skip", wouldSkip),
			slog.Bool("host_dev_known", hostDevOK), slog.Uint64("host_dev", hostDev))
		if !sleepOrDone(ctx, interval) {
			return
		}
	}
}

// execDryRunClassify returns why a container would be skipped ("" == would mark),
// plus the resolved root/device, using the live mark decision.
func execDryRunClassify(ctx context.Context, cfg fileProfileEnforcerConfig, c hostscan.Container, hostDev uint64, hostDevOK bool) (reason, root string, dev uint64, devOK bool) {
	if cfg.Protected.protects(c.ID, c.PodNS) {
		return "protected-ns-or-host", "", 0, false
	}
	root, err := hostscan.ContainerRoot(ctx, hostscan.ContainerRootOptions{
		HostRoot:  cfg.HostRoot,
		CrictlBin: cfg.CrictlBin,
	}, c)
	if err != nil || strings.TrimSpace(root) == "" {
		return "no-root", "", 0, false
	}
	dev, devOK = statDev(root)
	if !execEnforcerShouldMarkRoot(cfg.Protected, c.ID, c.PodNS, dev, devOK, hostDev, hostDevOK) {
		if !devOK {
			return "unknown-device", root, dev, devOK
		}
		return "host-shared-mount", root, dev, devOK
	}
	return "", root, dev, devOK
}

// statDev returns the device id of the filesystem backing path. ok=false when the
// path can't be stat'd. Used to tell a container's private overlay mount apart from
// the host root mount (see markContainerMounts).
func statDev(path string) (uint64, bool) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, false
	}
	return uint64(st.Dev), true
}

func (e *fanotifyExecEnforcer) serve(ctx context.Context, refresh <-chan time.Time, cfg fileProfileEnforcerConfig, enforce bool) {
	buf := make([]byte, 64*1024)
	for {
		select {
		case <-ctx.Done():
			return
		case <-refresh:
			return
		default:
		}
		n, err := unix.Read(e.fd, buf)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			cfg.Logger.Warn("exec-enforcer: read failed", slog.String("err", err.Error()))
			return
		}
		e.handleEvents(cfg, buf[:n], enforce)
	}
}

func (e *fanotifyExecEnforcer) handleEvents(cfg fileProfileEnforcerConfig, buf []byte, enforce bool) {
	metaSize := int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))
	for len(buf) >= metaSize {
		meta := (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[0]))
		if meta.Event_len < uint32(metaSize) || int(meta.Event_len) > len(buf) {
			return
		}
		if meta.Vers != unix.FANOTIFY_METADATA_VERSION {
			return
		}
		if meta.Fd >= 0 && meta.Mask&unix.FAN_OPEN_EXEC_PERM != 0 {
			event := cfg.fileProfileFanotifyDecisionEvent(meta.Fd, meta.Pid)
			// Short-circuit to ALLOW for host / own / system targets — never gate a
			// protected exec (defense in depth beyond the mark-time skip).
			if cfg.protectedEvent(event) {
				_ = writeFanotifyResponse(e.fd, meta.Fd, false)
				_ = unix.Close(int(meta.Fd))
				buf = buf[int(meta.Event_len):]
				continue
			}
			drift, reason := execEnforcerZeroDriftDecision(cfg, event)
			// Learn-first: deny only when the global switch is on AND this workload's
			// baseline is in enforce mode. Discover/Monitor (or no baseline yet) =>
			// observe, so flipping protect on doesn't block a not-yet-learned workload.
			deny := drift && enforce && cfg.workloadEnforceArmed(event.WorkloadID)
			if drift {
				cfg.Logger.Info("exec-enforcer: zero-drift exec",
					slog.String("path", event.Path),
					slog.String("workload", event.WorkloadID),
					slog.String("reason", reason),
					slog.Bool("denied", deny),
					slog.Int("pid", int(event.Pid)))
				if cfg.OnExecDeny != nil {
					cfg.OnExecDeny(event, reason, deny)
				}
			}
			_ = writeFanotifyResponse(e.fd, meta.Fd, deny)
			_ = unix.Close(int(meta.Fd))
		}
		buf = buf[int(meta.Event_len):]
	}
}

// execEnforcerZeroDriftDecision computes the P0-4 zero-drift verdict for a pre-exec
// fanotify event, using the host proc view. Returns (drift, reason). Fail-open on
// unknown container / start time.
func execEnforcerZeroDriftDecision(cfg fileProfileEnforcerConfig, event fanotifyDecisionEvent) (bool, string) {
	procRootDir := fileProfileEnforcerProcRoot(cfg.HostRoot)
	cid := containerIDFromProcCgroup(procRootDir, int(event.Pid))
	if cid == "" {
		return false, ""
	}
	if cfg.Workloads == nil {
		return false, ""
	}
	ident := cfg.Workloads.Resolve(cid)
	if ident.StartUnixNano == 0 {
		return false, "" // unknown start -> fail open
	}
	z := zeroDriftContextFromProc(procRootDir, uint32(event.Pid), cid, ident.StartUnixNano)
	if !execIsDrift(z) {
		return false, ""
	}
	if !z.Anchored {
		return true, "unanchored"
	}
	return true, "image-drift"
}

func fileProfileEnforcerProcRoot(hostRoot string) string {
	if strings.TrimSpace(hostRoot) != "" {
		return filepath.Join(hostRoot, "proc")
	}
	return "/proc"
}

func fileProfileEnforcerDepth(p string) int {
	p = strings.Trim(path.Clean(p), "/")
	if p == "" {
		return 0
	}
	return strings.Count(p, "/") + 1
}

// fileCtimeUnixNano returns the inode change time (ctime) of absPath in unix nanos.
// Used by the zero-drift provenance proxy (procFileWrittenAfter). ok=false when the
// path can't be stat'd.
func fileCtimeUnixNano(absPath string) (int64, bool) {
	var st unix.Stat_t
	if err := unix.Stat(absPath, &st); err != nil {
		return 0, false
	}
	return st.Ctim.Nano(), true
}

func readFileOrEmpty(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return string(b)
}

func readlinkOrEmpty(p string) string {
	value, err := os.Readlink(p)
	if err != nil {
		return ""
	}
	return value
}

func sleepOrDone(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
