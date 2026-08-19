package hostscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type FileProfileRule struct {
	ID             string   `json:"id"`
	WorkloadID     string   `json:"workload_id"`
	PodWorkloadIDs []string `json:"pod_workload_ids,omitempty"`
	Mode           string   `json:"mode"`
	Filter         string   `json:"filter"`
	Path           string   `json:"path"`
	Regex          string   `json:"regex"`
	Recursive      bool     `json:"recursive"`
	Behavior       string   `json:"behavior"`
}

type FileProfileWatchFile struct {
	Path          string `json:"path"`
	IsDir         bool   `json:"is_dir"`
	ContainerID   string `json:"container_id,omitempty"`
	ContainerName string `json:"container_name,omitempty"`
	PodName       string `json:"pod_name,omitempty"`
	PodNamespace  string `json:"pod_namespace,omitempty"`
	SizeBytes     int64  `json:"size_bytes,omitempty"`

	// Sha256 is the lowercase hex content hash of the file (B3). It is the
	// real-modification signal: size/mtime can change without content changing
	// (and vice-versa via chattr games), so the server compares the hash across
	// reports to confirm a genuine content modification. Populated only when
	// HashMaxBytes > 0 and the file is a regular file within the cap; empty for
	// directories, oversized files, or when hashing is disabled. Modeled on
	// NeuVector share/fsmon which keeps a per-file hash to filter false positives.
	Sha256 string `json:"sha256,omitempty"`
}

type FileProfileWatchRule struct {
	ID             string                 `json:"id"`
	WorkloadID     string                 `json:"workload_id"`
	Protect        bool                   `json:"protect,omitempty"`
	Enforcement    string                 `json:"enforcement_state,omitempty"`
	Files          []FileProfileWatchFile `json:"files"`
	FilesCount     int                    `json:"files_count"`
	SensitiveCount int                    `json:"sensitive_count"`
}

type FileProfileWatchSnapshot struct {
	Node       string                 `json:"node"`
	ObservedAt time.Time              `json:"observed_at"`
	Rules      []FileProfileWatchRule `json:"rules"`
}

type FileProfileWatchOptions struct {
	HostRoot        string
	ProcRoot        string
	NodeName        string
	CrictlBin       string
	Containers      Containers
	Rules           []FileProfileRule
	MaxFilesPerRule int
	MaxWalkDepth    int
	Timeout         time.Duration

	// HashMaxBytes bounds content hashing (B3). When > 0, each watched regular
	// file whose size is <= HashMaxBytes is sha256'd and the digest is set on
	// FileProfileWatchFile.Sha256. 0 disables hashing (size-only, legacy).
	HashMaxBytes int64
}

type ContainerRootOptions struct {
	HostRoot  string
	ProcRoot  string
	CrictlBin string
	Timeout   time.Duration
}

func ContainerRoot(ctx context.Context, opts ContainerRootOptions, c Container) (string, error) {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return containerRootForFileWatch(ctx, FileProfileWatchOptions{
		HostRoot:  opts.HostRoot,
		CrictlBin: opts.CrictlBin,
		Timeout:   timeout,
	}, c, procRootForFileWatch(opts.HostRoot, opts.ProcRoot))
}

func CollectFileProfileWatches(ctx context.Context, opts FileProfileWatchOptions) (FileProfileWatchSnapshot, error) {
	if opts.MaxFilesPerRule <= 0 {
		opts.MaxFilesPerRule = 200
	}
	if opts.MaxWalkDepth <= 0 {
		opts.MaxWalkDepth = 8
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	procRoot := procRootForFileWatch(opts.HostRoot, opts.ProcRoot)
	node := strings.TrimSpace(opts.NodeName)
	if node == "" {
		node = opts.Containers.Node
	}
	if node == "" {
		if h, _ := os.Hostname(); h != "" {
			node = h
		}
	}
	snap := FileProfileWatchSnapshot{Node: node, ObservedAt: time.Now().UTC()}
	if len(opts.Rules) == 0 {
		return snap, nil
	}
	if len(opts.Containers.Items) == 0 {
		return snap, nil
	}

	rootCache := map[string]string{}
	rulesByID := map[string]*FileProfileWatchRule{}
	for _, rule := range opts.Rules {
		rule.ID = strings.TrimSpace(rule.ID)
		if rule.ID == "" || strings.TrimSpace(rule.Filter) == "" {
			continue
		}
		out := rulesByID[rule.ID]
		if out == nil {
			out = &FileProfileWatchRule{ID: rule.ID, WorkloadID: strings.TrimSpace(rule.WorkloadID)}
			rulesByID[rule.ID] = out
		}
		for _, c := range opts.Containers.Items {
			if !fileProfileContainerMatchesRule(c, rule) || !isRunningForFileWatch(c.State) {
				continue
			}
			root, ok := rootCache[c.ID]
			if !ok {
				resolved, err := containerRootForFileWatch(ctx, opts, c, procRoot)
				if err != nil {
					rootCache[c.ID] = ""
					continue
				}
				root = resolved
				rootCache[c.ID] = root
			}
			if root == "" {
				continue
			}
			remaining := opts.MaxFilesPerRule - len(out.Files)
			if remaining <= 0 {
				break
			}
			files := collectRuleFilesAtRoot(root, c, rule, remaining, opts.MaxWalkDepth, opts.HashMaxBytes)
			out.Files = append(out.Files, files...)
		}
		out.Files = dedupeWatchFiles(out.Files)
		if len(out.Files) > opts.MaxFilesPerRule {
			out.Files = out.Files[:opts.MaxFilesPerRule]
		}
		out.FilesCount = len(out.Files)
		out.SensitiveCount = countSensitiveWatchFiles(out.Files)
	}
	for _, id := range sortedRuleIDs(rulesByID) {
		snap.Rules = append(snap.Rules, *rulesByID[id])
	}
	return snap, nil
}

func procRootForFileWatch(hostRoot, procRoot string) string {
	procRoot = strings.TrimSpace(procRoot)
	if procRoot != "" {
		return procRoot
	}
	if strings.TrimSpace(hostRoot) != "" {
		return filepath.Join(hostRoot, "proc")
	}
	return "/proc"
}

func containerRootForFileWatch(ctx context.Context, opts FileProfileWatchOptions, c Container, procRoot string) (string, error) {
	id := strings.TrimSpace(c.ID)
	if id == "" {
		return "", errors.New("container id is required")
	}
	bin := strings.TrimSpace(opts.CrictlBin)
	if bin == "" {
		bin = "crictl"
	}
	socket, _ := resolveCRISocket(opts.HostRoot)
	if socket == "" {
		return "", errors.New("no CRI socket detected")
	}
	inspect, err := inspectContainer(ctx, bin, socket, id, opts.Timeout)
	if err != nil {
		return "", err
	}
	pid := containerPID(inspect.Info)
	if pid <= 0 {
		return "", errors.New("container pid unavailable")
	}
	return filepath.Join(procRoot, strconv.Itoa(pid), "root"), nil
}

func collectRuleFilesAtRoot(root string, c Container, rule FileProfileRule, limit, maxDepth int, hashMaxBytes int64) []FileProfileWatchFile {
	filter := path.Clean(strings.TrimSpace(rule.Filter))
	if filter == "." || filter == "/" || !strings.HasPrefix(filter, "/") || limit <= 0 {
		return nil
	}
	matcher, err := compileFileWatchRuleMatcher(rule)
	if err != nil {
		return nil
	}
	if !strings.Contains(filter, "*") {
		item, ok := watchFileAtContainerPath(root, filter, c)
		if !ok || !matcher(filter) {
			return nil
		}
		item.Sha256 = hashWatchFile(filepath.Join(root, strings.TrimPrefix(path.Clean(filter), "/")), item.IsDir, item.SizeBytes, hashMaxBytes)
		return []FileProfileWatchFile{item}
	}

	scanRoot := literalFileWatchScanRoot(filter)
	hostRoot := filepath.Join(root, strings.TrimPrefix(scanRoot, "/"))
	rootDepth := fileWatchDepth(scanRoot)
	out := []FileProfileWatchFile{}
	_ = filepath.WalkDir(hostRoot, func(full string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(root, full)
		if err != nil {
			return nil
		}
		containerPath := "/" + filepath.ToSlash(rel)
		if containerPath == "/." {
			containerPath = "/"
		}
		if containerPath != scanRoot && fileWatchDepth(containerPath)-rootDepth > maxDepth {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !matcher(containerPath) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		item := fileWatchFromInfo(containerPath, c, info)
		item.Sha256 = hashWatchFile(full, item.IsDir, item.SizeBytes, hashMaxBytes)
		out = append(out, item)
		if len(out) >= limit {
			return filepath.SkipAll
		}
		return nil
	})
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].ContainerID < out[j].ContainerID
	})
	return out
}

func watchFileAtContainerPath(root, containerPath string, c Container) (FileProfileWatchFile, bool) {
	full := filepath.Join(root, strings.TrimPrefix(path.Clean(containerPath), "/"))
	info, err := os.Lstat(full)
	if err != nil {
		return FileProfileWatchFile{}, false
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return FileProfileWatchFile{}, false
	}
	return fileWatchFromInfo(containerPath, c, info), true
}

func fileWatchFromInfo(containerPath string, c Container, info os.FileInfo) FileProfileWatchFile {
	return FileProfileWatchFile{
		Path:          path.Clean(containerPath),
		IsDir:         info.IsDir(),
		ContainerID:   strings.TrimSpace(c.ID),
		ContainerName: strings.TrimSpace(c.Name),
		PodName:       strings.TrimSpace(c.PodName),
		PodNamespace:  strings.TrimSpace(c.PodNS),
		SizeBytes:     info.Size(),
	}
}

// hashWatchFile returns the lowercase-hex sha256 of the file at fullPath, or ""
// when hashing is disabled (maxBytes <= 0), the entry is a directory, the size
// exceeds the cap, or the file can't be read. Bounded read (LimitReader) so a
// sparse/growing file can't make the scan hang. This is the B3 real-modification
// signal: the server compares the returned digest across reports.
func hashWatchFile(fullPath string, isDir bool, size, maxBytes int64) string {
	if maxBytes <= 0 || isDir {
		return ""
	}
	if size > maxBytes {
		return ""
	}
	f, err := os.Open(fullPath)
	if err != nil {
		return ""
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > maxBytes {
		return ""
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, maxBytes)); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func compileFileWatchRuleMatcher(rule FileProfileRule) (func(string) bool, error) {
	if strings.TrimSpace(rule.Regex) == "" {
		re, err := regexp.Compile("^" + strings.TrimSpace(rule.Path) + "$")
		if err != nil {
			return nil, err
		}
		return re.MatchString, nil
	}
	dirRE, err := regexp.Compile("^" + strings.TrimSpace(rule.Path) + "$")
	if err != nil {
		return nil, err
	}
	recursiveRE, err := regexp.Compile("^" + strings.TrimSpace(rule.Path) + "(?:/.*)?$")
	if err != nil {
		return nil, err
	}
	baseRE, err := regexp.Compile("^" + strings.TrimSpace(rule.Regex) + "$")
	if err != nil {
		return nil, err
	}
	return func(p string) bool {
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
		if rule.Recursive {
			return recursiveRE.MatchString(dir)
		}
		return dirRE.MatchString(dir)
	}, nil
}

func literalFileWatchScanRoot(filter string) string {
	idx := strings.Index(filter, "*")
	if idx < 0 {
		return path.Clean(filter)
	}
	prefix := filter[:idx]
	if prefix == "" {
		return "/"
	}
	dir := path.Dir(prefix)
	if dir == "." || dir == "" {
		return "/"
	}
	return path.Clean(dir)
}

func fileProfileContainerMatchesRule(c Container, rule FileProfileRule) bool {
	podID := fileWatchPodWorkloadID(c.PodNS, c.PodName)
	if podID == "" {
		return false
	}
	if podID == strings.TrimSpace(rule.WorkloadID) {
		return true
	}
	for _, id := range rule.PodWorkloadIDs {
		if podID == strings.TrimSpace(id) {
			return true
		}
	}
	return false
}

func fileWatchPodWorkloadID(namespace, pod string) string {
	namespace = strings.TrimSpace(namespace)
	pod = strings.TrimSpace(pod)
	if namespace == "" || pod == "" {
		return ""
	}
	return namespace + "/pod/" + pod
}

func isRunningForFileWatch(state string) bool {
	state = strings.ToUpper(strings.TrimSpace(state))
	return state == "" || strings.Contains(state, "RUNNING")
}

func fileWatchDepth(p string) int {
	p = strings.Trim(path.Clean(p), "/")
	if p == "" {
		return 0
	}
	return strings.Count(p, "/") + 1
}

func dedupeWatchFiles(in []FileProfileWatchFile) []FileProfileWatchFile {
	seen := map[string]bool{}
	out := make([]FileProfileWatchFile, 0, len(in))
	for _, item := range in {
		key := item.ContainerID + "\x00" + item.Path
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, item)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].ContainerID < out[j].ContainerID
	})
	return out
}

func countSensitiveWatchFiles(files []FileProfileWatchFile) int {
	total := 0
	for _, file := range files {
		if sensitiveFileWatchPath(file.Path) {
			total++
		}
	}
	return total
}

func sensitiveFileWatchPath(p string) bool {
	for _, prefix := range []string{
		"/etc/shadow",
		"/etc/passwd",
		"/etc/sudoers",
		"/etc/kubernetes",
		"/var/lib/kubelet/pki",
		"/var/run/secrets",
		"/run/secrets",
		"/root/.ssh",
		"/home",
	} {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			return true
		}
	}
	return false
}

func sortedRuleIDs(rules map[string]*FileProfileWatchRule) []string {
	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
