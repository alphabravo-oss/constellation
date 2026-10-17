package hostscan

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"io/fs"
	"path"
	"strconv"
	"strings"
)

const (
	cisReleaseBytes    int64 = 4096
	cisProcModuleBytes int64 = 4 << 20
	cisBuiltinBytes    int64 = 16 << 20
	cisSSHBytes        int64 = 1 << 20
	cisModuleEntries         = 100000
	cisModuleDepth           = 64
)

var errCISEvidence = errors.New("incomplete CIS evidence")

// Reads are bounded, and Close participates in the evidence receipt. A complete
// positive record may still establish presence before a subsequent read failure.
func readCISEvidence(fsys fs.FS, name string, limit int64) ([]byte, error) {
	if fsys == nil {
		return nil, errCISEvidence
	}
	file, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	return readCISClosed(file, limit)
}

func readCISClosed(file io.ReadCloser, limit int64) ([]byte, error) {
	data, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if int64(len(data)) > limit {
		return data[:limit], errors.Join(errCISEvidence, readErr, closeErr)
	}
	return data, errors.Join(readErr, closeErr)
}

func moduleName(value string) (string, bool) {
	if value == "" {
		return "", false
	}
	for _, c := range value {
		if c != '_' && c != '-' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return "", false
		}
	}
	return strings.ReplaceAll(value, "-", "_"), true
}

func moduleFileName(value string) (string, bool) {
	for _, suffix := range []string{".ko.gz", ".ko.xz", ".ko.zst", ".ko"} {
		if strings.HasSuffix(value, suffix) {
			return moduleName(strings.TrimSuffix(value, suffix))
		}
	}
	return "", false
}

// On an incomplete read, the unfinished final line cannot prove presence.
func evidenceScanner(data []byte, incomplete bool) *bufio.Scanner {
	if incomplete {
		last := bytes.LastIndexByte(data, '\n')
		if last < 0 {
			data = nil
		} else {
			data = data[:last+1]
		}
	}
	return bufio.NewScanner(bytes.NewReader(data))
}

func loadedModuleEvidence(fsys fs.FS, wanted string) (bool, error) {
	data, readErr := readCISEvidence(fsys, "modules", cisProcModuleBytes)
	scanner := evidenceScanner(data, readErr != nil)
	found, malformed := false, false
	count := 0
	for scanner.Scan() {
		count++
		if count > cisModuleEntries {
			malformed = true
			break
		}
		if scanner.Text() == "" {
			continue
		}
		name, valid := loadedModuleLine(scanner.Text())
		malformed = malformed || !valid
		found = found || valid && name == wanted
	}
	return found, moduleScanError(readErr, scanner.Err(), malformed)
}

func moduleScanError(readErr, scanErr error, malformed bool) error {
	if malformed {
		return errors.Join(readErr, scanErr, errCISEvidence)
	}
	return errors.Join(readErr, scanErr)
}

func loadedModuleLine(line string) (string, bool) {
	fields := strings.Fields(line)
	if len(fields) < 6 || len(fields) > 7 {
		return "", false
	}
	name, valid := moduleName(fields[0])
	if !valid {
		return "", false
	}
	if _, err := strconv.ParseUint(fields[1], 10, 64); err != nil {
		return "", false
	}
	if !moduleRefcount(fields[2]) || !moduleDependencies(fields[3]) || !moduleAddress(fields[5]) {
		return "", false
	}
	if len(fields) == 7 && !moduleAnnotation(fields[6]) {
		return "", false
	}
	switch fields[4] {
	case "Live", "Loading", "Unloading":
		return name, true
	default:
		return "", false
	}
}

func moduleRefcount(value string) bool {
	if value == "-" {
		return true
	}
	count, err := strconv.ParseInt(value, 10, 64)
	return err == nil && count >= -1
}

func moduleDependencies(value string) bool {
	if value == "-" {
		return true
	}
	parts := strings.Split(value, ",")
	if len(parts) < 2 || parts[len(parts)-1] != "" {
		return false
	}
	for _, name := range parts[:len(parts)-1] {
		if name == "[permanent]" {
			continue
		}
		if _, valid := moduleName(name); !valid {
			return false
		}
	}
	return true
}

func moduleAddress(value string) bool {
	if !strings.HasPrefix(value, "0x") || len(value) <= 2 {
		return false
	}
	_, err := strconv.ParseUint(value[2:], 16, 64)
	return err == nil
}

func moduleAnnotation(value string) bool {
	if len(value) < 3 || value[0] != '(' || value[len(value)-1] != ')' {
		return false
	}
	for _, c := range value[1 : len(value)-1] {
		if c != '+' && c != '-' && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}

func kernelReleaseEvidence(fsys fs.FS) (string, error) {
	data, err := readCISEvidence(fsys, "sys/kernel/osrelease", cisReleaseBytes)
	if err != nil {
		return "", err
	}
	release := strings.TrimSpace(string(data))
	if release == "" || release == "." || release == ".." {
		return "", errCISEvidence
	}
	for _, c := range release {
		if c != '.' && c != '_' && c != '+' && c != '-' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return "", errCISEvidence
		}
	}
	return release, nil
}

func builtinModuleEvidence(fsys fs.FS, release, wanted string) (bool, error) {
	data, readErr := readCISEvidence(fsys, path.Join("lib/modules", release, "modules.builtin"), cisBuiltinBytes)
	scanner := evidenceScanner(data, readErr != nil)
	found, malformed := false, false
	count := 0
	for scanner.Scan() {
		count++
		if count > cisModuleEntries {
			malformed = true
			break
		}
		line := scanner.Text()
		if line == "" {
			continue
		}
		name, valid := builtinModuleLine(line)
		malformed = malformed || !valid
		found = found || valid && name == wanted
	}
	return found, moduleScanError(readErr, scanner.Err(), malformed)
}

func builtinModuleLine(line string) (string, bool) {
	name, valid := moduleFileName(path.Base(line))
	return name, valid && fs.ValidPath(line) && !strings.ContainsAny(line, "\x00\t\r ")
}

func checkModuleEvidence(proc, host fs.FS, name string) (string, string) {
	wanted, valid := moduleName(name)
	if !valid {
		return "skip", "module identity unavailable"
	}
	loaded, loadedErr := loadedModuleEvidence(proc, wanted)
	if loaded {
		return "fail", "module observed in the running kernel"
	}
	release, releaseErr := kernelReleaseEvidence(proc)
	if releaseErr != nil {
		return "skip", "running kernel release unavailable"
	}
	builtin, builtinErr := builtinModuleEvidence(host, release, wanted)
	if builtin {
		return "fail", "module built into the running-kernel inventory"
	}
	if errors.Join(loadedErr, builtinErr) != nil {
		return "skip", "kernel module evidence incomplete"
	}
	available, err := scanModuleTree(host, path.Join("lib/modules", release), wanted, cisModuleEntries, cisModuleDepth)
	if err != nil {
		return "skip", "installed module inventory incomplete"
	}
	return finishModuleEvidence(proc, wanted, release, available)
}

func finishModuleEvidence(proc fs.FS, wanted, release string, available bool) (string, string) {
	loaded, loadedErr := loadedModuleEvidence(proc, wanted)
	if loaded {
		return "fail", "module observed in the running kernel"
	}
	current, releaseErr := kernelReleaseEvidence(proc)
	if loadedErr != nil || releaseErr != nil || current != release {
		return "skip", "kernel module evidence changed or incomplete"
	}
	if available {
		return "warn", "module available but not observed loaded; effective disabling unverified"
	}
	return "pass", "module not observed loaded, built-in, or available in the inspected running-kernel inventory"
}

type moduleTreeBudget struct {
	remaining int
	depth     int
}

func scanModuleTree(fsys fs.FS, directory, wanted string, entries, depth int) (bool, error) {
	if fsys == nil {
		return false, errCISEvidence
	}
	budget := moduleTreeBudget{remaining: entries, depth: depth}
	return scanModuleDirectory(fsys, directory, wanted, &budget, 0)
}

func scanModuleDirectory(fsys fs.FS, directory, wanted string, budget *moduleTreeBudget, level int) (found bool, resultErr error) {
	if level > budget.depth {
		return false, errCISEvidence
	}
	file, err := fsys.Open(directory)
	if err != nil {
		return false, err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	dir, ok := file.(fs.ReadDirFile)
	if !ok {
		return false, errCISEvidence
	}
	for {
		entries, readErr := dir.ReadDir(256)
		for _, entry := range entries {
			budget.remaining--
			if budget.remaining < 0 {
				return found, errCISEvidence
			}
			present, err := scanModuleEntry(fsys, directory, wanted, entry, budget, level)
			found = found || present
			if err != nil {
				return found, err
			}
		}
		if cleanModuleDirectoryEOF(readErr) {
			return found, nil
		}
		if readErr != nil || len(entries) == 0 {
			return found, errors.Join(errCISEvidence, readErr)
		}
	}
}

// Only a terminal EOF in a bounded linear chain proves directory completion.
// Joined errors may contain an independent failure. A wrapper's Is method must
// not hide its inner cause; cycles and excessive nesting remain unverified.
func cleanModuleDirectoryEOF(err error) bool {
	for range 32 {
		switch cause := any(err).(type) {
		case interface{ Unwrap() []error }:
			return false
		case interface{ Unwrap() error }:
			err = cause.Unwrap()
		default:
			return errors.Is(err, io.EOF)
		}
	}
	return false
}

func scanModuleEntry(fsys fs.FS, directory, wanted string, entry fs.DirEntry, budget *moduleTreeBudget, level int) (bool, error) {
	if entry.Type()&fs.ModeSymlink != 0 {
		return false, errCISEvidence
	}
	if entry.IsDir() {
		return scanModuleDirectory(fsys, path.Join(directory, entry.Name()), wanted, budget, level+1)
	}
	info, err := entry.Info()
	if err != nil || info == nil || !info.Mode().IsRegular() {
		return false, errors.Join(errCISEvidence, err)
	}
	name, valid := moduleFileName(entry.Name())
	return valid && name == wanted, nil
}

func checkSSHDReader(input io.ReadCloser, option string, acceptable ...string) (string, string) {
	data, err := readCISClosed(input, cisSSHBytes)
	if err != nil {
		return "skip", "SSH configuration read incomplete"
	}
	value, uncertain, err := scanSSHDConfiguration(data, option)
	if err != nil {
		return "skip", "SSH configuration scan incomplete"
	}
	if uncertain {
		return "warn", "SSH effective configuration requires review (conditional, included, or unsupported syntax)"
	}
	if value == "" {
		return "warn", option + " not set in plain sshd_config (default applies)"
	}
	for _, wanted := range acceptable {
		if value == wanted {
			return "pass", option + " has an accepted value in the inspected plain configuration"
		}
	}
	if strings.EqualFold(value, "yes") {
		return "fail", option + "=yes (not accepted)"
	}
	return "fail", option + " does not have an accepted value"
}

func scanSSHDConfiguration(data []byte, option string) (string, bool, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	value := ""
	uncertain := false
	for scanner.Scan() {
		fields, supported := sshEvidenceFields(scanner.Text())
		uncertain = uncertain || !supported
		if len(fields) == 0 {
			continue
		}
		if strings.EqualFold(fields[0], "Include") || strings.EqualFold(fields[0], "Match") {
			uncertain = true
		}
		if strings.EqualFold(fields[0], option) {
			if len(fields) != 2 || !sshTargetValueSupported(option, fields[1]) {
				uncertain = true
			} else if value == "" {
				value = fields[1]
			}
		}
	}
	return value, uncertain, scanner.Err()
}

// sshd keywords are case-insensitive, but their arguments are not. Validate
// every occurrence so an invalid ignored duplicate cannot establish a pass.
func sshTargetValueSupported(option, value string) bool {
	if value == "yes" || value == "no" {
		return true
	}
	if !strings.EqualFold(option, "PermitRootLogin") {
		return false
	}
	switch value {
	case "prohibit-password", "without-password", "forced-commands-only":
		return true
	default:
		return false
	}
}

func sshEvidenceFields(line string) ([]string, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil, true
	}
	fields := strings.Fields(line)
	for i, field := range fields {
		if strings.HasPrefix(field, "#") {
			fields = fields[:i]
			break
		}
	}
	if strings.ContainsAny(strings.Join(fields, " "), "\x00\"'\\=;") {
		return nil, false
	}
	return fields, len(fields) >= 2
}
