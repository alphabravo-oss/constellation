package compliance

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// complianceReportRoot matches the scheduler's REPORT_OUT_DIR/default without
// creating or changing permissions: the API may have a read-only report mount.
func complianceReportRoot() (string, error) {
	dir := os.Getenv("REPORT_OUT_DIR")
	if dir == "" {
		dir = "/tmp/compliance-out"
	}
	return filepath.Abs(dir)
}

// openComplianceArtifact pins each directory beneath the configured report root.
// It rejects symlinks and nonregular/multiply linked files before serving bytes.
// Nonblocking, no-follow open also prevents a swapped FIFO or symlink from
// blocking or redirecting the reader between the metadata and open operations.
func openComplianceArtifact(path string) (file *os.File, err error) {
	rootPath, relative, err := complianceArtifactLocation(path)
	if err != nil {
		return nil, err
	}
	before, err := os.Lstat(rootPath)
	if err != nil {
		return nil, err
	}
	if !before.IsDir() {
		return nil, errors.New("report artifact root must be a directory, not a symlink")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, err
	}
	roots := []*os.Root{root}
	defer func() {
		for i := len(roots) - 1; i >= 0; i-- {
			err = errors.Join(err, roots[i].Close())
		}
		if err != nil && file != nil {
			err = errors.Join(err, file.Close())
			file = nil
		}
	}()
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(before, opened) {
		return nil, errors.New("report artifact root changed while opening")
	}
	root, name, err := openComplianceArtifactParents(root, relative, &roots)
	if err != nil {
		return nil, err
	}
	before, err = root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !singleReportFile(before) {
		return nil, errors.New("report artifact must be a single regular file")
	}
	file, err = root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return file, checkComplianceArtifactFile(root, name, before, file)
}

// complianceArtifactLocation retains the scheduler's relative-path behavior;
// filepath.Rel and IsLocal reject paths outside the configured report root.
func complianceArtifactLocation(path string) (string, string, error) {
	rootPath, err := complianceReportRoot()
	if err != nil {
		return "", "", err
	}
	if path == "" || rootPath == filepath.VolumeName(rootPath)+string(filepath.Separator) {
		return "", "", errors.New("a dedicated report artifact root is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", "", err
	}
	relative, err := filepath.Rel(rootPath, absolute)
	if err != nil || !filepath.IsLocal(relative) || relative == "." {
		return "", "", errors.New("report artifact is outside the configured root")
	}
	return rootPath, relative, nil
}

// Every opened child is registered before validation so the caller's existing
// reverse-order cleanup also closes children rejected by the identity checks.
func openComplianceArtifactParents(root *os.Root, relative string, roots *[]*os.Root) (*os.Root, string, error) {
	parts := strings.Split(relative, string(filepath.Separator))
	for _, part := range parts[:len(parts)-1] {
		before, err := root.Lstat(part)
		if err != nil || !before.IsDir() {
			return nil, "", errors.New("report artifact parent must be a directory, not a symlink")
		}
		child, err := root.OpenRoot(part)
		if err != nil {
			return nil, "", err
		}
		*roots = append(*roots, child)
		opened, err := child.Stat(".")
		current, currentErr := root.Lstat(part)
		if err != nil || currentErr != nil || !current.IsDir() || !os.SameFile(before, opened) || !os.SameFile(current, opened) {
			return nil, "", errors.New("report artifact parent changed while opening")
		}
		root = child
	}
	return root, parts[len(parts)-1], nil
}

func checkComplianceArtifactFile(root *os.Root, name string, before os.FileInfo, file *os.File) error {
	opened, err := file.Stat()
	current, currentErr := root.Lstat(name)
	if err != nil || currentErr != nil || !singleReportFile(opened) || !singleReportFile(current) || !os.SameFile(before, opened) || !os.SameFile(current, opened) {
		return errors.New("report artifact changed while opening")
	}
	return nil
}

func singleReportFile(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}
