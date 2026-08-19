// Host package inventory collector. Enumerates packages
// installed on the host via the native package-manager DBs - no
// shell-out, no extra binaries in the agent image.
//
// Vulnerability matching is intentionally separate: the agent reports raw
// packages here, and scanner workers match target-scoped package evidence
// against Constellation VulnDB. Keeping enumeration and matching apart means
// the runtime-agent does not ship a vulnerability scanner.
//
// Supported package managers:
//   - dpkg/apt   (Debian, Ubuntu)         reads /var/lib/dpkg/status
//   - rpm        (RHEL, Fedora, openSUSE) reads sqlite/ndb/bdb rpmdb files
//   - apk        (Alpine)                 reads /lib/apk/db/installed
package hostscan

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	rpmdb "github.com/anchore/go-rpmdb/pkg"
	_ "github.com/glebarez/go-sqlite"
)

// Package is one row in a Packages snapshot.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch,omitempty"`
	Source  string `json:"source,omitempty"` // dpkg | rpm | apk
}

// Packages is the wire shape POSTed by the agent.
type Packages struct {
	Node          string    `json:"node"`
	ObservedAt    time.Time `json:"observed_at"`
	Distro        string    `json:"distro,omitempty"`         // OS ID from /etc/os-release
	DistroVersion string    `json:"distro_version,omitempty"` // VERSION_ID from /etc/os-release
	Source        string    `json:"source,omitempty"`         // dpkg | rpm | apk | mixed | unknown
	Count         int       `json:"count"`
	Items         []Package `json:"items"`
}

// PackagesOptions controls collection.
type PackagesOptions struct {
	HostRoot      string
	NodeName      string
	Distro        string // ID from /etc/os-release, used to short-circuit the right reader
	DistroVersion string // VERSION_ID from /etc/os-release, reported for matching
}

// CollectPackages tries each known package-manager DB in turn and
// returns the first one that yields results. Best-effort; returns an
// empty Packages with err set when nothing succeeds.
//
// Path resolution: package DBs live under /var/lib/* and /lib/*, which
// the chart does NOT bind-mount under /host (mounting /var/lib would
// expose far more than we need). Instead we go through /proc/1/root —
// the agent runs with hostPID=true, so /proc/1/root is the host's
// view of /. Same trick we use for /etc/os-release in collectOS.
func CollectPackages(opts PackagesOptions) (Packages, error) {
	p := Packages{
		Node:          opts.NodeName,
		ObservedAt:    time.Now().UTC(),
		Distro:        opts.Distro,
		DistroVersion: opts.DistroVersion,
	}
	if p.Node == "" {
		if h, _ := os.Hostname(); h != "" {
			p.Node = h
		}
	}

	// Prefer an explicit HostRoot first so tests and alternate
	// deployments are deterministic, then fall back to /proc/1/root
	// (the host's view via PID 1) for the normal hostPID deployment.
	candidates := []string{"/proc/1/root", opts.HostRoot}
	if strings.TrimSpace(opts.HostRoot) != "" {
		candidates = []string{opts.HostRoot, "/proc/1/root"}
	}

	// Try dpkg first if distro suggests Debian-family or if no hint.
	debianFamily := opts.Distro == "" ||
		opts.Distro == "debian" || opts.Distro == "ubuntu"
	if debianFamily {
		for _, c := range candidates {
			if items, err := readDpkg(filepath.Join(c, "/var/lib/dpkg/status")); err == nil && len(items) > 0 {
				p.Source = "dpkg"
				p.Items = items
				p.Count = len(items)
				return p, nil
			}
		}
	}

	// apk (Alpine/Wolfi).
	if opts.Distro == "" || apkFamily(opts.Distro) {
		for _, c := range candidates {
			if items, err := readApk(filepath.Join(c, "/lib/apk/db/installed")); err == nil && len(items) > 0 {
				p.Source = "apk"
				p.Items = items
				p.Count = len(items)
				return p, nil
			}
		}
	}

	// rpm (RHEL/Fedora/openSUSE/SLES and compatible distros).
	if opts.Distro == "" || rpmFamily(opts.Distro) || (!debianFamily && !apkFamily(opts.Distro)) {
		for _, c := range candidates {
			if items, err := readRpm(c); err == nil && len(items) > 0 {
				p.Source = "rpm"
				p.Items = items
				p.Count = len(items)
				return p, nil
			}
		}
	}

	for _, c := range candidates {
		if hasRpmDB(c) {
			p.Source = "rpm"
			return p, errors.New("rpm package database found but could not be enumerated")
		}
	}

	return p, errors.New("no supported package manager DB found")
}

func apkFamily(distro string) bool {
	switch strings.ToLower(strings.TrimSpace(distro)) {
	case "alpine", "wolfi", "chainguard":
		return true
	default:
		return false
	}
}

func rpmFamily(distro string) bool {
	switch strings.ToLower(strings.TrimSpace(distro)) {
	case "rhel", "fedora", "centos", "rocky", "almalinux", "ol", "amzn", "sles",
		"suse", "opensuse", "opensuse-leap", "opensuse-tumbleweed", "azurelinux",
		"mariner", "photon":
		return true
	default:
		return false
	}
}

// readDpkg parses /var/lib/dpkg/status and, for distroless images that ship
// no monolithic status file, the per-package fragments under
// /var/lib/dpkg/status.d/. NeuVector reads the same two locations
// (share/scan/scan_utils.go DpkgStatus / DpkgStatusDir).
//
// statusPath is the directory-rooted /var/lib/dpkg/status path; the status.d/
// directory is derived as a sibling so a single rooted dpkg location yields
// both classic and distroless package sets.
func readDpkg(statusPath string) ([]Package, error) {
	var out []Package
	var any bool

	if f, err := os.Open(statusPath); err == nil {
		pkgs, perr := parseDpkgStatus(f)
		_ = f.Close()
		if perr != nil {
			return nil, perr
		}
		out = append(out, pkgs...)
		any = true
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	// Distroless images carry no monolithic status file; instead each
	// installed package drops an RFC822 fragment in status.d/. Parse every
	// fragment with the same paragraph parser and union the results.
	statusDir := filepath.Join(filepath.Dir(statusPath), "status.d")
	if entries, err := os.ReadDir(statusDir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			// status.d/ also holds <pkg>.md5sums files; only the bare
			// fragment (no extension) is a dpkg status paragraph.
			if strings.Contains(e.Name(), ".") {
				continue
			}
			f, oerr := os.Open(filepath.Join(statusDir, e.Name()))
			if oerr != nil {
				continue
			}
			pkgs, perr := parseDpkgStatus(f)
			_ = f.Close()
			if perr != nil {
				return nil, perr
			}
			out = append(out, pkgs...)
			any = true
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	if !any {
		// Neither status nor status.d/ present — surface the original
		// not-exist error so callers fall through to the next manager.
		return nil, os.ErrNotExist
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// parseDpkgStatus parses a dpkg status stream — RFC822-like paragraphs
// separated by blank lines. Each paragraph is one package. We only care about
// Package, Version, Architecture, Status (installed-ok or not). It handles both
// the monolithic /var/lib/dpkg/status and a single status.d/ fragment.
func parseDpkgStatus(r io.Reader) ([]Package, error) {
	var (
		out  []Package
		cur  Package
		stat string
	)
	flush := func() {
		// dpkg status field looks like "install ok installed" — only
		// emit packages that are actually installed (not just config-only).
		if cur.Name != "" && strings.Contains(stat, "installed") &&
			!strings.Contains(stat, "config-files") &&
			!strings.Contains(stat, "not-installed") {
			cur.Source = "dpkg"
			out = append(out, cur)
		}
		cur = Package{}
		stat = ""
	}
	sc := bufio.NewScanner(r)
	// dpkg status can be huge (~tens of MiB on busy hosts); bump the buffer.
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue // continuation of previous field, ignore
		}
		k, v, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		switch k {
		case "Package":
			cur.Name = v
		case "Version":
			cur.Version = v
		case "Architecture":
			cur.Arch = v
		case "Status":
			stat = v
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// readApk parses /lib/apk/db/installed — apk uses single-letter field
// prefixes (P=package, V=version, A=arch, etc.), one field per line,
// blank lines between packages.
func readApk(path string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var (
		out []Package
		cur Package
	)
	flush := func() {
		if cur.Name != "" {
			cur.Source = "apk"
			out = append(out, cur)
		}
		cur = Package{}
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		switch line[0] {
		case 'P':
			cur.Name = line[2:]
		case 'V':
			cur.Version = line[2:]
		case 'A':
			cur.Arch = line[2:]
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

var rpmDBRelativePaths = []string{
	"/usr/lib/sysimage/rpm/rpmdb.sqlite",
	"/usr/lib/sysimage/rpm/Packages.db",
	"/usr/lib/sysimage/rpm/Packages",
	"/usr/sysimage/rpm/rpmdb.sqlite",
	"/usr/sysimage/rpm/Packages.db",
	"/usr/sysimage/rpm/Packages",
	"/var/lib/rpm/rpmdb.sqlite",
	"/var/lib/rpm/Packages.db",
	"/var/lib/rpm/Packages",
}

func hasRpmDB(root string) bool {
	for _, rel := range rpmDBRelativePaths {
		if st, err := os.Stat(filepath.Join(root, rel)); err == nil && !st.IsDir() {
			return true
		}
	}
	return false
}

func readRpm(root string) ([]Package, error) {
	var errs []error
	for _, rel := range rpmDBRelativePaths {
		path := filepath.Join(root, rel)
		st, err := os.Stat(path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Errorf("%s: %w", path, err))
			}
			continue
		}
		if st.IsDir() {
			continue
		}
		items, err := readRpmDBFile(path)
		if err == nil && len(items) > 0 {
			return items, nil
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, err))
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return nil, os.ErrNotExist
}

func readRpmDBFile(path string) ([]Package, error) {
	db, err := rpmdb.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()

	pkgList, err := db.ListPackages()
	if err != nil {
		return nil, err
	}
	out := make([]Package, 0, len(pkgList))
	for _, pkg := range pkgList {
		if pkg == nil || strings.TrimSpace(pkg.Name) == "" {
			continue
		}
		out = append(out, Package{
			Name:    pkg.Name,
			Version: rpmPackageVersion(pkg),
			Arch:    pkg.Arch,
			Source:  "rpm",
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		if out[i].Arch != out[j].Arch {
			return out[i].Arch < out[j].Arch
		}
		return out[i].Version < out[j].Version
	})
	return out, nil
}

func rpmPackageVersion(pkg *rpmdb.PackageInfo) string {
	version := strings.TrimSpace(pkg.Version)
	release := strings.TrimSpace(pkg.Release)
	if release != "" {
		version += "-" + release
	}
	if pkg.Epoch != nil && *pkg.Epoch > 0 {
		version = fmt.Sprintf("%d:%s", *pkg.Epoch, version)
	}
	return version
}
