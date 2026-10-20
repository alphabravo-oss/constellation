// scanner-tools rebuilds the pinned scanner CLIs (syft, grype, cosign) from reviewed source locks
// with the repository's Go toolchain, so the scanner image never ships upstream binaries that
// embed vulnerable dependencies. Lock layout (deploy/docker/scanner-tools):
//
//	sources.json             {"go": "go1.27.3", "patchRevision": "...", "tools": [{name, module, version, sum, commit, patchRevision?, patches?}]}
//	<tool>/go.mod, go.sum    reviewed dependency locks copied over the upstream module
//
// Flags mirror the Dockerfile and workflow call sites:
//
//	scanner-tools --work /work --output /tools [--locks deploy/docker/scanner-tools] [--tool cosign] [--prepare-only] [--go go]
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type lockFile struct {
	Go            string `json:"go"`
	PatchRevision string `json:"patchRevision"`
	Tools         []tool `json:"tools"`
}

type tool struct {
	Name          string  `json:"name"`
	Module        string  `json:"module"`
	Version       string  `json:"version"`
	Sum           string  `json:"sum"`
	Commit        string  `json:"commit"`
	PatchRevision string  `json:"patchRevision"`
	Patches       []patch `json:"patches"`
}

type patch struct {
	Path         string            `json:"path"`
	SHA256       string            `json:"sha256"`
	Replacements map[string]string `json:"replacements"`
}

func main() {
	locks := flag.String("locks", defaultLocks(), "directory holding sources.json and per-tool go.mod/go.sum")
	work := flag.String("work", "", "scratch directory for the patched sources (required)")
	output := flag.String("output", "", "directory receiving the built binaries (required)")
	goBin := flag.String("go", "go", "go executable")
	only := flag.String("tool", "", "build only this tool (syft|grype|cosign)")
	prepareOnly := flag.Bool("prepare-only", false, "download, lock and patch the sources without building")
	flag.Parse()
	if *work == "" || *output == "" {
		fmt.Fprintln(os.Stderr, "scanner-tools: --work and --output are required")
		os.Exit(2)
	}
	if err := build(*locks, *work, *output, *goBin, *only, *prepareOnly); err != nil {
		fmt.Fprintln(os.Stderr, "scanner-tools:", err)
		os.Exit(1)
	}
}

func defaultLocks() string {
	if exe, err := os.Executable(); err == nil {
		if root := findRepoRoot(filepath.Dir(exe)); root != "" {
			return filepath.Join(root, "deploy", "docker", "scanner-tools")
		}
	}
	if wd, err := os.Getwd(); err == nil {
		if root := findRepoRoot(wd); root != "" {
			return filepath.Join(root, "deploy", "docker", "scanner-tools")
		}
	}
	return "deploy/docker/scanner-tools"
}

func findRepoRoot(dir string) string {
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func build(lockDir, work, output, goBin, only string, prepareOnly bool) error {
	raw, err := os.ReadFile(filepath.Join(lockDir, "sources.json"))
	if err != nil {
		return err
	}
	var lock lockFile
	if err := json.Unmarshal(raw, &lock); err != nil {
		return fmt.Errorf("sources.json: %w", err)
	}
	env := append(os.Environ(), "GOWORK=off", "GOTOOLCHAIN=local", "CGO_ENABLED=0", "GOOS=linux", "GOFLAGS=")
	actual, err := output1(goBin, env, "", "env", "GOVERSION")
	if err != nil {
		return err
	}
	if actual != lock.Go {
		return fmt.Errorf("scanner tools require %s, got %s", lock.Go, actual)
	}
	if only != "" {
		known := false
		for _, t := range lock.Tools {
			known = known || t.Name == only
		}
		if !known {
			return errors.New("unknown tool selection")
		}
	}
	if err := os.MkdirAll(output, 0o750); err != nil {
		return err
	}
	if err := os.MkdirAll(work, 0o750); err != nil {
		return err
	}
	for _, t := range lock.Tools {
		if only != "" && only != t.Name {
			continue
		}
		dir := filepath.Join(work, t.Name)
		if err := prepare(t, lockDir, dir, goBin, env); err != nil {
			return fmt.Errorf("%s: %w", t.Name, err)
		}
		_ = os.Remove(filepath.Join(output, t.Name))
		if prepareOnly {
			continue
		}
		rev := t.PatchRevision
		if rev == "" {
			rev = lock.PatchRevision
		}
		version := t.Version + "-" + rev
		var ldflags string
		if t.Name == "cosign" {
			prefix := "sigs.k8s.io/release-utils/version."
			ldflags = "-s -w -X " + prefix + "gitVersion=" + version + " -X " + prefix + "gitCommit=" + t.Commit + " -X " + prefix + "gitTreeState=dirty"
		} else {
			ldflags = "-s -w -X main.version=" + strings.TrimPrefix(version, "v") + " -X main.gitCommit=" + t.Commit + " -X main.gitDescription=" + version
		}
		cmd := exec.Command(goBin, "build", "-p", "1", "-mod=readonly", "-trimpath",
			"-tags", "containers_image_openpgp,exclude_graphdriver_btrfs", "-ldflags", ldflags,
			"-o", filepath.Join(output, t.Name), "./cmd/"+t.Name)
		cmd.Dir, cmd.Env, cmd.Stdout, cmd.Stderr = dir, env, os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s: go build: %w", t.Name, err)
		}
		fmt.Printf("Built %s %s\n", t.Name, version)
	}
	return nil
}

// prepare downloads the module at the reviewed checksum, copies it into a fresh writable tree,
// overlays the reviewed go.mod/go.sum and applies the reviewed source patches.
func prepare(t tool, lockDir, dir, goBin string, env []string) error {
	out, err := output1(goBin, env, "", "mod", "download", "-json", t.Module+"@"+t.Version)
	if err != nil {
		return err
	}
	var meta struct {
		Path, Version, Sum, Dir string
	}
	if err := json.Unmarshal([]byte(out), &meta); err != nil {
		return fmt.Errorf("go mod download: %w", err)
	}
	if meta.Path != t.Module || meta.Version != t.Version || meta.Sum != t.Sum {
		return errors.New("downloaded source does not match the reviewed module checksum")
	}
	// Fresh per-tool source prevents stale local edits entering the build.
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := copyTree(meta.Dir, dir); err != nil {
		return err
	}
	for _, name := range []string{"go.mod", "go.sum"} {
		b, err := os.ReadFile(filepath.Join(lockDir, t.Name, name))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			return err
		}
	}
	return applyPatches(dir, t.Patches)
}

func applyPatches(dir string, patches []patch) error {
	type prepared struct {
		path string
		data []byte
	}
	var out []prepared
	for _, p := range patches {
		rel := filepath.Clean(p.Path)
		if filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return errors.New("source patch must stay inside the tool directory")
		}
		path := filepath.Join(dir, rel)
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return err
		}
		if resolved != path {
			return errors.New("source patch must not follow symlinks")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != p.SHA256 {
			return errors.New("source patch does not match reviewed input")
		}
		for old, repl := range p.Replacements {
			if old == "" || bytes.Count(data, []byte(old)) != 1 {
				return errors.New("source patch must replace exactly one occurrence")
			}
			data = bytes.Replace(data, []byte(old), []byte(repl), 1)
		}
		out = append(out, prepared{path, data})
	}
	for _, p := range out {
		if err := os.WriteFile(p.path, p.data, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// copyTree copies the read-only module cache tree into a writable directory.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o750)
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil // module zips never carry symlinks; skip defensively
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o600)
	})
}

func output1(bin string, env []string, dir string, args ...string) (string, error) {
	cmd := exec.Command(bin, args...)
	cmd.Env, cmd.Dir = env, dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w: %s", bin, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}
