// api-runtime-probe checks the runtime data needed by static API/CLI binaries.
package main

import (
	"crypto/x509"
	"debug/buildinfo"
	"debug/elf"
	"fmt"
	"os"
	"os/user"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata"
)

func main() {
	if err := check(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("API runtime identity, home, CA roots, timezone aliases and temporary storage verified")
}

func check() error {
	if os.Getuid() != 10001 || os.Getgid() != 10001 {
		return fmt.Errorf("unexpected uid/gid: %d/%d", os.Getuid(), os.Getgid())
	}
	u, err := user.Current()
	if err != nil {
		return err
	}
	if u.Username != "constellation" || u.HomeDir != "/home/constellation" {
		return fmt.Errorf("unexpected user: %+v", u)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	if home != u.HomeDir {
		return fmt.Errorf("HOME mismatch: %q", home)
	}
	stat, err := os.Stat(home)
	if err != nil {
		return err
	}
	if !stat.IsDir() || stat.Sys().(*syscall.Stat_t).Uid != 10001 || stat.Mode().Perm()&0200 == 0 {
		return fmt.Errorf("home directory is not owned/writable by application user")
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return err
	}
	if roots == nil || len(roots.Subjects()) < 10 {
		return fmt.Errorf("system CA roots unavailable")
	}
	for _, name := range []string{"UTC", "America/New_York", "Europe/London", "Asia/Kolkata", "US/Pacific", "Asia/Calcutta"} {
		if _, err := time.LoadLocation(name); err != nil {
			return fmt.Errorf("timezone %q: %w", name, err)
		}
	}
	for _, path := range []string{"/usr/local/bin/constellation-api", "/usr/local/bin/constellationctl"} {
		info, err := buildinfo.ReadFile(path)
		if err != nil {
			return err
		}
		embeddedZones := false
		for _, setting := range info.Settings {
			if setting.Key == "-tags" {
				for _, tag := range strings.Split(setting.Value, ",") {
					if tag == "timetzdata" {
						embeddedZones = true
					}
				}
			}
		}
		if !embeddedZones {
			return fmt.Errorf("%s lacks embedded timezone data", path)
		}
		binary, err := elf.Open(path)
		if err != nil {
			return err
		}
		for _, program := range binary.Progs {
			if program.Type == elf.PT_INTERP {
				binary.Close()
				return fmt.Errorf("%s needs a dynamic linker", path)
			}
		}
		if err := binary.Close(); err != nil {
			return err
		}
	}
	f, err := os.CreateTemp("", "api-runtime-probe-")
	if err != nil {
		return err
	}
	name := f.Name()
	if err := f.Close(); err != nil {
		return err
	}
	return os.Remove(name)
}
