package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jackc/pgservicefile"
)

// The private service profile avoids argv credentials without reconstructing a
// lossy set of host/user/TLS command flags. Libpq remains the option authority.
func pgDumpEnvironment(ctx context.Context, dsn, directory string) ([]string, error) {
	merged, err := mergedLibpqSettings(ctx, dsn)
	if err != nil {
		return nil, err
	}
	password, hasPassword := merged["password"]
	delete(merged, "password")
	var text strings.Builder
	text.WriteString("[constellation_backup]\n")
	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := merged[k]
		if !libpqKey(k) || strings.ContainsAny(v, "\x00\r\n") || strings.TrimSpace(v) != v {
			return nil, errors.New("database option cannot be represented safely in a private service profile")
		}
		text.WriteString(k + "=" + v + "\n")
	}
	if strings.ContainsRune(password, 0) {
		return nil, errors.New("invalid database credential")
	}
	profile := filepath.Join(directory, "pg_service.conf")
	file, err := os.OpenFile(profile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, errors.New("private database profile unavailable")
	}
	_, writeErr := io.WriteString(file, text.String())
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		removeErr := os.Remove(profile)
		return nil, errors.Join(errors.New("private database profile write failed"), safeProfileCleanup(removeErr))
	}
	env := make([]string, 0, len(os.Environ())+2)
	for _, e := range os.Environ() {
		k, _, _ := strings.Cut(e, "=")
		if k == "DATABASE_URL" || k == "PGSERVICEFILE" || k == "PGSERVICE" || (hasPassword && k == "PGPASSWORD") {
			continue
		}
		env = append(env, e)
	}
	env = append(env, "PGSERVICEFILE="+profile)
	if hasPassword {
		env = append(env, "PGPASSWORD="+password)
	}
	return env, nil
}

func mergedLibpqSettings(ctx context.Context, dsn string) (map[string]string, error) {
	settings, err := parseLibpqDSN(dsn)
	if err != nil {
		return nil, err
	}
	service := os.Getenv("PGSERVICE")
	if v, ok := settings["service"]; ok {
		service = v
	}
	merged := map[string]string{}
	if service != "" {
		base, err := loadLibpqService(ctx, service)
		if err != nil {
			return nil, err
		}
		for k, v := range base {
			merged[k] = v
		}
	}
	for k, v := range settings {
		merged[k] = v
	}
	delete(merged, "service")
	return merged, nil
}

func libpqKey(key string) bool {
	if key == "" {
		return false
	}
	for _, c := range key {
		if (c < 'a' || c > 'z') && c != '_' && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
func parseLibpqDSN(raw string) (map[string]string, error) {
	if strings.ContainsRune(raw, 0) {
		return nil, errors.New("invalid database connection options")
	}
	if strings.HasPrefix(raw, "postgres://") || strings.HasPrefix(raw, "postgresql://") {
		return parseLibpqURI(raw)
	}
	result := map[string]string{}
	input := strings.TrimLeftFunc(raw, libpqSpace)
	for input != "" {
		at := strings.IndexByte(input, '=')
		if at < 0 {
			return nil, errors.New("invalid database keyword options")
		}
		key := strings.TrimSpace(input[:at])
		if !libpqKey(key) {
			return nil, errors.New("invalid database keyword options")
		}
		input = strings.TrimLeftFunc(input[at+1:], libpqSpace)
		value, remaining, err := libpqValue(input)
		if err != nil {
			return nil, err
		}
		result[key] = value
		input = strings.TrimLeftFunc(remaining, libpqSpace)
	}
	return result, nil
}
func libpqValue(input string) (string, string, error) {
	var out strings.Builder
	quoted := strings.HasPrefix(input, "'")
	if quoted {
		input = input[1:]
	}
	for i := 0; i < len(input); i++ {
		c := input[i]
		if c == '\\' {
			i++
			if i >= len(input) {
				return "", "", errors.New("invalid database keyword escape")
			}
			out.WriteByte(input[i])
			continue
		}
		if quoted && c == '\'' {
			return out.String(), input[i+1:], nil
		}
		if !quoted && libpqSpace(rune(c)) {
			return out.String(), input[i:], nil
		}
		out.WriteByte(c)
	}
	if quoted {
		return "", "", errors.New("unterminated database keyword value")
	}
	return out.String(), "", nil
}
func parseLibpqURI(raw string) (map[string]string, error) {
	_, rest, _ := strings.Cut(raw, "://")
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	authority, tail := rest[:end], rest[end:]
	userinfo := ""
	hosts := authority
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		userinfo = authority[:at+1]
		hosts = authority[at+1:]
	}
	// Parsing a synthetic host permits libpq's percent-encoded Unix socket host.
	parsed, err := url.Parse("postgresql://" + userinfo + "placeholder" + tail)
	if err != nil || parsed.Fragment != "" {
		return nil, errors.New("invalid database URI")
	}
	settings := map[string]string{}
	if parsed.User != nil {
		settings["user"] = parsed.User.Username()
		if p, ok := parsed.User.Password(); ok {
			settings["password"] = p
		}
	}
	if parsed.Path != "" {
		settings["dbname"] = strings.TrimPrefix(parsed.Path, "/")
	}
	if err = applyLibpqHosts(settings, hosts); err != nil {
		return nil, err
	}
	if err = applyLibpqURIOptions(settings, parsed.RawQuery); err != nil {
		return nil, err
	}
	return settings, nil
}

func applyLibpqHosts(settings map[string]string, hosts string) error {
	if hosts == "" {
		return nil
	}
	var names, ports []string
	for _, host := range strings.Split(hosts, ",") {
		name, port, err := libpqURIHost(host)
		if err != nil {
			return err
		}
		names = append(names, name)
		ports = append(ports, port)
	}
	settings["host"] = strings.Join(names, ",")
	if strings.Trim(strings.Join(ports, ","), ",") != "" {
		settings["port"] = strings.Join(ports, ",")
	}
	return nil
}
func libpqURIHost(raw string) (string, string, error) {
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		return "", "", errors.New("invalid database URI host")
	}
	name, port := decoded, ""
	switch {
	case strings.HasPrefix(decoded, "[") && strings.HasSuffix(decoded, "]"):
		name = strings.TrimSuffix(strings.TrimPrefix(decoded, "["), "]")
	case strings.Contains(decoded, ":"):
		name, port, err = net.SplitHostPort(decoded)
	}
	if err != nil || strings.Contains(name, ",") {
		return "", "", errors.New("invalid database URI host")
	}
	return name, port, nil
}
func applyLibpqURIOptions(settings map[string]string, query string) error {
	if query == "" {
		return nil
	}
	for _, part := range strings.Split(query, "&") {
		key, val, ok := strings.Cut(part, "=")
		if !ok {
			return errors.New("invalid database URI options")
		}
		key, err := url.PathUnescape(key)
		if err != nil || !libpqKey(key) {
			return errors.New("invalid database URI options")
		}
		val, err = url.PathUnescape(val)
		if err != nil {
			return errors.New("invalid database URI options")
		}
		if key == "ssl" && val == "true" {
			key = "sslmode"
			val = "require"
		}
		settings[key] = val
	}
	return nil
}

var errServiceMissing = errors.New("database service not found")

func loadLibpqService(ctx context.Context, name string) (map[string]string, error) {
	if path := os.Getenv("PGSERVICEFILE"); path != "" {
		service, err := readLibpqService(path, name)
		if err != nil {
			return nil, errors.New("configured database service unavailable")
		}
		return service, nil
	}
	if home, err := os.UserHomeDir(); err == nil {
		service, err := readLibpqService(filepath.Join(home, ".pg_service.conf"), name)
		if err == nil {
			return service, nil
		}
		if !os.IsNotExist(err) && !errors.Is(err, errServiceMissing) {
			return nil, errors.New("user database service unavailable")
		}
	}
	directory := os.Getenv("PGSYSCONFDIR")
	if directory == "" {
		cmd := exec.CommandContext(ctx, "pg_config", "--sysconfdir")
		body, err := cmd.Output()
		if err != nil {
			return nil, errors.New("database service directory unavailable")
		}
		directory = strings.TrimSpace(string(body))
		if !filepath.IsAbs(directory) || strings.ContainsAny(directory, "\r\n\x00") {
			return nil, errors.New("invalid database service directory")
		}
	}
	service, err := readLibpqService(filepath.Join(directory, "pg_service.conf"), name)
	if err != nil {
		return nil, errors.New("database service unavailable")
	}
	return service, nil
}
func readLibpqService(path, name string) (settings map[string]string, resultErr error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := file.Close(); err != nil {
			resultErr = errors.Join(resultErr, errors.New("database service close failed"))
		}
	}()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxLibpqServiceFileBytes {
		return nil, errors.New("invalid database service file")
	}
	return parseBoundedLibpqService(file, name)
}

const maxLibpqServiceFileBytes = 1 << 20

// Stat is only an early rejection. A file can grow while being read, so reject
// any incomplete or over-limit read before a valid prefix can select a target.
func parseBoundedLibpqService(reader io.Reader, name string) (map[string]string, error) {
	body, err := io.ReadAll(io.LimitReader(reader, maxLibpqServiceFileBytes+1))
	if err != nil || len(body) > maxLibpqServiceFileBytes {
		return nil, errors.New("invalid database service file")
	}
	servicefile, err := pgservicefile.ParseServicefile(bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("invalid database service file")
	}
	service, err := servicefile.GetService(name)
	if err != nil {
		return nil, errServiceMissing
	}
	if _, nested := service.Settings["service"]; nested {
		return nil, errors.New("nested database service is unsupported")
	}
	return service.Settings, nil
}

func libpqSpace(c rune) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f'
}

func safeProfileCleanup(err error) error {
	if err == nil || os.IsNotExist(err) {
		return nil
	}
	return errors.New("private database profile cleanup failed")
}
