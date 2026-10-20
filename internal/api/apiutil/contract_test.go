package apiutil

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every REST error must flow through this package: no handler may build an
// error body inline or use http.Error. This is the static half of the error
// contract; internal/server's integration test is the runtime half.
func TestNoInlineErrorBodiesOutsideApiutil(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..", "..")
	forbidden := regexp.MustCompile(`map\[string\](?:any|string|interface\{\})\{\s*"error":|http\.Error\(`)
	var offenders []string
	for _, dir := range []string{"internal/handler", "internal/server", "internal/auth", "pkg/plugin"} {
		_ = filepath.WalkDir(filepath.Join(root, dir), func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			body, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil
			}
			src := string(body)
			for _, loc := range forbidden.FindAllStringIndex(src, -1) {
				line := strings.Count(src[:loc[0]], "\n") + 1
				text := strings.Split(src[loc[0]:], "\n")[0]
				if strings.Contains(text, "apiutil:allow") {
					continue
				}
				offenders = append(offenders, path+":"+itoa(line)+": "+strings.TrimSpace(text))
			}
			return nil
		})
	}
	if len(offenders) > 0 {
		t.Fatalf("%d inline error bodies; route them through apiutil.WriteStatus/WriteError:\n%s", len(offenders), strings.Join(offenders, "\n"))
	}
}

func TestRecovererWritesContractShapeWithoutLeaking(t *testing.T) {
	t.Parallel()
	h := Recoverer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("db password=hunter2") }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	b := decode(t, rec)
	if rec.Code != 500 || b.Error.Code != CodeInternal || b.Error.Message != InternalMessage || strings.Contains(rec.Body.String(), "hunter2") {
		t.Fatalf("recoverer: %d %s", rec.Code, rec.Body.String())
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
