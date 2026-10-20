package backup

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/securefiles"
)

const defaultArtifactDir = "/var/lib/constellation/backups"

// ArtifactName combines a readable hint with the actual unique catalog identity.
// The unmodified organization name remains in the signed archive manifest.
func ArtifactName(orgName string, id uuid.UUID, now time.Time) string {
	var slug strings.Builder
	for _, ch := range orgName {
		if slug.Len() >= 48 {
			break
		}
		switch {
		case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9':
			slug.WriteRune(ch)
		default:
			slug.WriteByte('-')
		}
	}
	hint := strings.Trim(slug.String(), "-")
	if hint == "" {
		hint = "org"
	}
	return "constellation-backup-" + hint + "-" + now.UTC().Format("20060102T150405Z") + "-" + id.String() + ".tar.gz"
}

// ManagedArtifactDir validates a dedicated private server output directory. Only
// an implicit default may fall back for unprivileged development installations.
func ManagedArtifactDir(configured string) (string, error) {
	return managedArtifactDir(configured, securefiles.OpenPrivateDir)
}

func managedArtifactDir(configured string, openPrivate func(string) (*os.Root, error)) (string, error) {
	dir := configured
	if dir == "" {
		dir = defaultArtifactDir
	}
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	root, err := openPrivate(absolute)
	if err != nil && configured == "" {
		absolute = filepath.Join(os.TempDir(), "constellation-backups")
		root, err = openPrivate(absolute)
	}
	if err != nil {
		return "", err
	}
	if err := root.Close(); err != nil {
		return "", err
	}
	return absolute, nil
}

type artifactParent struct {
	root     *os.Root
	path     string
	private  bool
	identity os.FileInfo
}

func openArtifactParent(path string, private bool) (*artifactParent, string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, "", err
	}
	parent := &artifactParent{path: filepath.Dir(absolute), private: private}
	if private {
		parent.root, err = securefiles.OpenPrivateDir(parent.path)
	} else {
		parent.root, err = os.OpenRoot(parent.path)
	}
	if err != nil {
		return nil, "", err
	}
	parent.identity, err = parent.root.Stat(".")
	if err == nil {
		err = parent.current()
	}
	if err != nil {
		return nil, "", errors.Join(err, parent.root.Close())
	}
	return parent, filepath.Base(absolute), nil
}

func (p *artifactParent) current() error {
	var info os.FileInfo
	var err error
	if p.private {
		info, err = os.Lstat(p.path)
	} else {
		info, err = os.Stat(p.path)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || !os.SameFile(info, p.identity) {
		return errors.New("backup artifact parent changed")
	}
	return nil
}

func writeArtifact(ctx context.Context, path string, private bool, produce func(io.Writer) error) (size int64, err error) {
	parent, name, err := openArtifactParent(path, private)
	if err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, parent.root.Close()) }()
	if err = ctx.Err(); err != nil {
		return 0, err
	}
	size, err = securefiles.WriteStream(parent.root, name, 0o600, func(out io.Writer) error {
		if err := produce(out); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return parent.current()
	})
	if err != nil {
		return 0, err
	}
	// Publication already happened: preserve the completed private file if the
	// configured pathname was replaced, but do not claim that pathname is current.
	if err = parent.current(); err != nil {
		return 0, err
	}
	return size, nil
}

func exportArtifact(ctx context.Context, pool *pgxpool.Pool, path string, private bool, opts ExportOptions) (*ExportResult, error) {
	var result *ExportResult
	size, err := writeArtifact(ctx, path, private, func(out io.Writer) error {
		opts.Out = out
		var exportErr error
		result, exportErr = Export(ctx, pool, opts)
		return exportErr
	})
	if err != nil {
		return nil, err
	}
	result.Bytes = size
	return result, nil
}

// ExportManaged writes a job-unique artifact inside a dedicated private server
// directory. Caller records success only after this operation has completed.
func ExportManaged(ctx context.Context, pool *pgxpool.Pool, dir, name string, opts ExportOptions) (*ExportResult, error) {
	if dir == "" {
		return nil, errors.New("managed backup directory is required")
	}
	if !filepath.IsLocal(name) || filepath.Base(name) != name || name == "." {
		return nil, errors.New("backup artifact name must be a single filename")
	}
	return exportArtifact(ctx, pool, filepath.Join(dir, name), true, opts)
}

func (p *artifactParent) openRegular(name string) (*os.File, error) {
	before, err := p.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, errors.New("backup artifact must be a regular file")
	}
	file, err := p.root.Open(name)
	if err != nil {
		return nil, err
	}
	err = p.checkOpened(name, before, file)
	if err == nil {
		err = p.current()
	}
	if err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return file, nil
}

func (p *artifactParent) checkOpened(name string, before os.FileInfo, file *os.File) error {
	opened, err := file.Stat()
	if err != nil {
		return err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return errors.New("backup artifact changed while opening")
	}
	current, err := p.root.Lstat(name)
	if err != nil {
		return err
	}
	if !current.Mode().IsRegular() || !os.SameFile(current, opened) {
		return errors.New("backup artifact changed while opening")
	}
	return nil
}

// OpenArtifact preserves legacy catalog paths, including explicit CLI outputs
// outside the managed directory. It pins that exact parent for this operation;
// no persisted inode identity or cross-operation authenticity is implied.
func OpenArtifact(path string) (file *os.File, err error) {
	parent, name, err := openArtifactParent(path, false)
	if err != nil {
		return nil, err
	}
	file, err = parent.openRegular(name)
	err = errors.Join(err, parent.root.Close())
	if err != nil && file != nil {
		err = errors.Join(err, file.Close())
		file = nil
	}
	return file, err
}

// RemoveArtifact removes only the catalog's exact regular file, using its pinned
// parent. Missing files are already pruned; errors retain the catalog for retry.
func RemoveArtifact(path string) (err error) {
	parent, name, err := openArtifactParent(path, false)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, parent.root.Close()) }()
	file, err := parent.openRegular(name)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = parent.root.Remove(name); err != nil && !os.IsNotExist(err) {
		return err
	}
	return parent.current()
}
