// Package crypto is the column-encryption wrapper the guide prescribes
// (ch.06): age (X25519 + ChaCha20-Poly1305) behind a small API, master keys
// from a file or environment variable only, and the (key_id, algorithm,
// ciphertext) row shape so keys can rotate without downtime.
//
// A key set is one or more age identities; the first is the current key every
// write uses, the rest are kept so rows sealed under previous keys still
// decrypt until `constellationctl admin rotate-keys` has re-sealed them.
package crypto

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"filippo.io/age"
)

// Algorithm is the algorithm identifier stamped on every row this package writes.
const Algorithm = "age-x25519-chacha20poly1305"

// EnvKey / EnvKeyFile are the environment variables the composition roots read.
const (
	EnvKey     = "CONSTELLATION_AGE_KEY"
	EnvKeyFile = "CONSTELLATION_AGE_KEY_FILE"
)

// ErrNoKey is returned by Default when neither EnvKey nor EnvKeyFile is set.
var ErrNoKey = errors.New("crypto: no age key configured (set " + EnvKey + " or " + EnvKeyFile + ")")

// Sealed is one encrypted value with its key metadata, mirroring the column triple.
type Sealed struct {
	KeyID      string
	Algorithm  string
	Ciphertext []byte
	// Nonce is nil for age: the envelope carries its own nonce/file key.
	Nonce []byte
}

// Encryptor holds an ordered key set. It is safe for concurrent use.
type Encryptor struct {
	identities []*age.X25519Identity
	byID       map[string]*age.X25519Identity
	ids        []string
}

// NewEncryptor parses one or more AGE-SECRET-KEY-1... identities (newline or
// comma separated; '#' comments allowed, as in an age identity file). The
// first identity is the current key.
func NewEncryptor(secretKeys string) (*Encryptor, error) {
	var ids []*age.X25519Identity
	sc := bufio.NewScanner(strings.NewReader(strings.ReplaceAll(secretKeys, ",", "\n")))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		id, err := age.ParseX25519Identity(line)
		if err != nil {
			return nil, fmt.Errorf("crypto: parse age identity: %w", err)
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil, errors.New("crypto: no age identity found")
	}
	e := &Encryptor{identities: ids, byID: make(map[string]*age.X25519Identity, len(ids))}
	for _, id := range ids {
		kid := id.Recipient().String()
		if _, dup := e.byID[kid]; dup {
			continue
		}
		e.byID[kid] = id
		e.ids = append(e.ids, kid)
	}
	return e, nil
}

// NewEncryptorFromFile reads the key set from an age identity file.
func NewEncryptorFromFile(path string) (*Encryptor, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("crypto: read key file: %w", err)
	}
	return NewEncryptor(string(b))
}

// NewEncryptorFromEnv reads the key set from the named environment variable.
func NewEncryptorFromEnv(envVar string) (*Encryptor, error) {
	v := strings.TrimSpace(os.Getenv(envVar))
	if v == "" {
		return nil, fmt.Errorf("crypto: %s is empty", envVar)
	}
	return NewEncryptor(v)
}

// GenerateKey mints a fresh X25519 identity for first-time setup and returns
// (secret key, key id/recipient).
func GenerateKey() (secret, keyID string, err error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return "", "", fmt.Errorf("crypto: generate: %w", err)
	}
	return id.String(), id.Recipient().String(), nil
}

// KeyID is the identifier (age recipient) of the current key.
func (e *Encryptor) KeyID() string { return e.ids[0] }

// KeyIDs lists every key id in the set, current first.
func (e *Encryptor) KeyIDs() []string { return append([]string(nil), e.ids...) }

// Encrypt seals plaintext under the current key.
func (e *Encryptor) Encrypt(plaintext []byte) (Sealed, error) {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, e.identities[0].Recipient())
	if err != nil {
		return Sealed{}, fmt.Errorf("crypto: encrypt: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return Sealed{}, fmt.Errorf("crypto: encrypt write: %w", err)
	}
	if err := w.Close(); err != nil {
		return Sealed{}, fmt.Errorf("crypto: encrypt close: %w", err)
	}
	return Sealed{KeyID: e.KeyID(), Algorithm: Algorithm, Ciphertext: buf.Bytes()}, nil
}

// Decrypt opens s with the identity its KeyID names; a row without a key id
// (or with an unknown one) is tried against every identity in the set.
func (e *Encryptor) Decrypt(s Sealed) ([]byte, error) {
	if s.Algorithm != "" && s.Algorithm != Algorithm {
		return nil, fmt.Errorf("crypto: unsupported algorithm %q", s.Algorithm)
	}
	var ids []age.Identity
	if id, ok := e.byID[s.KeyID]; ok {
		ids = []age.Identity{id}
	} else {
		for _, id := range e.identities {
			ids = append(ids, id)
		}
	}
	r, err := age.Decrypt(bytes.NewReader(s.Ciphertext), ids...)
	if err != nil {
		return nil, fmt.Errorf("crypto: decrypt: %w", err)
	}
	pt, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("crypto: decrypt read: %w", err)
	}
	return pt, nil
}

// Seal / Open are the []byte-only forms used where a column carries only the
// ciphertext (the key id is written alongside by the caller via KeyID). They
// satisfy the historical Sealer interface so call sites migrate mechanically.
func (e *Encryptor) Seal(plaintext []byte) ([]byte, error) {
	s, err := e.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}
	return s.Ciphertext, nil
}

// Open decrypts ciphertext produced by Seal, trying every key in the set.
func (e *Encryptor) Open(ciphertext []byte) ([]byte, error) {
	return e.Decrypt(Sealed{Ciphertext: ciphertext})
}

// Current reports whether keyID is the key new writes use.
func (e *Encryptor) Current(keyID string) bool { return keyID == e.KeyID() }

var (
	defaultOnce sync.Once
	defaultEnc  *Encryptor
	defaultErr  error
)

// Default returns the process-wide Encryptor built from EnvKey or EnvKeyFile
// (EnvKey wins). It never consults the database (guide ch.06).
func Default() (*Encryptor, error) {
	defaultOnce.Do(func() {
		switch {
		case strings.TrimSpace(os.Getenv(EnvKey)) != "":
			defaultEnc, defaultErr = NewEncryptorFromEnv(EnvKey)
		case strings.TrimSpace(os.Getenv(EnvKeyFile)) != "":
			defaultEnc, defaultErr = NewEncryptorFromFile(strings.TrimSpace(os.Getenv(EnvKeyFile)))
		default:
			defaultErr = ErrNoKey
		}
	})
	return defaultEnc, defaultErr
}
