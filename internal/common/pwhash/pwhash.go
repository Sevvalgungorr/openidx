// Package pwhash hashes and verifies user login passwords.
//
// New hashes are Argon2id, written in the PHC string format
// ("$argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>"). bcrypt hashes written
// before this package keep verifying unchanged, and a successful bcrypt verify
// reports NeedsRehash so the caller can upgrade the stored value in place while
// it still holds the plaintext.
//
// Why move off bcrypt at all: bcrypt's work factor buys CPU time only, and its
// 4 KiB working set fits in the on-die memory of a GPU or FPGA core, so an
// attacker parallelises it cheaply. Argon2id is memory-hard — each guess must
// hold Memory KiB for the whole computation, which is what makes custom
// hardware expensive rather than merely fast. bcrypt also silently truncates
// the password at 72 bytes, so a long passphrase is weaker than it looks;
// Argon2id has no such limit.
//
// The parameters below are the OWASP Password Storage baseline for Argon2id
// (m=19 MiB, t=2, p=1). Verification cost is per concurrent login, so raising
// Memory raises the server's peak memory under a login burst, not just its CPU
// time — that is the trade being made here, deliberately.
package pwhash

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// Params are the Argon2id cost parameters. They are recorded inside every hash,
// so changing them here never invalidates existing values: an older hash still
// verifies under the parameters it was written with, and Verify reports that it
// should be rehashed.
type Params struct {
	Memory      uint32 // KiB held for the duration of one hash
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// Default is what new hashes are written with. Encoded length is ~96 bytes,
// well inside the VARCHAR(255) password_hash column.
var Default = Params{
	Memory:      19456, // 19 MiB
	Iterations:  2,
	Parallelism: 1,
	SaltLength:  16,
	KeyLength:   32,
}

// ErrUnknownFormat is returned for a stored value that is neither an Argon2id
// PHC string nor a bcrypt hash. It is deliberately distinct from "wrong
// password": a corrupt or truncated hash is an operational problem, and
// reporting it as a failed login would hide it.
var ErrUnknownFormat = errors.New("pwhash: unrecognized password hash format")

// Hash returns an Argon2id PHC string for password using Default.
func Hash(password string) (string, error) { return Default.Hash(password) }

// Hash returns an Argon2id PHC string for password using these parameters.
func (p Params) Hash(password string) (string, error) {
	salt := make([]byte, p.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("pwhash: salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Iterations, p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// Verify reports whether password matches stored.
//
// needsRehash is true when the value verified but was not written with the
// current scheme and parameters — a bcrypt hash, or an Argon2id hash whose cost
// is below Default. It is only ever true alongside ok, so a caller can upgrade
// without re-deciding whether the login succeeded.
//
// A wrong password is (false, false, nil), not an error. err is reserved for a
// stored value that cannot be interpreted at all.
func Verify(stored, password string) (ok bool, needsRehash bool, err error) {
	switch {
	case strings.HasPrefix(stored, "$argon2id$"):
		p, salt, want, perr := decode(stored)
		if perr != nil {
			return false, false, perr
		}
		got := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, uint32(len(want)))
		if subtle.ConstantTimeCompare(got, want) != 1 {
			return false, false, nil
		}
		return true, p.weakerThanDefault(), nil

	case strings.HasPrefix(stored, "$2a$"), strings.HasPrefix(stored, "$2b$"), strings.HasPrefix(stored, "$2y$"):
		if berr := bcrypt.CompareHashAndPassword([]byte(stored), []byte(password)); berr != nil {
			if errors.Is(berr, bcrypt.ErrMismatchedHashAndPassword) {
				return false, false, nil
			}
			return false, false, fmt.Errorf("pwhash: bcrypt: %w", berr)
		}
		// Verified under the old scheme — the caller should upgrade it.
		return true, true, nil

	default:
		return false, false, ErrUnknownFormat
	}
}

// weakerThanDefault reports whether a hash written with p should be upgraded.
// Only cost is compared: a hash stronger than Default is left alone, since
// rewriting it would weaken the stored credential.
func (p Params) weakerThanDefault() bool {
	return p.Memory < Default.Memory ||
		p.Iterations < Default.Iterations ||
		p.KeyLength < Default.KeyLength
}

// decode parses a PHC Argon2id string into its parameters, salt and key.
func decode(stored string) (p Params, salt, key []byte, err error) {
	parts := strings.Split(stored, "$")
	// ["", "argon2id", "v=19", "m=..,t=..,p=..", salt, key]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return p, nil, nil, ErrUnknownFormat
	}
	var version int
	if _, err = fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return p, nil, nil, ErrUnknownFormat
	}
	if version != argon2.Version {
		return p, nil, nil, fmt.Errorf("pwhash: unsupported argon2 version %d", version)
	}
	if _, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism); err != nil {
		return p, nil, nil, ErrUnknownFormat
	}
	if salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil {
		return p, nil, nil, ErrUnknownFormat
	}
	if key, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil {
		return p, nil, nil, ErrUnknownFormat
	}
	if len(salt) == 0 || len(key) == 0 {
		return p, nil, nil, ErrUnknownFormat
	}
	p.SaltLength = uint32(len(salt))
	p.KeyLength = uint32(len(key))
	return p, salt, key, nil
}

// IsArgon2id reports whether stored was written by this package's current
// scheme. Used by tests and by callers that report credential posture.
func IsArgon2id(stored string) bool { return strings.HasPrefix(stored, "$argon2id$") }

// init keeps Parallelism within what the machine can actually run. argon2.IDKey
// spawns Parallelism lanes; asking for more than GOMAXPROCS costs scheduling
// churn without adding memory hardness.
func init() {
	if n := runtime.GOMAXPROCS(0); n > 0 && Default.Parallelism > uint8(min(n, 255)) {
		Default.Parallelism = uint8(min(n, 255))
	}
}
