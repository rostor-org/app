// Package crypto is the single legitimate build-time seam (spec §12, D20):
// the Standard profile links this default provider; High Security links a
// FIPS 140-3 validated module behind the same interface. Nothing above this
// package may branch on which provider is linked.
//
// The interface surface (sign/verify, seal/open, KDF, random) is what the M0
// crypto spike (spec §18 OQ4) must confirm covers snapshot, token and CA paths.
// Until that spike reports, this surface is provisional and is named as such.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// Provider is the provisional crypto-provider abstraction.
type Provider interface {
	Random(n int) ([]byte, error)
	Hash(data []byte) []byte
	// Seal/Open protect stored secrets (credential material, CA keys) under the
	// provider's master key. aad binds the ciphertext to its owner.
	Seal(plaintext, aad []byte) ([]byte, error)
	Open(sealed, aad []byte) ([]byte, error)
	// Password KDF. The provider owns parameters; callers see opaque bytes.
	PasswordHash(password []byte) ([]byte, error)
	PasswordVerify(stored, password []byte) (bool, error)
	// Ed25519 for snapshots/tokens (D17). Keys are opaque byte slices.
	GenerateSigningKey() (public, private []byte, err error)
	Sign(private, msg []byte) ([]byte, error)
	Verify(public, msg, sig []byte) bool
	Name() string
}

// Default is the Standard-profile provider: Go standard library primitives.
type Default struct {
	masterKey []byte
}

func NewDefault(masterKey []byte) (*Default, error) {
	if len(masterKey) != 32 {
		return nil, errors.New("crypto: master key must be 32 bytes")
	}
	return &Default{masterKey: masterKey}, nil
}

func (d *Default) Name() string { return "default(go-stdlib)" }

func (d *Default) Random(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

func (d *Default) Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func (d *Default) Seal(plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(d.masterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	// Layout: version(1) | nonce | ciphertext+tag
	out := make([]byte, 0, 1+len(nonce)+len(plaintext)+gcm.Overhead())
	out = append(out, 1)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plaintext, aad), nil
}

func (d *Default) Open(sealed, aad []byte) ([]byte, error) {
	if len(sealed) < 1 || sealed[0] != 1 {
		return nil, errors.New("crypto: unknown sealed format")
	}
	block, err := aes.NewCipher(d.masterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(sealed) < 1+ns {
		return nil, errors.New("crypto: sealed data truncated")
	}
	return gcm.Open(nil, sealed[1:1+ns], sealed[1+ns:], aad)
}

// argon2id parameters: OWASP 2024 baseline (m=19MiB, t=2, p=1) with a
// per-hash salt. Stored layout: version(1) | t(4) | m(4) | p(1) | salt(16) | key(32).
const (
	argonTime    = 2
	argonMemory  = 19 * 1024
	argonThreads = 1
	argonKeyLen  = 32
	argonSaltLen = 16
)

func (d *Default) PasswordHash(password []byte) ([]byte, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key := argon2.IDKey(password, salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	out := make([]byte, 0, 1+4+4+1+argonSaltLen+argonKeyLen)
	out = append(out, 1)
	out = binary.BigEndian.AppendUint32(out, argonTime)
	out = binary.BigEndian.AppendUint32(out, argonMemory)
	out = append(out, argonThreads)
	out = append(out, salt...)
	out = append(out, key...)
	return out, nil
}

func (d *Default) PasswordVerify(stored, password []byte) (bool, error) {
	if len(stored) < 1+4+4+1+argonSaltLen || stored[0] != 1 {
		return false, errors.New("crypto: unknown password hash format")
	}
	t := binary.BigEndian.Uint32(stored[1:5])
	m := binary.BigEndian.Uint32(stored[5:9])
	p := stored[9]
	salt := stored[10 : 10+argonSaltLen]
	want := stored[10+argonSaltLen:]
	got := argon2.IDKey(password, salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

func (d *Default) GenerateSigningKey() ([]byte, []byte, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return []byte(pub), []byte(priv), nil
}

func (d *Default) Sign(private, msg []byte) ([]byte, error) {
	if len(private) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("crypto: bad private key length %d", len(private))
	}
	return ed25519.Sign(ed25519.PrivateKey(private), msg), nil
}

func (d *Default) Verify(public, msg, sig []byte) bool {
	if len(public) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(public), msg, sig)
}
