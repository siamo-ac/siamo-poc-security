// Package store is an encrypted-at-rest secret store: values are
// encrypted with AES-256-GCM before they ever touch disk, and decrypted
// only in memory on read. The disk file contains ciphertext and nothing
// else — no plaintext, no key.
package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// entry is one encrypted record on disk.
type entry struct {
	Nonce      string `json:"nonce"` // base64
	Ciphertext string `json:"ct"`    // base64
}

// Store keeps encrypted secrets in a single JSON file.
type Store struct {
	path string
	key  []byte // 32-byte AES key (in memory only, never written)
	mu   sync.Mutex
}

// New opens (or creates) a store backed by the file at path. The
// encryption key is derived from STORE_KEY (or the demo default) and is
// never persisted — lose the env var and the data is unreadable, which is
// exactly the point of the demo.
func New(path string) *Store {
	raw := os.Getenv("STORE_KEY")
	if raw == "" {
		raw = "demo-store-key-NOT-FOR-PRODUCTION"
	}
	sum := sha256.Sum256([]byte(raw))
	return &Store{path: path, key: sum[:]}
}

func (s *Store) gcm() (cipher.AEAD, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (s *Store) load() (map[string]entry, error) {
	m := map[string]entry{}
	raw, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return m, nil
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func (s *Store) save(m map[string]entry) error {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	// 0600: only the owner can even read the ciphertext file.
	return os.WriteFile(s.path, raw, 0o600)
}

// Put encrypts value and persists it under name.
func (s *Store) Put(name, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, err := s.gcm()
	if err != nil {
		return err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ct := g.Seal(nil, nonce, []byte(value), nil) // no additional data
	m, err := s.load()
	if err != nil {
		return err
	}
	m[name] = entry{
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}
	return s.save(m)
}

// Get reads name, decrypts it, and returns the plaintext. The plaintext
// only ever exists in memory.
func (s *Store) Get(name string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, err := s.gcm()
	if err != nil {
		return "", err
	}
	m, err := s.load()
	if err != nil {
		return "", err
	}
	e, ok := m[name]
	if !ok {
		return "", fmt.Errorf("no such secret")
	}
	nonce, err := base64.StdEncoding.DecodeString(e.Nonce)
	if err != nil {
		return "", err
	}
	ct, err := base64.StdEncoding.DecodeString(e.Ciphertext)
	if err != nil {
		return "", err
	}
	pt, err := g.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed (wrong STORE_KEY?)")
	}
	return string(pt), nil
}
