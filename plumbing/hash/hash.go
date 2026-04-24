// Package hash provides hashing utilities for git objects.
// It supports multiple hash algorithms including SHA1 and SHA256.
package hash

import (
	"crypto"
	_ "crypto/sha1"
	_ "crypto/sha256"
	"fmt"
	"hash"
)

// Hash represents a git object hash.
type Hash [20]byte

// ZeroHash is a Hash with all bytes set to zero.
var ZeroHash Hash

// Algorithm represents the hashing algorithm used.
type Algorithm uint

const (
	// SHA1 is the SHA-1 hashing algorithm (default for git).
	SHA1 Algorithm = iota
	// SHA256 is the SHA-256 hashing algorithm (used in git 2.29+).
	SHA256
)

// algos maps Algorithm to crypto.Hash.
var algos = map[Algorithm]crypto.Hash{
	SHA1:   crypto.SHA1,
	SHA256: crypto.SHA256,
}

// CryptoType returns the crypto.Hash for the given Algorithm.
func (a Algorithm) CryptoType() (crypto.Hash, error) {
	h, ok := algos[a]
	if !ok {
		return 0, fmt.Errorf("unsupported hash algorithm: %d", a)
	}
	return h, nil
}

// New returns a new hash.Hash for the given Algorithm.
func New(algo Algorithm) (hash.Hash, error) {
	cryptoHash, err := algo.CryptoType()
	if err != nil {
		return nil, err
	}
	if !cryptoHash.Available() {
		return nil, fmt.Errorf("hash algorithm not available: %v", cryptoHash)
	}
	return cryptoHash.New(), nil
}

// Sum computes the hash of data using the given Algorithm.
func Sum(algo Algorithm, data []byte) ([]byte, error) {
	h, err := New(algo)
	if err != nil {
		return nil, err
	}
	_, err = h.Write(data)
	if err != nil {
		return nil, fmt.Errorf("writing data to hash: %w", err)
	}
	return h.Sum(nil), nil
}

// FromHex parses a hex-encoded hash string into a Hash.
func FromHex(s string) (Hash, error) {
	if len(s) != 40 {
		return ZeroHash, fmt.Errorf("invalid hash length: expected 40, got %d", len(s))
	}
	var h Hash
	for i := 0; i < 20; i++ {
		b, err := hexToByte(s[i*2], s[i*2+1])
		if err != nil {
			return ZeroHash, fmt.Errorf("invalid hex character at position %d: %w", i*2, err)
		}
		h[i] = b
	}
	return h, nil
}

// String returns the hex-encoded representation of the Hash.
func (h Hash) String() string {
	const hexChars = "0123456789abcdef"
	buf := make([]byte, 40)
	for i, b := range h {
		buf[i*2] = hexChars[b>>4]
		buf[i*2+1] = hexChars[b&0x0f]
	}
	return string(buf)
}

// IsZero reports whether the hash is the zero hash.
func (h Hash) IsZero() bool {
	return h == ZeroHash
}

// hexToByte converts two hex characters to a byte.
func hexToByte(hi, lo byte) (byte, error) {
	h, err := hexVal(hi)
	if err != nil {
		return 0, err
	}
	l, err := hexVal(lo)
	if err != nil {
		return 0, err
	}
	return (h << 4) | l, nil
}

// hexVal converts a single hex character to its numeric value.
func hexVal(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	default:
		return 0, fmt.Errorf("invalid hex character: %q", c)
	}
}
