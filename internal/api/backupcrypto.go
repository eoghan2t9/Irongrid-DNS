package api

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// backupMagic marks an encrypted backup envelope so restore can tell it
// apart from a plain zip archive (which always starts with "PK\x03\x04")
// without the client having to say which kind it uploaded.
var backupMagic = []byte("IGBK1")

const (
	backupSaltLen  = 16
	backupNonceLen = 12
)

// Argon2id parameters for deriving the AES key from a backup passphrase.
// This runs once per backup/restore, not on a request-rate hot path, so the
// "sensible" interactive-use baseline from the golang.org/x/crypto/argon2
// package doc is used as-is: enough work to resist offline cracking of a
// stolen archive without making a routine backup noticeably slow.
const (
	argonTime    = 1
	argonMemory  = 64 * 1024 // KiB (64 MiB)
	argonThreads = 4
	argonKeyLen  = 32 // AES-256
)

// ErrBackupBadPassphrase is returned by decryptBackup for both a wrong
// passphrase and a corrupted/tampered archive — AES-GCM authentication
// can't (and shouldn't) distinguish the two, since doing so would leak a
// padding-oracle-style signal to an attacker probing passphrases.
var ErrBackupBadPassphrase = errors.New("incorrect passphrase or corrupt backup")

func deriveBackupKey(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
}

// isEncryptedBackup reports whether data is an encrypted backup envelope
// rather than a plain zip archive.
func isEncryptedBackup(data []byte) bool {
	return len(data) >= len(backupMagic) && string(data[:len(backupMagic)]) == string(backupMagic)
}

// encryptBackup wraps a plaintext backup zip in an AES-256-GCM envelope
// keyed from passphrase via Argon2id. Layout: magic || salt || nonce ||
// ciphertext+tag. Salt and nonce are freshly random per call, so encrypting
// the same archive twice with the same passphrase never produces the same
// bytes.
func encryptBackup(plain []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, backupSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	gcm, err := newBackupGCM(passphrase, salt)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	out := make([]byte, 0, len(backupMagic)+len(salt)+len(nonce)+len(plain)+gcm.Overhead())
	out = append(out, backupMagic...)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, plain, nil)
	return out, nil
}

// decryptBackup reverses encryptBackup, returning ErrBackupBadPassphrase for
// any failure (wrong passphrase, truncated, or tampered data).
func decryptBackup(data []byte, passphrase string) ([]byte, error) {
	if !isEncryptedBackup(data) {
		return nil, errors.New("not an encrypted backup")
	}
	rest := data[len(backupMagic):]
	if len(rest) < backupSaltLen+backupNonceLen {
		return nil, ErrBackupBadPassphrase
	}
	salt := rest[:backupSaltLen]
	nonce := rest[backupSaltLen : backupSaltLen+backupNonceLen]
	ciphertext := rest[backupSaltLen+backupNonceLen:]

	gcm, err := newBackupGCM(passphrase, salt)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrBackupBadPassphrase
	}
	return plain, nil
}

func newBackupGCM(passphrase string, salt []byte) (cipher.AEAD, error) {
	key := deriveBackupKey(passphrase, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
