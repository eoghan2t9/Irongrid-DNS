package api

import (
	"bytes"
	"errors"
	"testing"
)

// TestBackupCryptoRoundTrip verifies encrypt then decrypt with the correct
// passphrase recovers the original bytes exactly.
func TestBackupCryptoRoundTrip(t *testing.T) {
	plain := []byte("this is a fake zip archive body")
	enc, err := encryptBackup(plain, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !isEncryptedBackup(enc) {
		t.Fatal("encrypted output not recognized as an encrypted backup")
	}
	if isEncryptedBackup(plain) {
		t.Fatal("plain zip-like bytes misidentified as an encrypted backup")
	}
	got, err := decryptBackup(enc, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("decrypted = %q, want %q", got, plain)
	}
}

// TestBackupCryptoWrongPassphrase verifies a wrong passphrase fails closed
// with ErrBackupBadPassphrase rather than returning corrupted plaintext.
func TestBackupCryptoWrongPassphrase(t *testing.T) {
	enc, err := encryptBackup([]byte("secret config"), "correct passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decryptBackup(enc, "wrong passphrase"); !errors.Is(err, ErrBackupBadPassphrase) {
		t.Fatalf("err = %v, want ErrBackupBadPassphrase", err)
	}
}

// TestBackupCryptoTamperDetected verifies a flipped ciphertext byte is
// rejected by GCM authentication instead of silently decrypting to garbage.
func TestBackupCryptoTamperDetected(t *testing.T) {
	enc, err := encryptBackup([]byte("secret config"), "a passphrase")
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), enc...)
	tampered[len(tampered)-1] ^= 0xFF
	if _, err := decryptBackup(tampered, "a passphrase"); !errors.Is(err, ErrBackupBadPassphrase) {
		t.Fatalf("err = %v, want ErrBackupBadPassphrase", err)
	}
}

// TestBackupCryptoDistinctSaltNonce verifies two encryptions of the same
// plaintext with the same passphrase never collide (fresh salt/nonce each
// call), so an attacker can't correlate repeated backups by ciphertext.
func TestBackupCryptoDistinctSaltNonce(t *testing.T) {
	plain := []byte("same content every time")
	a, err := encryptBackup(plain, "pw")
	if err != nil {
		t.Fatal(err)
	}
	b, err := encryptBackup(plain, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two encryptions of identical plaintext produced identical ciphertext")
	}
}

// TestDecryptBackupRejectsPlainZip verifies decryptBackup refuses input that
// isn't an encrypted envelope at all (e.g. a plain zip) instead of panicking
// on a malformed header.
func TestDecryptBackupRejectsPlainZip(t *testing.T) {
	if _, err := decryptBackup([]byte("PK\x03\x04not really encrypted"), "pw"); err == nil {
		t.Fatal("plain zip-like bytes accepted as an encrypted backup")
	}
}

// TestDecryptBackupRejectsTruncated verifies a too-short "encrypted" blob
// (magic present, no room for salt+nonce) fails cleanly rather than
// panicking on a slice out-of-range.
func TestDecryptBackupRejectsTruncated(t *testing.T) {
	truncated := append(append([]byte(nil), backupMagic...), []byte("short")...)
	if _, err := decryptBackup(truncated, "pw"); !errors.Is(err, ErrBackupBadPassphrase) {
		t.Fatalf("err = %v, want ErrBackupBadPassphrase", err)
	}
}
