// Package dnsname provides DNS name normalization helpers shared across
// internal packages.
package dnsname

import "strings"

// Question identifies a DNS query tuple (name, type, class) independently of
// the underlying DNS library's wire representation.
type Question struct {
	Name   string
	Qtype  uint16
	Qclass uint16
}

// CanonicalDomain trims whitespace, lowercases, and strips the trailing
// dot that DNS wire format uses but human-facing config/APIs omit.
func CanonicalDomain(s string) string {
	if IsCanonical(s) {
		return s
	}
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}

// IsCanonical reports whether s is already in canonical form in a single
// pass: pure ASCII, no upper-case letters, no leading/trailing ASCII
// whitespace and no trailing dot. For such strings TrimSpace, TrimSuffix and
// ToLower are all no-ops, so callers can skip them — the overwhelming
// majority of query names off the wire are already canonical. A false result
// only means "take the slow path"; it never changes the outcome.
func IsCanonical(s string) bool {
	n := len(s)
	if n == 0 {
		return true
	}
	if s[n-1] == '.' || isSpaceByte(s[0]) || isSpaceByte(s[n-1]) {
		return false
	}
	for i := range n {
		c := s[i]
		if c >= 0x80 || ('A' <= c && c <= 'Z') {
			return false
		}
	}
	return true
}

// isSpaceByte matches the ASCII characters strings.TrimSpace strips.
func isSpaceByte(c byte) bool {
	return c == ' ' || (c >= '\t' && c <= '\r')
}
