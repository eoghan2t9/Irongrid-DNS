// Package dnsname provides DNS name normalization helpers shared across
// internal packages.
package dnsname

import "strings"

// CanonicalDomain trims whitespace, lowercases, and strips the trailing
// dot that DNS wire format uses but human-facing config/APIs omit.
func CanonicalDomain(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}
