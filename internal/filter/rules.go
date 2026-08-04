package filter

import (
	"strings"

	"golang.org/x/net/idna"
)

// normalizeDomain lowercases, strips the trailing dot and converts unicode
// (IDN) domains to their ASCII (punycode) representation so matching is
// consistent with the wire format used by miekg/dns.
func normalizeDomain(d string) string {
	d = strings.TrimSpace(d)
	d = strings.TrimSuffix(d, ".")
	d = strings.ToLower(d)
	if ascii, err := idna.Lookup.ToASCII(d); err == nil {
		d = ascii
	}
	return d
}

// domainMatch reports whether qname matches the rule rooted at rule.
// A rule matches the exact domain AND all of its subdomains unless exactOnly
// is set, in which case it matches the bare domain only.
func domainMatch(qname, rule string, exactOnly bool) bool {
	qname = strings.TrimSuffix(qname, ".")
	rule = strings.TrimSuffix(rule, ".")
	if qname == rule {
		return true
	}
	if exactOnly {
		return false
	}
	return strings.HasSuffix(qname, "."+rule)
}

// splitRule normalizes a raw rule line into (domain, exactOnly).
// It understands:
//
//	example.com          -> subtree block
//	*.example.com        -> subtree block
//	.example.com         -> subtree block
//	=example.com         -> exact-only block (AdGuard "=" syntax)
//	||example.com^       -> Adblock-style subtree block
//	@@||allow.com^       -> Adblock-style exception
func splitRule(raw string) (domain string, exactOnly bool, isException bool, ok bool) {
	line := strings.TrimSpace(raw)
	if line == "" {
		return "", false, false, false
	}
	// Adblock exceptions.
	if strings.HasPrefix(line, "@@") {
		line = strings.TrimPrefix(line, "@@")
		isException = true
	}
	// Adblock domain markers.
	if strings.HasPrefix(line, "||") {
		line = strings.TrimPrefix(line, "||")
		// Strip modifiers after ^ or $.
		if i := strings.IndexAny(line, "^$"); i >= 0 {
			line = line[:i]
		}
	} else if strings.HasPrefix(line, "|") {
		// "|http://..." style rules are not domain rules; ignore.
		return "", false, false, false
	}
	// AdGuard exact-only "=" prefix.
	if strings.HasPrefix(line, "=") {
		line = strings.TrimPrefix(line, "=")
		exactOnly = true
	}
	// Strip trailing ^ used by some lists without the || prefix.
	line = strings.TrimSuffix(line, "^")
	// Strip "*." wildcard prefix.
	if strings.HasPrefix(line, "*.") {
		line = strings.TrimPrefix(line, "*.")
	}
	// Strip leading "." subtree marker.
	line = strings.TrimPrefix(line, ".")

	domain = normalizeDomain(line)
	if domain == "" || strings.ContainsAny(domain, " \t/#*[]!@|$^=\"") {
		return "", false, false, false
	}
	if !strings.Contains(domain, ".") {
		// Single-label names are almost always junk in blocklists; skip.
		return "", false, false, false
	}
	return domain, exactOnly, isException, true
}
