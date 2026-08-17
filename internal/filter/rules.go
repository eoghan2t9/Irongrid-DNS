package filter

import (
	"regexp"
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
	// idna.ToASCII only has work to do on non-ASCII labels; skipping it for
	// the (vast majority) plain-ASCII case avoids a Unicode table lookup on
	// every single query.
	if !isASCII(d) {
		if ascii, err := idna.Lookup.ToASCII(d); err == nil {
			d = ascii
		}
	}
	return d
}

// isASCII reports whether s contains only ASCII bytes.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7f {
			return false
		}
	}
	return true
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
	if after, ok0 := strings.CutPrefix(line, "@@"); ok0 {
		line = after
		isException = true
	}
	// Adblock domain markers.
	if after, ok0 := strings.CutPrefix(line, "||"); ok0 {
		line = after
		// Strip modifiers after ^ or $.
		if i := strings.IndexAny(line, "^$"); i >= 0 {
			line = line[:i]
		}
	} else if strings.HasPrefix(line, "|") {
		// "|http://..." style rules are not domain rules; ignore.
		return "", false, false, false
	}
	// AdGuard exact-only "=" prefix.
	if after, ok0 := strings.CutPrefix(line, "="); ok0 {
		line = after
		exactOnly = true
	}
	// Strip trailing ^ used by some lists without the || prefix.
	line = strings.TrimSuffix(line, "^")
	// Strip "*." wildcard prefix.
	line = strings.TrimPrefix(line, "*.")
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

// RegexRule is a compiled AdGuard-style /pattern/flags blocklist rule. The
// pattern is matched against the normalized query name (lowercased, no
// trailing dot), like every other rule form. List carries the list ID for
// the dashboard's "blocked by" reporting; empty for user blacklist entries.
type RegexRule struct {
	Re   *regexp.Regexp
	List string
}

// parseRegexRule parses an AdGuard-style regex rule: /pattern/flags, where
// pattern is a Go (RE2) regular expression and flags one or more of
// i (case-insensitive), s (dot matches newline) and m (multi-line). The
// pattern may contain / escaped as \/. Returns nil when the line is not a
// regex rule, uses an unsupported flag, or the pattern does not compile —
// a bad rule is skipped rather than failing the whole list.
func parseRegexRule(raw string, listID string) *RegexRule {
	line := strings.TrimSpace(raw)
	// A regex rule must start and end with '/'; "/*" is a comment-style
	// line some lists use, never a pattern.
	if len(line) < 3 || line[0] != '/' || strings.HasPrefix(line, "/*") {
		return nil
	}
	// The pattern runs to the last '/'; everything after is flags. A bare
	// "//" or "///" is not a rule.
	last := strings.LastIndexByte(line, '/')
	if last <= 1 {
		return nil
	}
	pattern := line[1:last]
	if pattern == "" {
		return nil
	}
	var inline strings.Builder
	for _, f := range line[last+1:] {
		switch f {
		case 'i', 's', 'm':
			inline.WriteString(string(f))
		default:
			return nil
		}
	}
	if inline.String() != "" {
		pattern = "(?" + inline.String() + ")" + pattern
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	return &RegexRule{Re: re, List: listID}
}
