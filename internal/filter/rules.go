package filter

import (
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"

	"github.com/eoghan2t9/Irongrid-DNS/internal/dnsname"
)

// normalizeDomain lowercases, strips the trailing dot and converts unicode
// (IDN) domains to their ASCII (punycode) representation so matching is
// consistent with the wire format used by miekg/dns.
func normalizeDomain(d string) string {
	// Fast path: wire names are almost always already lower-case ASCII with no
	// trailing dot, in which case every step below is a no-op.
	if dnsname.IsCanonical(d) {
		return d
	}
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
		// Strip modifiers after ^ or $, but reject rules scoped with
		// $domain= — a DNS-level blocker has no notion of the page that
		// initiated the request, so blindly discarding the scope and
		// blocking the pattern everywhere would silently over-block
		// sites/CDNs the rule was never meant to affect (e.g. a shared
		// CDN meant to be blocked only when embedded by one specific
		// tracker page).
		if i := strings.IndexAny(line, "^$"); i >= 0 {
			modifiers := line[i:]
			line = line[:i]
			if hasDomainModifier(modifiers) {
				return "", false, false, false
			}
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

// hasDomainModifier reports whether an Adblock rule's modifier suffix (the
// text from the first ^ or $ onward, e.g. "^$domain=example.com") scopes
// the rule to specific referring page(s) via $domain=. Such rules can't be
// evaluated correctly by a DNS-level blocker, which never sees the page
// that initiated the query, so they must be rejected rather than applied
// as an unconditional block on the bare domain.
func hasDomainModifier(modifiers string) bool {
	for part := range strings.SplitSeq(modifiers, "$") {
		for opt := range strings.SplitSeq(part, ",") {
			if strings.HasPrefix(strings.TrimPrefix(opt, "~"), "domain=") {
				return true
			}
		}
	}
	return false
}

// RegexRule is a compiled AdGuard-style /pattern/flags blocklist rule. The
// pattern is matched against the normalized query name (lowercased, no
// trailing dot), like every other rule form. List carries the list ID for
// the dashboard's "blocked by" reporting; empty for user blacklist entries.
type RegexRule struct {
	Re   *regexp.Regexp
	List string

	// minLen, lits and foldLits are cheap necessary conditions derived from
	// the pattern (see analyzeRegex): any name the regex matches is at least
	// minLen bytes long, contains every string in lits, and contains every
	// string in foldLits ignoring ASCII case. DecideDomain runs every regex on every
	// non-blocked query, and RE2 costs ~65 ns per rule even when it fails at
	// once, so checking these first skips almost all of them. They only ever
	// rule a name OUT, never in, so a decision can't change.
	minLen   int
	lits     []string
	foldLits []string
}

// mayMatch reports whether qname could possibly match the rule. A false
// result guarantees Re.MatchString(qname) is false; true means "run the
// regex to find out".
func (r *RegexRule) mayMatch(qname string) bool {
	if len(qname) < r.minLen {
		return false
	}
	for _, l := range r.lits {
		if !strings.Contains(qname, l) {
			return false
		}
	}
	for _, l := range r.foldLits {
		if !containsFoldASCII(qname, l) {
			return false
		}
	}
	return true
}

// containsFoldASCII reports whether s contains lit (lowercase ASCII),
// ignoring ASCII case, without allocating.
func containsFoldASCII(s, lit string) bool {
	n := len(lit)
	for i := 0; i+n <= len(s); i++ {
		j := 0
		for ; j < n; j++ {
			c := s[i+j]
			if 'A' <= c && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != lit[j] {
				break
			}
		}
		if j == n {
			return true
		}
	}
	return false
}

// maxRequiredLits bounds how many literal checks one rule can add; the
// longest are kept since they are the most selective.
const maxRequiredLits = 4

// analyzeRegex derives, for pattern, a lower bound on the byte length of any
// match, the literal substrings every match must contain, and the
// case-insensitive literals every match must contain (ASCII only). All are
// conservative — when the syntax tree is too complex to reason about they
// degrade to 0 / nil (no filtering), never to a wrong rejection.
func analyzeRegex(pattern string) (minLen int, lits, foldLits []string) {
	sre, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return 0, nil, nil
	}
	sre = sre.Simplify()
	exact, fold := requiredLiterals(sre)
	return minMatchLen(sre), topLiterals(exact), topLiterals(fold)
}

// topLiterals dedupes and keeps the longest maxRequiredLits literals.
func topLiterals(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := slices.Clone(in)
	slices.SortStableFunc(out, func(a, b string) int { return len(b) - len(a) })
	out = slices.Compact(out)
	if len(out) > maxRequiredLits {
		out = out[:maxRequiredLits]
	}
	return out
}

// minMatchLen returns a lower bound on the number of bytes any match of re
// consumes.
func minMatchLen(re *syntax.Regexp) int {
	const capLen = 1 << 20 // keep repeat arithmetic far from overflow
	switch re.Op {
	case syntax.OpLiteral:
		if re.Flags&syntax.FoldCase != 0 {
			// A case-folded rune can match a rune of a different UTF-8
			// width (e.g. 'k' and the Kelvin sign), so only count runes.
			return len(re.Rune)
		}
		n := 0
		for _, r := range re.Rune {
			n += utf8.RuneLen(r)
		}
		return n
	case syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return 1
	case syntax.OpCapture, syntax.OpPlus:
		return minMatchLen(re.Sub[0])
	case syntax.OpRepeat:
		return min(capLen, re.Min*minMatchLen(re.Sub[0]))
	case syntax.OpConcat:
		n := 0
		for _, sub := range re.Sub {
			n += minMatchLen(sub)
		}
		return min(capLen, n)
	case syntax.OpAlternate:
		if len(re.Sub) == 0 {
			return 0
		}
		n := minMatchLen(re.Sub[0])
		for _, sub := range re.Sub[1:] {
			n = min(n, minMatchLen(sub))
		}
		return n
	default: // empty match, anchors, boundaries, star, quest, no-match
		return 0
	}
}

// requiredLiterals returns literal substrings that every match of re must
// contain: exact ones, and case-folded ones (lowercased ASCII). A folded
// literal is only reported when every character's case-fold orbit is pure
// ASCII — e.g. 'k' also matches the Kelvin sign and 's' matches 'ſ', which an
// ASCII comparison would miss, so those are left out.
func requiredLiterals(re *syntax.Regexp) (exact, fold []string) {
	switch re.Op {
	case syntax.OpLiteral:
		if re.Flags&syntax.FoldCase != 0 {
			if l, ok := asciiFoldLiteral(re.Rune); ok {
				return nil, []string{l}
			}
			return nil, nil
		}
		return []string{string(re.Rune)}, nil
	case syntax.OpCapture, syntax.OpPlus:
		return requiredLiterals(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return requiredLiterals(re.Sub[0])
		}
		return nil, nil
	case syntax.OpConcat:
		for _, sub := range re.Sub {
			e, f := requiredLiterals(sub)
			exact = append(exact, e...)
			fold = append(fold, f...)
		}
		return exact, fold
	default: // alternation, star, quest, classes: nothing provably required
		return nil, nil
	}
}

// asciiFoldLiteral lowercases rs when every rune is ASCII and no rune's
// case-fold orbit leaves ASCII.
func asciiFoldLiteral(rs []rune) (string, bool) {
	b := make([]byte, 0, len(rs))
	for _, r := range rs {
		if r > unicode.MaxASCII {
			return "", false
		}
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f > unicode.MaxASCII {
				return "", false
			}
		}
		if 'A' <= r && r <= 'Z' {
			r += 'a' - 'A'
		}
		b = append(b, byte(r))
	}
	return string(b), true
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
	minLen, lits, foldLits := analyzeRegex(pattern)
	return &RegexRule{Re: re, List: listID, minLen: minLen, lits: lits, foldLits: foldLits}
}
