package filter

import (
	"bufio"
	"net"
	"strings"
)

// ParseResult accumulates what a blocklist contributed.
type ParseResult struct {
	Domains      int
	ExactDomains int
	IPs          int
	Exceptions   int
}

// parseContent applies blocklist content to the target rule sets.
// targetBlock* receives blocking rules, targetAllow* receives exceptions
// (both inline "@@" adblock rules and dedicated whitelist entries).
func parseContent(content string, listID string, targetBlock, targetBlockExact, targetIPs, targetAllow, targetAllowExact map[string]struct{}, allowIPs map[string]struct{}, listOf map[string]string) ParseResult {
	var res ParseResult
	sc := bufio.NewScanner(strings.NewReader(content))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	// track records which block domain came from this list, for the UI's
	// "blocked by" reporting. Exceptions and IP rules have their own
	// attribution and are skipped.
	track := func(domain string) {
		if listOf != nil {
			listOf[domain] = listID
		}
	}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		// Hosts-file syntax: "<ip> <domain> [<domain> ...]".
		if ip := net.ParseIP(firstField(line)); ip != nil {
			fields := strings.Fields(line)
			// A bare IP (no hostname) blocks answers resolving to it.
			if len(fields) == 1 {
				targetIPs[ip.String()] = struct{}{}
				res.IPs++
				continue
			}
			// "0.0.0.0" / "127.0.0.1" / "::" / "::1" are the standard
			// blackhole markers; other IPs with a hostname are still treated
			// as a domain block for compatibility.
			for _, f := range fields[1:] {
				domain, exact, _, ok := splitRule(f)
				if !ok {
					continue
				}
				if exact {
					targetBlockExact[domain] = struct{}{}
					res.ExactDomains++
				} else {
					targetBlock[domain] = struct{}{}
					res.Domains++
				}
				track(domain)
			}
			continue
		}
		// If the line is itself an IP, treat it as an IP block rule.
		if ip := net.ParseIP(line); ip != nil {
			targetIPs[ip.String()] = struct{}{}
			res.IPs++
			continue
		}
		// Otherwise treat it as a domain rule (plain or adblock syntax).
		domain, exactOnly, isException, ok := splitRule(line)
		if !ok {
			continue
		}
		if isException {
			if exactOnly {
				targetAllowExact[domain] = struct{}{}
			} else {
				targetAllow[domain] = struct{}{}
			}
			res.Exceptions++
			continue
		}
		if exactOnly {
			targetBlockExact[domain] = struct{}{}
			res.ExactDomains++
		} else {
			targetBlock[domain] = struct{}{}
			res.Domains++
		}
		track(domain)
	}
	return res
}

// firstField returns the first whitespace-separated field of s.
func firstField(s string) string {
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i]
	}
	return s
}
