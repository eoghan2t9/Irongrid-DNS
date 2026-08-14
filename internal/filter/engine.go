// Package filter implements the blocking engine: blocklist parsing, rule
// matching with wildcard/subdomain semantics, and whitelist override.
package filter

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Action is the outcome of a filter decision.
type Action int

const (
	// Allow means the query proceeds to resolution.
	Allow Action = iota
	// Block means the query is answered with the configured block response.
	Block
)

// Decision is the result of evaluating a query name.
type Decision struct {
	Action Action
	// Reason explains why: "whitelist:<domain>", "blocklist:<listID>",
	// "blacklist", "ip-blocklist" or "" when allowed.
	Reason string
	// ListName is the friendly name of the list that matched, for the UI.
	ListName string
}

// Engine holds the compiled rule sets. All fields are guarded by mu.
type Engine struct {
	mu sync.RWMutex

	blockDomains map[string]struct{}
	blockExact   map[string]struct{}
	blockIPs     map[string]struct{}
	allowDomains map[string]struct{}
	allowExact   map[string]struct{}
	allowIPs     map[string]struct{}
	// blockRegex / allowRegex are the compiled AdGuard-style /pattern/ rules
	// DecideDomain scans (order within a source is preserved; matching scans
	// them linearly). Compile rebuilds them from the two sources below, so
	// repeated Compile calls are idempotent: listBlockRegex/listAllowRegex
	// come from LoadList, userBlockRegex/userAllowRegex from SetUserLists.
	blockRegex     []RegexRule
	allowRegex     []RegexRule
	listBlockRegex []RegexRule
	listAllowRegex []RegexRule
	userBlockRegex []RegexRule
	userAllowRegex []RegexRule

	// domainList tracks which list a domain came from, for reporting.
	domainList map[string]string // domain -> list ID
	listNames  map[string]string // list ID -> friendly name

	// Explicit user entries take precedence over list contents.
	userBlacklist []string
	userWhitelist []string

	totalBlockedDomains int
	totalIPRules        int

	// hasIPRules is true whenever any IP rule (block or allow) is present,
	// so the DNS hot path can skip its answer-IP walk entirely for the
	// common domain-only list setups. It is maintained under e.mu wherever
	// the IP sets change (syncIPFlag) and read lock-free.
	hasIPRules atomic.Bool
}

// NewEngine returns an empty engine.
func NewEngine() *Engine {
	return &Engine{
		blockDomains: map[string]struct{}{},
		blockExact:   map[string]struct{}{},
		blockIPs:     map[string]struct{}{},
		allowDomains: map[string]struct{}{},
		allowExact:   map[string]struct{}{},
		allowIPs:     map[string]struct{}{},
		domainList:   map[string]string{},
		listNames:    map[string]string{},
	}
}

// Reset clears every rule so a fresh reload replaces (not accumulates) state.
// Used by the list manager before recompiling from current sources.
func (e *Engine) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.blockDomains = map[string]struct{}{}
	e.blockExact = map[string]struct{}{}
	e.blockIPs = map[string]struct{}{}
	e.allowDomains = map[string]struct{}{}
	e.allowExact = map[string]struct{}{}
	e.allowIPs = map[string]struct{}{}
	e.blockRegex = nil
	e.allowRegex = nil
	e.listBlockRegex = nil
	e.listAllowRegex = nil
	e.userBlockRegex = nil
	e.userAllowRegex = nil
	e.domainList = map[string]string{}
	e.listNames = map[string]string{}
	e.totalBlockedDomains = 0
	e.totalIPRules = 0
	e.hasIPRules.Store(false)
}

// syncIPFlag recomputes the hasIPRules gate from the current IP rule sets.
// Callers hold e.mu.
func (e *Engine) syncIPFlag() {
	e.hasIPRules.Store(len(e.blockIPs) > 0 || len(e.allowIPs) > 0)
}

// SetUserLists replaces the explicit blacklist/whitelist entries.
func (e *Engine) SetUserLists(blacklist, whitelist []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.userBlacklist = normalizeList(blacklist)
	e.userWhitelist = normalizeList(whitelist)
	// /pattern/ entries in the manual lists become regex rules; everything
	// else stays a domain entry. Rebuilt on every call so Compile is
	// idempotent.
	e.userBlockRegex = parseUserRegexes(blacklist)
	e.userAllowRegex = parseUserRegexes(whitelist)
}

// parseUserRegexes extracts compiled /pattern/ rules from raw user-list
// entries (the same check normalizeList uses to keep them verbatim).
func parseUserRegexes(in []string) []RegexRule {
	var out []RegexRule
	for _, s := range in {
		if rr := parseRegexRule(s, ""); rr != nil {
			out = append(out, *rr)
		}
	}
	return out
}

func normalizeList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		// Regex entries are kept verbatim and compiled in Compile; everything
		// else must survive splitRule (exceptions are dropped — the user
		// blacklist/whitelist fields are explicitly one-directional).
		if parseRegexRule(s, "") != nil {
			out = append(out, s)
			continue
		}
		if d, exact, exc, ok := splitRule(s); ok && !exc {
			if exact {
				out = append(out, "="+d)
			} else {
				out = append(out, d)
			}
		}
	}
	return out
}

// LoadList parses content for the given list and merges it into the engine.
// Returns the number of rules added. Call Compile afterwards.
func (e *Engine) LoadList(id, name string, content []byte) (ParseResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if id == "" {
		return ParseResult{}, fmt.Errorf("list id required")
	}
	if e.listNames == nil {
		e.listNames = map[string]string{}
	}
	e.listNames[id] = name
	res := parseContent(string(content), id,
		e.blockDomains, e.blockExact, e.blockIPs,
		e.allowDomains, e.allowExact, e.allowIPs,
		e.domainList, &e.listBlockRegex, &e.listAllowRegex)
	e.totalBlockedDomains += res.Domains + res.ExactDomains + res.Regexes
	e.totalIPRules += res.IPs
	e.syncIPFlag()
	return res, nil
}

// Compile rebuilds derived state (user lists take precedence over list rules).
func (e *Engine) Compile() {
	e.mu.Lock()
	defer e.mu.Unlock()
	// Rebuild the merged regex set from its two sources so a repeated
	// Compile (without an intervening Reset) doesn't duplicate rules — the
	// domain sets below are maps and dedupe naturally, the regex slices are
	// not.
	e.blockRegex = append(append([]RegexRule(nil), e.listBlockRegex...), e.userBlockRegex...)
	e.allowRegex = append(append([]RegexRule(nil), e.listAllowRegex...), e.userAllowRegex...)
	// User whitelist wins: remove matching block entries. Regex entries in
	// the user lists are handled by parseUserRegexes; splitRule rejects the
	// '/' lines so they fall through here untouched.
	for _, d := range e.userWhitelist {
		domain, exact, _, _ := splitRule(d)
		if exact {
			e.allowExact[domain] = struct{}{}
			delete(e.blockExact, domain)
		} else {
			e.allowDomains[domain] = struct{}{}
			delete(e.blockDomains, domain)
			delete(e.blockExact, domain)
		}
	}
	for _, d := range e.userBlacklist {
		domain, exact, _, _ := splitRule(d)
		if exact {
			e.blockExact[domain] = struct{}{}
		} else {
			e.blockDomains[domain] = struct{}{}
		}
	}
	e.syncIPFlag()
}

// HasIPRules reports whether the engine holds any IP rules (block or allow).
// The DNS hot path gates its answer-IP walk on this atomic read, so the
// common domain-only list setup skips the per-answer IP check entirely.
func (e *Engine) HasIPRules() bool { return e.hasIPRules.Load() }

// DecideDomain evaluates a fully qualified query name (with trailing dot).
func (e *Engine) DecideDomain(qname string) Decision {
	qname = normalizeDomain(qname)
	if qname == "" {
		return Decision{Action: Allow}
	}
	e.mu.RLock()
	defer e.mu.RUnlock()

	// lastDot bounds both ancestor walks below: parent suffixes are sliced
	// directly off qname at each '.' (zero allocation — Go string slicing
	// shares the backing array, unlike the strings.Split+Join this replaced,
	// which allocated a new string per ancestor level per query) and the
	// walk stops before the bare top-level label, e.g. "com" alone is never
	// treated as a subtree rule. -1 for a single-label qname makes both
	// loops below a no-op, correctly limiting it to the exact-match checks.
	lastDot := strings.LastIndexByte(qname, '.')

	// Whitelist (exact first, then subtree). Walks ancestor domains with map
	// lookups — same shape as the blocklist walk below — instead of scanning
	// every whitelist entry with domainMatch, which used to cost O(len(allowDomains))
	// per query regardless of whether it hit.
	if _, ok := e.allowExact[qname]; ok {
		return Decision{Action: Allow, Reason: "whitelist:" + qname}
	}
	if _, ok := e.allowDomains[qname]; ok {
		return Decision{Action: Allow, Reason: "whitelist:" + qname}
	}
	for i := 0; i < lastDot; i++ {
		if qname[i] != '.' {
			continue
		}
		parent := qname[i+1:]
		if _, ok := e.allowDomains[parent]; ok {
			return Decision{Action: Allow, Reason: "whitelist:" + parent}
		}
	}
	// Whitelist regexes (AdGuard @@/pattern/ exceptions) override block
	// regexes. RE2 matching is linear-time, so even a long regex list can't
	// be weaponised into a ReDoS.
	for _, rr := range e.allowRegex {
		if rr.Re.MatchString(qname) {
			return Decision{Action: Allow, Reason: "whitelist:regex"}
		}
	}

	// Block exact matches.
	if _, ok := e.blockExact[qname]; ok {
		return Decision{Action: Block, Reason: "blocklist:exact", ListName: e.listNames[e.domainList[qname]]}
	}
	if _, ok := e.blockDomains[qname]; ok {
		return Decision{Action: Block, Reason: "blocklist:" + qname, ListName: e.listNames[e.domainList[qname]]}
	}
	// Block subtree matches. Walk ancestors for better reasons.
	for i := 0; i < lastDot; i++ {
		if qname[i] != '.' {
			continue
		}
		parent := qname[i+1:]
		if _, ok := e.blockDomains[parent]; ok {
			return Decision{Action: Block, Reason: "blocklist:" + parent, ListName: e.listNames[e.domainList[parent]]}
		}
	}
	// Block regexes: matched against the full query name, so a pattern can
	// target any label (^ads\. matches only the first label, \.ads\. any
	// label).
	for _, rr := range e.blockRegex {
		if rr.Re.MatchString(qname) {
			return Decision{Action: Block, Reason: "blocklist:regex", ListName: e.listNames[rr.List]}
		}
	}
	return Decision{Action: Allow}
}

// CheckIPs reports whether any of the given addresses is blocked by an IP
// rule (and not whitelisted).
func (e *Engine) CheckIPs(ips []net.IP) (bool, string) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, ip := range ips {
		s := ip.String()
		if _, ok := e.allowIPs[s]; ok {
			continue
		}
		if _, ok := e.blockIPs[s]; ok {
			return true, "ip-blocklist:" + s
		}
	}
	return false, ""
}

// AddIPBlock adds a manual IP rule (used by the API).
func (e *Engine) AddIPBlock(ip string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if parsed := net.ParseIP(ip); parsed != nil {
		e.blockIPs[parsed.String()] = struct{}{}
		e.syncIPFlag()
	}
}

// RemoveIPBlock removes a manual IP rule.
func (e *Engine) RemoveIPBlock(ip string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if parsed := net.ParseIP(ip); parsed != nil {
		delete(e.blockIPs, parsed.String())
		e.syncIPFlag()
	}
}

// Stats returns counters for the dashboard.
func (e *Engine) Stats() map[string]int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return map[string]int{
		"blocked_domains": e.totalBlockedDomains,
		"blocked_exact":   len(e.blockExact),
		"ip_rules":        e.totalIPRules,
		"regex_rules":     len(e.blockRegex),
		"whitelist":       len(e.userWhitelist),
		"blacklist":       len(e.userBlacklist),
		"lists":           len(e.listNames),
	}
}

// Lists returns the registered list names.
func (e *Engine) Lists() map[string]string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make(map[string]string, len(e.listNames))
	for k, v := range e.listNames {
		out[k] = v
	}
	return out
}

// SortedLists returns list IDs in stable order.
func (e *Engine) SortedLists() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	ids := make([]string, 0, len(e.listNames))
	for id := range e.listNames {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
