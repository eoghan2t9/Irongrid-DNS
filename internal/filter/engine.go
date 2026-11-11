// Package filter implements the blocking engine: blocklist parsing, rule
// matching with wildcard/subdomain semantics, and whitelist override.
package filter

import (
	"fmt"
	"maps"
	"net"
	"slices"
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
	// "blacklist:<domain>", "ip-blocklist" or "" when allowed.
	Reason string
	// ListName is the friendly name of the list that matched, for the UI.
	ListName string
}

// ruleSet is the immutable snapshot DecideDomain/CheckIPs/Stats/Lists read
// lock-free. Every field is a private copy made at publish time — once
// stored in Engine.rs, nothing ever mutates it again, so concurrent readers
// need no lock. This trades a copy on every write-side call (LoadList batch
// completion, AddIPBlock/RemoveIPBlock, Reset — all config-reload-frequency,
// never per-query) for lock-free reads on the DNS hot path, which runs on
// every query that isn't already resolved by an earlier rewrite/cache/DHCP
// hit.
type ruleSet struct {
	// blockDomains / blockExact are the downloaded lists' block rules as
	// compact fingerprint tables (see hashTable); the per-entry payload indexes
	// listIDs so a hit can still report which list it came from.
	blockDomains *hashTable
	blockExact   *hashTable
	listIDs      []string
	blockIPs     map[string]struct{}
	allowDomains map[string]struct{}
	allowExact   map[string]struct{}
	allowIPs     map[string]struct{}
	blockRegex   []RegexRule
	allowRegex   []RegexRule
	listNames    map[string]string

	// userBlockExact / userBlockDomains hold only the manual blacklist's
	// entries, kept apart from blockExact/blockDomains (downloaded-list
	// entries only) so DecideDomain can let an explicit manual block win
	// over the whitelist — e.g. a curated device whitelist meant to
	// protect against the downloaded blocklists' false positives, not
	// against a domain the operator has specifically chosen to block —
	// while a downloaded blocklist's entries never do.
	userBlockExact   map[string]struct{}
	userBlockDomains map[string]struct{}

	totalBlockedDomains int
	totalIPRules        int
	userWhitelistLen    int
	userBlacklistLen    int
}

// listName resolves a table payload to the list's friendly name.
func (rs *ruleSet) listName(li uint16) string {
	if int(li) < len(rs.listIDs) {
		return rs.listNames[rs.listIDs[li]]
	}
	return ""
}

var emptyRuleSet = &ruleSet{
	blockIPs:         map[string]struct{}{},
	allowDomains:     map[string]struct{}{},
	allowExact:       map[string]struct{}{},
	allowIPs:         map[string]struct{}{},
	listNames:        map[string]string{},
	userBlockExact:   map[string]struct{}{},
	userBlockDomains: map[string]struct{}{},
}

// Engine holds the compiled rule sets. The mutable fields below (the
// write-side working state) are guarded by mu; DecideDomain and CheckIPs
// never take mu — they read the atomically-published rs snapshot instead.
type Engine struct {
	mu sync.Mutex

	// blockDomains / blockExact hold the downloaded lists' block rules as
	// compact tables. LoadList parses each list into throwaway maps and folds
	// them in here immediately, so the large string maps never accumulate.
	blockDomains *hashTable
	blockExact   *hashTable
	// listIDs / listIdx map a list ID to the uint16 payload stored in the
	// tables above.
	listIDs []string
	listIdx map[string]uint16

	blockIPs     map[string]struct{}
	allowDomains map[string]struct{}
	allowExact   map[string]struct{}
	allowIPs     map[string]struct{}
	// blockRegex / allowRegex are the compiled AdGuard-style /pattern/ rules
	// DecideDomain scans (order within a source is preserved; matching scans
	// them linearly). Compile rebuilds them from the two sources below, so
	// repeated Compile calls are idempotent: listBlockRegex/listAllowRegex
	// come from LoadList, userBlockRegex/userAllowRegex from SetUserLists.
	//
	// Scaling note: every query that reaches the regex stage pays one RE2
	// match per rule, in list order, until one hits or the list is
	// exhausted (RE2 itself is linear-time per match, so this is safe from
	// ReDoS, just not free). Fine at the sizes AdGuard-style manual/inline
	// regex rules realistically reach (tens to low hundreds); an operator
	// loading thousands of regex rules would feel this on every query that
	// isn't resolved by an earlier exact/domain/subtree hit. There's no
	// structural fix without building a regex-combining engine (and RE2
	// alternation of that many patterns isn't free either) — if this ever
	// becomes the bottleneck, the fix is bounding/warning on regex rule
	// count, not a rewrite here.
	blockRegex     []RegexRule
	allowRegex     []RegexRule
	listBlockRegex []RegexRule
	listAllowRegex []RegexRule
	userBlockRegex []RegexRule
	userAllowRegex []RegexRule

	listNames map[string]string // list ID -> friendly name

	// Explicit user entries take precedence over list contents.
	userBlacklist []string
	userWhitelist []string

	// userBlockExact / userBlockDomains mirror blockExact/blockDomains but
	// are populated from userBlacklist only (see Compile), kept separate
	// so DecideDomain can let them override the whitelist while a
	// downloaded blocklist's entries never do.
	userBlockExact   map[string]struct{}
	userBlockDomains map[string]struct{}

	totalBlockedDomains int
	totalIPRules        int

	// hasIPRules is true whenever any IP rule (block or allow) is present,
	// so the DNS hot path can skip its answer-IP walk entirely for the
	// common domain-only list setups. It is maintained under e.mu wherever
	// the IP sets change (syncIPFlag) and read lock-free.
	hasIPRules atomic.Bool

	// shared is true while the working maps above are the very same map
	// objects the published snapshot (rs) references. Publishing hands the
	// maps over instead of cloning them — a clone doubled the resident size of
	// a ~1M-rule engine — so any later in-place mutation must first call
	// unshareLocked, which clones them (copy-on-write). Guarded by mu.
	shared bool

	// rs is the published snapshot DecideDomain/CheckIPs/Stats/Lists read.
	rs atomic.Pointer[ruleSet]
}

// NewEngine returns an empty engine.
func NewEngine() *Engine {
	e := &Engine{
		listIdx:          map[string]uint16{},
		blockIPs:         map[string]struct{}{},
		allowDomains:     map[string]struct{}{},
		allowExact:       map[string]struct{}{},
		allowIPs:         map[string]struct{}{},
		listNames:        map[string]string{},
		userBlockExact:   map[string]struct{}{},
		userBlockDomains: map[string]struct{}{},
	}
	e.rs.Store(emptyRuleSet)
	return e
}

// Reset clears every rule so a fresh reload replaces (not accumulates) state.
// Used by the list manager before recompiling from current sources.
func (e *Engine) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.blockDomains = nil
	e.blockExact = nil
	e.listIDs = nil
	e.listIdx = map[string]uint16{}
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
	e.listNames = map[string]string{}
	e.userBlockExact = map[string]struct{}{}
	e.userBlockDomains = map[string]struct{}{}
	e.totalBlockedDomains = 0
	e.totalIPRules = 0
	e.shared = false
	e.hasIPRules.Store(false)
	e.rs.Store(emptyRuleSet)
}

// publishLocked atomically publishes the current working state as the
// snapshot lock-free readers use. Callers must hold e.mu.
//
// The maps are handed over by reference, not cloned: the working state and the
// snapshot then share one copy, halving the memory of a large engine. That is
// safe because every in-place mutation of a map goes through unshareLocked
// (or replaces the map outright) first, so a published map is never written
// to again.
func (e *Engine) publishLocked() {
	e.shared = true
	e.rs.Store(&ruleSet{
		blockDomains:        e.blockDomains,
		blockExact:          e.blockExact,
		listIDs:             slices.Clone(e.listIDs),
		blockIPs:            e.blockIPs,
		allowDomains:        e.allowDomains,
		allowExact:          e.allowExact,
		allowIPs:            e.allowIPs,
		blockRegex:          e.blockRegex,
		allowRegex:          e.allowRegex,
		listNames:           e.listNames,
		userBlockExact:      e.userBlockExact,
		userBlockDomains:    e.userBlockDomains,
		totalBlockedDomains: e.totalBlockedDomains,
		totalIPRules:        e.totalIPRules,
		userWhitelistLen:    len(e.userWhitelist),
		userBlacklistLen:    len(e.userBlacklist),
	})
}

// unshareLocked gives the working state private copies of every map when they
// are currently shared with the published snapshot, so they can be mutated
// without racing a lock-free reader. Callers must hold e.mu.
func (e *Engine) unshareLocked() {
	if !e.shared {
		return
	}
	e.blockDomains = e.blockDomains.clone()
	e.blockExact = e.blockExact.clone()
	e.blockIPs = maps.Clone(e.blockIPs)
	e.allowDomains = maps.Clone(e.allowDomains)
	e.allowExact = maps.Clone(e.allowExact)
	e.allowIPs = maps.Clone(e.allowIPs)
	e.listIdx = maps.Clone(e.listIdx)
	e.listIDs = slices.Clone(e.listIDs)
	e.listNames = maps.Clone(e.listNames)
	e.userBlockExact = maps.Clone(e.userBlockExact)
	e.userBlockDomains = maps.Clone(e.userBlockDomains)
	e.shared = false
}

// Rebuild replaces every list-derived rule with a freshly built set and swaps
// it in atomically. fill receives a private engine to LoadList into; user
// lists are carried over, the result is compiled, and only then is it
// published — so DecideDomain never observes an empty or half-loaded rule set
// (Reset followed by LoadList/Compile exposed exactly that window).
func (e *Engine) Rebuild(fill func(nb *Engine)) {
	for attempt := 0; ; attempt++ {
		e.mu.Lock()
		bl, wl := e.userBlacklist, e.userWhitelist
		bre, are := e.userBlockRegex, e.userAllowRegex
		e.mu.Unlock()

		nb := NewEngine()
		nb.userBlacklist, nb.userWhitelist = bl, wl
		nb.userBlockRegex, nb.userAllowRegex = bre, are
		fill(nb)
		nb.Compile()

		e.mu.Lock()
		// SetUserLists may have run while we were building; if so the new
		// state was compiled against stale user lists, so build again.
		if attempt < 3 && (!slices.Equal(bl, e.userBlacklist) || !slices.Equal(wl, e.userWhitelist)) {
			e.mu.Unlock()
			continue
		}
		e.blockDomains, e.blockExact, e.blockIPs = nb.blockDomains, nb.blockExact, nb.blockIPs
		e.listIDs, e.listIdx = nb.listIDs, nb.listIdx
		e.allowDomains, e.allowExact, e.allowIPs = nb.allowDomains, nb.allowExact, nb.allowIPs
		e.blockRegex, e.allowRegex = nb.blockRegex, nb.allowRegex
		e.listBlockRegex, e.listAllowRegex = nb.listBlockRegex, nb.listAllowRegex
		e.userBlockRegex, e.userAllowRegex = nb.userBlockRegex, nb.userAllowRegex
		e.listNames = nb.listNames
		e.userBlockExact, e.userBlockDomains = nb.userBlockExact, nb.userBlockDomains
		e.totalBlockedDomains, e.totalIPRules = nb.totalBlockedDomains, nb.totalIPRules
		e.syncIPFlag()
		e.publishLocked()
		e.mu.Unlock()
		return
	}
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
	e.unshareLocked()
	if e.listNames == nil {
		e.listNames = map[string]string{}
	}
	e.listNames[id] = name
	// Block rules are parsed into throwaway maps and folded straight into the
	// compact tables, so only one list's worth of string maps is ever live
	// (peak memory) and none survive past this call (steady-state memory).
	blockDomains := map[string]struct{}{}
	blockExact := map[string]struct{}{}
	res := parseContent(string(content), id,
		blockDomains, blockExact, e.blockIPs,
		e.allowDomains, e.allowExact, e.allowIPs,
		nil, &e.listBlockRegex, &e.listAllowRegex)
	li := e.listIndexLocked(id)
	for d := range blockDomains {
		e.blockDomains = e.blockDomains.insert(hashName(d), li)
	}
	for d := range blockExact {
		e.blockExact = e.blockExact.insert(hashName(d), li)
	}
	e.totalBlockedDomains += res.Domains + res.ExactDomains + res.Regexes
	e.totalIPRules += res.IPs
	e.syncIPFlag()
	return res, nil
}

// listIndexLocked returns the table payload for a list ID, assigning the next
// index on first use. Callers hold e.mu. Past 65534 distinct lists (not a
// realistic configuration) extra lists share the last slot, which only blurs
// the "blocked by" attribution.
func (e *Engine) listIndexLocked(id string) uint16 {
	if i, ok := e.listIdx[id]; ok {
		return i
	}
	if e.listIdx == nil {
		e.listIdx = map[string]uint16{}
	}
	if len(e.listIDs) >= 1<<16-1 {
		return uint16(len(e.listIDs) - 1)
	}
	i := uint16(len(e.listIDs))
	e.listIDs = append(e.listIDs, id)
	e.listIdx[id] = i
	return i
}

// Compile rebuilds derived state (user lists take precedence over list rules).
func (e *Engine) Compile() {
	e.mu.Lock()
	defer e.mu.Unlock()
	// Rebuild the merged regex set from its two sources so a repeated
	// Compile (without an intervening Reset) doesn't duplicate rules — the
	// domain sets below are maps and dedupe naturally, the regex slices are
	// not.
	e.blockRegex = slices.Concat(e.listBlockRegex, e.userBlockRegex)
	e.allowRegex = slices.Concat(e.listAllowRegex, e.userAllowRegex)
	if len(e.userWhitelist) > 0 && e.shared {
		// The loop below writes to the allow maps in place; they may be the
		// published snapshot's. (The block tables are never written here.)
		e.allowExact = maps.Clone(e.allowExact)
		e.allowDomains = maps.Clone(e.allowDomains)
	}
	// User whitelist wins. Regex entries in
	// the user lists are handled by parseUserRegexes; splitRule rejects the
	// '/' lines so they fall through here untouched.
	// DecideDomain consults the allow sets before the block tables, so a
	// whitelist entry wins without needing to be deleted from them (which the
	// compact tables can't do — they don't retain the names).
	for _, d := range e.userWhitelist {
		domain, exact, _, _ := splitRule(d)
		if exact {
			e.allowExact[domain] = struct{}{}
		} else {
			e.allowDomains[domain] = struct{}{}
		}
	}
	// Incremental LoadList growth can leave slack; trim before publishing.
	e.blockDomains = e.blockDomains.fit()
	e.blockExact = e.blockExact.fit()
	// Manual blacklist entries are kept in their own sets rather than
	// merged into blockExact/blockDomains, so DecideDomain can let them
	// override the whitelist above — unlike a downloaded blocklist's
	// entries, which the whitelist loop above already stripped out.
	// Rebuilt fresh each call, same as blockRegex/allowRegex, so a
	// repeated Compile without an intervening Reset doesn't retain an
	// entry removed from userBlacklist since the last call.
	e.userBlockExact = map[string]struct{}{}
	e.userBlockDomains = map[string]struct{}{}
	for _, d := range e.userBlacklist {
		domain, exact, _, _ := splitRule(d)
		if exact {
			e.userBlockExact[domain] = struct{}{}
		} else {
			e.userBlockDomains[domain] = struct{}{}
		}
	}
	e.syncIPFlag()
	e.publishLocked()
}

// HasIPRules reports whether the engine holds any IP rules (block or allow).
// The DNS hot path gates its answer-IP walk on this atomic read, so the
// common domain-only list setup skips the per-answer IP check entirely.
func (e *Engine) HasIPRules() bool { return e.hasIPRules.Load() }

// DecideDomain evaluates a fully qualified query name (with trailing dot).
// Lock-free: it reads the published ruleSet snapshot rather than taking
// e.mu, so concurrent queries never contend with each other here (only a
// config reload's Compile/AddIPBlock/RemoveIPBlock briefly takes the write
// lock, and even that never blocks a reader — Load always returns the
// previously published snapshot until the new one is stored).
func (e *Engine) DecideDomain(qname string) Decision {
	qname = normalizeDomain(qname)
	if qname == "" {
		return Decision{Action: Allow}
	}
	rs := e.rs.Load()

	// lastDot bounds both ancestor walks below: parent suffixes are sliced
	// directly off qname at each '.' (zero allocation — Go string slicing
	// shares the backing array, unlike the strings.Split+Join this replaced,
	// which allocated a new string per ancestor level per query) and the
	// walk stops before the bare top-level label, e.g. "com" alone is never
	// treated as a subtree rule. -1 for a single-label qname makes both
	// loops below a no-op, correctly limiting it to the exact-match checks.
	lastDot := strings.LastIndexByte(qname, '.')

	// Manual blacklist (exact first, then subtree), ahead of the whitelist
	// below: an explicit, operator-added block is a stronger signal than a
	// whitelist entry — e.g. a curated device whitelist meant only to
	// protect against the downloaded blocklists' false positives, not
	// against a domain the operator has specifically decided to block.
	if _, ok := rs.userBlockExact[qname]; ok {
		return Decision{Action: Block, Reason: "blacklist:" + qname}
	}
	if _, ok := rs.userBlockDomains[qname]; ok {
		return Decision{Action: Block, Reason: "blacklist:" + qname}
	}
	for i := range lastDot {
		if qname[i] != '.' {
			continue
		}
		parent := qname[i+1:]
		if _, ok := rs.userBlockDomains[parent]; ok {
			return Decision{Action: Block, Reason: "blacklist:" + parent}
		}
	}

	// Whitelist (exact first, then subtree). Walks ancestor domains with map
	// lookups — same shape as the blocklist walk below — instead of scanning
	// every whitelist entry with domainMatch, which used to cost O(len(allowDomains))
	// per query regardless of whether it hit.
	if _, ok := rs.allowExact[qname]; ok {
		return Decision{Action: Allow, Reason: "whitelist:" + qname}
	}
	if _, ok := rs.allowDomains[qname]; ok {
		return Decision{Action: Allow, Reason: "whitelist:" + qname}
	}
	for i := range lastDot {
		if qname[i] != '.' {
			continue
		}
		parent := qname[i+1:]
		if _, ok := rs.allowDomains[parent]; ok {
			return Decision{Action: Allow, Reason: "whitelist:" + parent}
		}
	}
	// Whitelist regexes (AdGuard @@/pattern/ exceptions) override block
	// regexes. RE2 matching is linear-time, so even a long regex list can't
	// be weaponised into a ReDoS.
	for _, rr := range rs.allowRegex {
		if rr.mayMatch(qname) && rr.Re.MatchString(qname) {
			return Decision{Action: Allow, Reason: "whitelist:regex"}
		}
	}

	// Block exact matches.
	qh := hashName(qname)
	if li, ok := rs.blockExact.get(qh); ok {
		return Decision{Action: Block, Reason: "blocklist:exact", ListName: rs.listName(li)}
	}
	if li, ok := rs.blockDomains.get(qh); ok {
		return Decision{Action: Block, Reason: "blocklist:" + qname, ListName: rs.listName(li)}
	}
	// Block subtree matches. Walk ancestors for better reasons.
	for i := range lastDot {
		if qname[i] != '.' {
			continue
		}
		parent := qname[i+1:]
		if li, ok := rs.blockDomains.get(hashName(parent)); ok {
			return Decision{Action: Block, Reason: "blocklist:" + parent, ListName: rs.listName(li)}
		}
	}
	// Block regexes: matched against the full query name, so a pattern can
	// target any label (^ads\. matches only the first label, \.ads\. any
	// label).
	for _, rr := range rs.blockRegex {
		if rr.mayMatch(qname) && rr.Re.MatchString(qname) {
			return Decision{Action: Block, Reason: "blocklist:regex", ListName: rs.listNames[rr.List]}
		}
	}
	return Decision{Action: Allow}
}

// CheckIPs reports whether any of the given addresses is blocked by an IP
// rule (and not whitelisted). Lock-free, same rationale as DecideDomain.
func (e *Engine) CheckIPs(ips []net.IP) (bool, string) {
	rs := e.rs.Load()
	for _, ip := range ips {
		s := ip.String()
		if _, ok := rs.allowIPs[s]; ok {
			continue
		}
		if _, ok := rs.blockIPs[s]; ok {
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
		e.blockIPs = maps.Clone(e.blockIPs) // copy-on-write: the old set may be published
		e.blockIPs[parsed.String()] = struct{}{}
		e.syncIPFlag()
		e.publishLocked()
	}
}

// RemoveIPBlock removes a manual IP rule.
func (e *Engine) RemoveIPBlock(ip string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if parsed := net.ParseIP(ip); parsed != nil {
		e.blockIPs = maps.Clone(e.blockIPs) // copy-on-write: the old set may be published
		delete(e.blockIPs, parsed.String())
		e.syncIPFlag()
		e.publishLocked()
	}
}

// Stats returns counters for the dashboard.
func (e *Engine) Stats() map[string]int {
	rs := e.rs.Load()
	return map[string]int{
		"blocked_domains": rs.totalBlockedDomains,
		"blocked_exact":   rs.blockExact.Len(),
		"ip_rules":        rs.totalIPRules,
		"regex_rules":     len(rs.blockRegex),
		"whitelist":       rs.userWhitelistLen,
		"blacklist":       rs.userBlacklistLen,
		"lists":           len(rs.listNames),
	}
}

// Lists returns the registered list names.
func (e *Engine) Lists() map[string]string {
	rs := e.rs.Load()
	out := make(map[string]string, len(rs.listNames))
	maps.Copy(out, rs.listNames)
	return out
}

// SortedLists returns list IDs in stable order.
func (e *Engine) SortedLists() []string {
	rs := e.rs.Load()
	ids := make([]string, 0, len(rs.listNames))
	for id := range rs.listNames {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}
