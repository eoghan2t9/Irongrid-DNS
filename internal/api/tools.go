package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
	"github.com/eoghan2t9/Irongrid-DNS/internal/upstream"
)

// publicResolvers are the fixed third-party resolvers the DNS Tools page can
// query side-by-side with the locally configured upstreams.
var publicResolvers = []struct{ label, spec string }{
	{"cloudflare", "udp://1.1.1.1:53"},
	{"google", "udp://8.8.8.8:53"},
	{"quad9", "udp://9.9.9.9:53"},
}

// fastestResolver is one candidate the "find fastest upstreams" tool
// benchmarks from this server.
type fastestResolver struct{ label, spec string }

// fastestResolvers is the curated pool the Settings → Upstreams benchmark
// probes. It covers the major public resolver networks in their plain (UDP),
// encrypted (DoT) and DoH forms — including the encrypted variants, since a
// DoT/DoH handshake is a real per-connection cost the server pays. A
// variable so tests can point it at local test servers.
var fastestResolvers = []fastestResolver{
	{"Cloudflare (UDP)", "udp://1.1.1.1:53"},
	{"Cloudflare (DoT)", "tls://1.1.1.1:853"},
	{"Cloudflare (DoH)", "https://cloudflare-dns.com/dns-query"},
	{"Google (UDP)", "udp://8.8.8.8:53"},
	{"Google (DoT)", "tls://8.8.8.8:853"},
	{"Google (DoH)", "https://dns.google/dns-query"},
	{"Quad9 (UDP)", "udp://9.9.9.9:53"},
	{"Quad9 (DoT)", "tls://dns.quad9.net:853"},
	{"Quad9 (DoH)", "https://dns.quad9.net/dns-query"},
	{"OpenDNS (UDP)", "udp://208.67.222.222:53"},
	{"AdGuard (UDP)", "udp://94.140.14.14:53"},
	{"AdGuard (DoT)", "tls://dns.adguard-dns.com:853"},
	{"NextDNS (UDP)", "udp://45.90.28.167:53"},
	{"NextDNS (DoT)", "tls://dns.nextdns.io:853"},
	{"UncensoredDNS (UDP)", "udp://91.239.100.100:53"},
	{"Verisign (UDP)", "udp://64.6.64.6:53"},
	{"Comodo (UDP)", "udp://8.26.56.26:53"},
	{"Yandex (UDP)", "udp://77.88.8.8:53"},
}

// fastestProbeRounds is how many latency samples each candidate gets; the
// best (lowest) wins. The first DoT/DoH round includes the TLS handshake, so
// several rounds approximate steady-state latency. A variable so tests can
// run a single round.
var fastestProbeRounds = 3

// fastestProbeTimeout bounds one probe round; fastestMaxConcurrent caps how
// many resolvers are probed in parallel (each probe is a goroutine + socket,
// and a firewalled candidate can sit out its full timeout).
const (
	fastestProbeTimeout  = 2 * time.Second
	fastestMaxConcurrent = 6
)

// rblZones are the DNS-based reputation blocklists the RBL tool queries. A
// listing shows up as an A record in the reversed-IP form of these zones.
var rblZones = []struct{ name, zone string }{
	{"Spamhaus ZEN", "zen.spamhaus.org"},
	{"SpamCop", "bl.spamcop.net"},
	{"SORBS", "dnsbl.sorbs.net"},
	{"Barracuda", "b.barracudacentral.org"},
}

// crtShBase is the certificate-transparency endpoint used by the subdomain
// audit tool. It's a variable so tests can point it at a local server.
var crtShBase = "https://crt.sh"

// crtShClient fetches crt.sh with the same SSRF guard as the site scanner but
// a longer budget (crt.sh is slow under load).
var crtShClient = func() *http.Client {
	c := newSiteScanClient()
	c.Timeout = 20 * time.Second
	return c
}()

const (
	toolsTimeout  = 25 * time.Second
	maxSubdomains = 2000
	maxAXFRNS     = 8
)

// axfrPort is the port zone-transfer attempts dial. A variable so tests can
// point at a local test server instead of real port 53.
var axfrPort = "53"

// resolveAny queries name/type through the configured upstreams first, then
// falls back to the public resolvers — the "just answer this, I don't care
// who from" helper used by the mail, RBL and AXFR tools.
func (h *Handler) resolveAny(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	h.cfgMu.Lock()
	ups := append([]*upstream.Upstream(nil), h.Upstreams...)
	h.cfgMu.Unlock()

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true

	var lastErr error
	for _, up := range ups {
		r, err := up.Query(ctx, m)
		if err == nil {
			return r, nil
		}
		lastErr = err
	}
	for _, pr := range publicResolvers {
		up, err := upstream.Parse(pr.spec)
		if err != nil {
			continue
		}
		r, err := up.Query(ctx, m)
		if err == nil {
			return r, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// ---- fastest upstream benchmark ----

type fastestResult struct {
	Label     string `json:"label"`
	Transport string `json:"transport"`
	Spec      string `json:"spec"`
	LatencyMS int64  `json:"latency_ms"`
	InUse     bool   `json:"in_use"`
	Error     string `json:"error"`
}

// canonicalUpstreamKey normalizes a parsed upstream to the key the benchmark's
// candidate specs are indexed under, so "in use" matching survives config
// entries that omit the scheme or the port ("1.1.1.1", "tls://9.9.9.9" —
// Parse fills those in). The dial address already carries the default port;
// DoH keys on the full URL because the path is part of the endpoint.
func canonicalUpstreamKey(u *upstream.Upstream) string {
	if u.Transport == upstream.HTTPS {
		return strings.ToLower(u.Name())
	}
	return strings.ToLower(string(u.Transport) + "://" + u.Addr)
}

// toolsFastest benchmarks the curated public resolver list from this server
// and returns them sorted by measured latency, so the Settings page can offer
// one-click addition of the fastest upstreams for the server's location. Each
// candidate is probed with a real DNS query (example.com A); the best of
// fastestProbeRounds wins. Results already in the configured upstreams are
// flagged in_use, and unreachable candidates are reported (last) with their
// error rather than silently dropped.
func (h *Handler) toolsFastest(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(ctx, toolsTimeout)
	defer cancel()

	inUse := map[string]bool{}
	h.cfgMu.Lock()
	if h.Cfg != nil {
		for _, s := range h.Cfg.Upstreams {
			s = strings.ToLower(strings.TrimSpace(s))
			inUse[s] = true
			// Also index the canonical form so a configured "1.1.1.1" or
			// "tls://9.9.9.9" (Parse fills in default schemes/ports) still
			// matches the canonical "udp://1.1.1.1:53" / "tls://9.9.9.9:853"
			// candidates. DoH keys on the full URL because the path is part of
			// the endpoint.
			if up, err := upstream.Parse(s); err == nil {
				inUse[canonicalUpstreamKey(up)] = true
			}
		}
	}
	h.cfgMu.Unlock()

	out := make([]fastestResult, len(fastestResolvers))
	sem := make(chan struct{}, fastestMaxConcurrent)
	var wg sync.WaitGroup
	for i, cand := range fastestResolvers {
		wg.Add(1)
		go func(i int, cand fastestResolver) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			res := fastestResult{
				Label:     cand.label,
				Transport: strings.SplitN(cand.spec, "://", 2)[0],
				Spec:      cand.spec,
			}
			up, err := upstream.Parse(cand.spec)
			if err != nil {
				res.Error = err.Error()
				out[i] = res
				return
			}
			res.InUse = inUse[canonicalUpstreamKey(up)]
			// DoT/TCP probes pool warm connections; close them so a benchmark
			// run doesn't leave idle sockets behind for the process lifetime.
			defer up.Close()

			var best time.Duration
			var lastErr error
			for round := 0; round < fastestProbeRounds; round++ {
				if ctx.Err() != nil {
					break
				}
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				m.RecursionDesired = true
				pctx, pcancel := context.WithTimeout(ctx, fastestProbeTimeout)
				start := time.Now()
				resp, qerr := up.Query(pctx, m)
				pcancel()
				if qerr != nil {
					lastErr = qerr
					// A timeout is transient (retry); a hard error like a dial
					// refusal or no-route won't fix itself next round, and
					// burning the remaining rounds keeps the whole benchmark
					// near its 25s budget when several hosts are firewalled.
					var ne net.Error
					if errors.As(qerr, &ne) && ne.Timeout() {
						continue
					}
					break
				}
				if resp == nil || resp.Rcode == dns.RcodeServerFailure {
					lastErr = fmt.Errorf("rcode %s", dns.RcodeToString[dns.RcodeServerFailure])
					continue
				}
				d := time.Since(start)
				if best == 0 || d < best {
					best = d
				}
			}
			if best > 0 {
				res.LatencyMS = best.Milliseconds()
			} else {
				if lastErr == nil {
					lastErr = fmt.Errorf("no usable response")
				}
				res.Error = lastErr.Error()
			}
			out[i] = res
		}(i, cand)
	}
	wg.Wait()

	// Reachable candidates first, sorted by latency; failures last.
	sort.Slice(out, func(i, j int) bool {
		ei, ej := out[i].Error != "", out[j].Error != ""
		if ei != ej {
			return !ei
		}
		if ei {
			return out[i].Label < out[j].Label
		}
		return out[i].LatencyMS < out[j].LatencyMS
	})

	writeJSON(w, http.StatusOK, map[string]any{"query": "example.com", "type": "A", "results": out})
}

// ---- resolve (lookup + propagation) ----

type toolsResolvePayload struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	RD      bool     `json:"rd"`
	DO      bool     `json:"do"`
	CD      bool     `json:"cd"`
	Sources []string `json:"sources"`
}

type resolveResult struct {
	Source    string   `json:"source"`
	Server    string   `json:"server"`
	Rcode     string   `json:"rcode"`
	Answers   []string `json:"answers"`
	AA        bool     `json:"aa"`
	AD        bool     `json:"ad"`
	RA        bool     `json:"ra"`
	LatencyMS int64    `json:"latency_ms"`
	Error     string   `json:"error"`
}

// toolsResolve answers one question against a chosen set of sources — the
// configured upstreams ("local") and/or the fixed public resolvers — so the
// dashboard can offer both a dig-style lookup and a propagation comparison.
func (h *Handler) toolsResolve(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var p toolsResolvePayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil || strings.TrimSpace(p.Name) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name required"})
		return
	}
	qt, ok := dns.StringToType[strings.ToUpper(strings.TrimSpace(p.Type))]
	if !ok {
		qt = dns.TypeA
	}
	if len(p.Sources) == 0 {
		p.Sources = []string{"local"}
	}
	name := strings.TrimSuffix(strings.TrimSpace(p.Name), ".")

	ctx, cancel := context.WithTimeout(ctx, toolsTimeout)
	defer cancel()

	h.cfgMu.Lock()
	local := append([]*upstream.Upstream(nil), h.Upstreams...)
	h.cfgMu.Unlock()

	out := make([]resolveResult, 0, len(p.Sources))
	for _, src := range p.Sources {
		src = strings.ToLower(strings.TrimSpace(src))
		var ups []*upstream.Upstream
		switch src {
		case "local":
			ups = local
		case "cloudflare", "google", "quad9":
			for _, pr := range publicResolvers {
				if pr.label == src {
					if up, err := upstream.Parse(pr.spec); err == nil {
						ups = []*upstream.Upstream{up}
					}
					break
				}
			}
		default:
			continue // unknown source label
		}
		if len(ups) == 0 {
			out = append(out, resolveResult{Source: src, Error: "no upstream available for this source"})
			continue
		}

		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), qt)
		m.RecursionDesired = p.RD
		m.CheckingDisabled = p.CD
		if p.DO {
			o := new(dns.OPT)
			o.Hdr.Name = "."
			o.Hdr.Rrtype = dns.TypeOPT
			o.SetUDPSize(1232)
			o.SetDo()
			m.Extra = append(m.Extra, o)
		}

		// Answers must be non-nil so JSON serializes it as [] — a nil slice
		// becomes null, and the dashboard reads res.answers.length, which
		// throws on null and blanks the whole page (NXDOMAIN/NODATA lookups
		// return no records, so this is the common case, not the edge case).
		res := resolveResult{Source: src, Answers: []string{}}
		var lastErr error
		for _, up := range ups {
			start := time.Now()
			resp, err := up.Query(ctx, m)
			res.LatencyMS = time.Since(start).Milliseconds()
			if err == nil {
				res.Rcode = dns.RcodeToString[resp.Rcode]
				res.AA = resp.Authoritative
				res.AD = resp.AuthenticatedData
				res.RA = resp.RecursionAvailable
				res.Server = up.Name()
				for _, rr := range resp.Answer {
					res.Answers = append(res.Answers, rr.String())
				}
				break
			}
			lastErr = err
		}
		if res.Rcode == "" {
			res.Error = "query failed"
			if lastErr != nil {
				res.Error = lastErr.Error()
			}
		}
		out = append(out, res)
	}
	if len(out) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no valid sources"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"name": name, "type": dns.TypeToString[qt], "results": out,
	})
}

// ---- mail records ----

type mailCheckResult struct {
	Domain      string   `json:"domain"`
	MX          []string `json:"mx"`
	MXErr       string   `json:"mx_error"`
	SPF         string   `json:"spf"`
	SPFOK       bool     `json:"spf_ok"`
	SPFIssues   []string `json:"spf_issues"`
	SPFErr      string   `json:"spf_error"`
	DKIM        string   `json:"dkim"`
	DKIMOK      bool     `json:"dkim_ok"`
	DKIMErr     string   `json:"dkim_error"`
	DMARC       string   `json:"dmarc"`
	DMARCPolicy string   `json:"dmarc_policy"`
	DMARCErr    string   `json:"dmarc_error"`
	CAA         []string `json:"caa"`
	CAAErr      string   `json:"caa_error"`
}

// toolsMail checks the email-deliverability records for a domain: MX, SPF,
// DKIM (default selector), DMARC and CAA.
func (h *Handler) toolsMail(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var p struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil || strings.TrimSpace(p.Domain) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "domain required"})
		return
	}
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p.Domain), "."))
	if !validDomain(domain) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid domain"})
		return
	}

	ctx, cancel := context.WithTimeout(ctx, toolsTimeout)
	defer cancel()

	// Slices must be non-nil so JSON serializes them as [] — a nil slice
	// becomes null and crashes the frontend's res.mx.join/res.caa.length.
	res := mailCheckResult{Domain: domain, MX: []string{}, CAA: []string{}, SPFIssues: []string{}}

	if m, err := h.resolveAny(ctx, domain, dns.TypeMX); err == nil {
		for _, rr := range m.Answer {
			if mx, ok := rr.(*dns.MX); ok {
				res.MX = append(res.MX, fmt.Sprintf("%d %s", mx.Preference, mx.Mx))
			}
		}
		if len(res.MX) == 0 {
			res.MXErr = "no MX records"
		}
	} else {
		res.MXErr = err.Error()
	}

	if m, err := h.resolveAny(ctx, domain, dns.TypeTXT); err == nil {
		for _, rr := range m.Answer {
			if t, ok := rr.(*dns.TXT); ok {
				joined := strings.Join(t.Txt, "")
				if strings.HasPrefix(strings.ToLower(strings.TrimSpace(joined)), "v=spf1") {
					res.SPF = joined
					break
				}
			}
		}
		if res.SPF == "" {
			res.SPFErr = "no SPF record (no TXT starting with v=spf1)"
		} else {
			res.SPFOK = true
			res.SPFIssues = spfIssues(res.SPF)
			if len(res.SPFIssues) > 0 {
				res.SPFOK = false
			}
		}
	} else {
		res.SPFErr = err.Error()
	}

	if m, err := h.resolveAny(ctx, "default._domainkey."+domain, dns.TypeTXT); err == nil {
		for _, rr := range m.Answer {
			if t, ok := rr.(*dns.TXT); ok {
				joined := strings.Join(t.Txt, "")
				lower := strings.ToLower(joined)
				if strings.Contains(lower, "v=dkim1") || strings.Contains(lower, "k=rsa") {
					res.DKIM = joined
					break
				}
			}
		}
		if res.DKIM == "" {
			res.DKIMErr = "no DKIM record at default._domainkey (custom selectors aren't checked)"
		} else {
			res.DKIMOK = true
		}
	} else {
		res.DKIMErr = err.Error()
	}

	if m, err := h.resolveAny(ctx, "_dmarc."+domain, dns.TypeTXT); err == nil {
		for _, rr := range m.Answer {
			if t, ok := rr.(*dns.TXT); ok {
				joined := strings.Join(t.Txt, "")
				if strings.HasPrefix(strings.ToLower(strings.TrimSpace(joined)), "v=dmarc1") {
					res.DMARC = joined
					res.DMARCPolicy = dmarcPolicy(joined)
					break
				}
			}
		}
		if res.DMARC == "" {
			res.DMARCErr = "no DMARC record (no _dmarc TXT starting with v=DMARC1)"
		}
	} else {
		res.DMARCErr = err.Error()
	}

	if m, err := h.resolveAny(ctx, domain, dns.TypeCAA); err == nil {
		for _, rr := range m.Answer {
			if c, ok := rr.(*dns.CAA); ok {
				res.CAA = append(res.CAA, fmt.Sprintf("%d %s %q", c.Flag, c.Tag, c.Value))
			}
		}
		if len(res.CAA) == 0 {
			res.CAAErr = "no CAA records (any CA may issue certificates)"
		}
	} else {
		res.CAAErr = err.Error()
	}

	writeJSON(w, http.StatusOK, res)
}

// validDomain reports whether s is a plausible DNS name — also blocks query
// parameter injection into URLs built from user-supplied domains.
func validDomain(s string) bool {
	_, ok := dns.IsDomainName(s)
	return ok
}

// spfIssues runs the two checks that break real-world SPF records: exceeding
// the 10-DNS-lookup limit and lacking a hard/soft fail term.
func spfIssues(spf string) []string {
	var issues []string
	upper := strings.ToUpper(spf)
	if !strings.Contains(upper, "-ALL") && !strings.Contains(upper, "~ALL") {
		issues = append(issues, "no -all or ~all term — receivers won't hard-fail forged mail")
	}
	lookups := 0
	for mech := range strings.FieldsSeq(spf) {
		m := mech
		if i := strings.IndexAny(m, ":/"); i >= 0 {
			m = m[:i]
		}
		switch strings.ToLower(m) {
		case "a", "mx", "ptr", "exists", "include":
			lookups++
		}
	}
	if lookups > 10 {
		issues = append(issues, fmt.Sprintf("%d DNS lookups — the SPF limit is 10, receivers will reject or strip the record", lookups))
	}
	return issues
}

func dmarcPolicy(record string) string {
	for part := range strings.SplitSeq(record, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "p=") {
			return strings.TrimSpace(part[2:])
		}
	}
	return ""
}

// ---- RBL reputation check ----

type rblResult struct {
	RBL    string `json:"rbl"`
	Zone   string `json:"zone"`
	Listed bool   `json:"listed"`
	Code   string `json:"code"`
	Reason string `json:"reason"`
	Error  string `json:"error"`
}

// toolsRBL checks an IPv4 address against the DNS-based reputation lists.
func (h *Handler) toolsRBL(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var p struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ip required"})
		return
	}
	v4 := net.ParseIP(strings.TrimSpace(p.IP)).To4()
	if v4 == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "must be an IPv4 address"})
		return
	}

	ctx, cancel := context.WithTimeout(ctx, toolsTimeout)
	defer cancel()

	octets := strings.Split(v4.String(), ".")
	reversed := octets[3] + "." + octets[2] + "." + octets[1] + "." + octets[0]

	out := make([]rblResult, 0, len(rblZones))
	for _, z := range rblZones {
		res := rblResult{RBL: z.name, Zone: z.zone}
		qname := reversed + "." + z.zone
		m, err := h.resolveAny(ctx, qname, dns.TypeA)
		if err != nil {
			res.Error = err.Error()
		} else if m.Rcode == dns.RcodeSuccess && len(m.Answer) > 0 {
			res.Listed = true
			for _, rr := range m.Answer {
				if a, ok := rr.(*dns.A); ok {
					res.Code = a.A.String()
					break
				}
			}
			if tm, terr := h.resolveAny(ctx, qname, dns.TypeTXT); terr == nil {
				for _, rr := range tm.Answer {
					if t, ok := rr.(*dns.TXT); ok {
						res.Reason = strings.Join(t.Txt, " ")
						break
					}
				}
			}
		}
		out = append(out, res)
	}

	writeJSON(w, http.StatusOK, map[string]any{"ip": v4.String(), "checks": out})
}

// ---- zone-transfer (AXFR) check ----

type axfrNSResult struct {
	Host    string `json:"host"`
	Address string `json:"address"`
	AXFR    bool   `json:"axfr"`
	Records int    `json:"records"`
	Error   string `json:"error"`
}

// toolsAXFR tries a zone transfer against each of a domain's nameservers and
// reports any that leak the zone.
func (h *Handler) toolsAXFR(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var p struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil || strings.TrimSpace(p.Domain) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "domain required"})
		return
	}
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p.Domain), "."))
	if !validDomain(domain) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid domain"})
		return
	}

	ctx, cancel := context.WithTimeout(ctx, toolsTimeout)
	defer cancel()

	nsm, err := h.resolveAny(ctx, domain, dns.TypeNS)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "could not resolve NS records: " + err.Error()})
		return
	}
	seen := map[string]bool{}
	var nsHosts []string
	for _, rr := range nsm.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			host := strings.ToLower(strings.TrimSuffix(ns.Ns, "."))
			if !seen[host] {
				seen[host] = true
				nsHosts = append(nsHosts, host)
			}
		}
	}
	if len(nsHosts) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"domain": domain, "nameservers": []axfrNSResult{}, "note": "no NS records found"})
		return
	}
	if len(nsHosts) > maxAXFRNS {
		nsHosts = nsHosts[:maxAXFRNS]
	}

	out := make([]axfrNSResult, 0, len(nsHosts))
	for _, host := range nsHosts {
		// dns.Transfer.In ignores ctx, so bound the work between attempts.
		if ctx.Err() != nil {
			break
		}
		addrs := []string{}
		for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
			if am, err := h.resolveAny(ctx, host, qt); err == nil {
				for _, rr := range am.Answer {
					if a, ok := rr.(*dns.A); ok {
						addrs = append(addrs, a.A.String())
					} else if aaaa, ok := rr.(*dns.AAAA); ok {
						addrs = append(addrs, aaaa.AAAA.String())
					}
				}
			}
		}
		if len(addrs) == 0 {
			out = append(out, axfrNSResult{Host: host, Error: "no addresses"})
			continue
		}
		// Try at most the first two addresses per nameserver.
		for i, addr := range addrs {
			if i >= 2 || ctx.Err() != nil {
				break
			}
			records, err := tryAXFR(ctx, domain, addr)
			res := axfrNSResult{Host: host, Address: addr}
			if err != nil {
				res.Error = err.Error()
			} else {
				res.AXFR = records > 0
				res.Records = records
			}
			out = append(out, res)
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"domain": domain, "nameservers": out})
}

// tryAXFR requests a zone transfer over TCP and reports how many records the
// server was willing to hand over (0 with no error means a refused transfer).
func tryAXFR(ctx context.Context, domain, addr string) (int, error) {
	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(domain))
	t := &dns.Transfer{DialTimeout: 3 * time.Second, ReadTimeout: 3 * time.Second}
	// In (not InContext — unavailable in this miekg/dns version); the
	// caller's toolsTimeout budget plus the ctx checks between attempts
	// still bound the whole thing, and a single in-flight transfer can't
	// run more than ~6s past that budget.
	ch, err := t.In(m, net.JoinHostPort(addr, axfrPort))
	if err != nil {
		return 0, err
	}
	count := 0
	for env := range ch {
		if env.Error != nil {
			return count, env.Error
		}
		count += len(env.RR)
	}
	return count, nil
}

// ---- subdomain audit (certificate transparency) ----

type subdomainResult struct {
	Domain  string `json:"domain"`
	Blocked bool   `json:"blocked"`
	List    string `json:"list"`
}

// toolsSubdomains enumerates a domain's subdomains via crt.sh and reports
// which ones the current blocklists cover.
func (h *Handler) toolsSubdomains(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var p struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil || strings.TrimSpace(p.Domain) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "domain required"})
		return
	}
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p.Domain), "."))
	// dns.IsDomainName also blocks query-parameter injection into the crt.sh
	// URL built below (characters like & and = fail label validation).
	if !validDomain(domain) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid domain"})
		return
	}

	ctx, cancel := context.WithTimeout(ctx, toolsTimeout)
	defer cancel()

	u := fmt.Sprintf("%s/?q=%%25.%s&output=json", crtShBase, domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	req.Header.Set("User-Agent", "Irongrid-DNS tools/1.0 (+https://github.com/eoghan2t9/Irongrid-DNS)")

	resp, err := crtShClient.Do(req)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "crt.sh fetch failed: " + err.Error()})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": fmt.Sprintf("crt.sh returned HTTP %d", resp.StatusCode)})
		return
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20+1))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "read failed: " + err.Error()})
		return
	}
	if len(body) > 8<<20 {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "crt.sh response too large"})
		return
	}

	var rows []struct {
		NameValue  string `json:"name_value"`
		CommonName string `json:"common_name"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "crt.sh returned unparseable data"})
		return
	}

	suffix := "." + domain
	unique := map[string]bool{}
	for _, row := range rows {
		for _, n := range append(strings.Fields(row.CommonName), strings.Fields(row.NameValue)...) {
			n = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(n), "*."), "."))
			if n == "" || (n != domain && !strings.HasSuffix(n, suffix)) {
				continue
			}
			unique[n] = true
		}
	}
	names := make([]string, 0, len(unique))
	for n := range unique {
		names = append(names, n)
	}
	sort.Strings(names)

	truncated := len(names) > maxSubdomains
	if truncated {
		names = names[:maxSubdomains]
	}

	blocked := 0
	out := make([]subdomainResult, 0, len(names))
	for _, n := range names {
		bl := false
		list := ""
		if h.Engine != nil {
			dec := h.Engine.DecideDomain(n)
			bl = dec.Action == filter.Block
			list = dec.ListName
		}
		if bl {
			blocked++
		}
		out = append(out, subdomainResult{Domain: n, Blocked: bl, List: list})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"domain": domain, "total": len(out), "blocked": blocked,
		"truncated": truncated, "domains": out,
	})
}
