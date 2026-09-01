package api

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/eoghan2t9/Irongrid-DNS/internal/acme"
	"github.com/eoghan2t9/Irongrid-DNS/internal/cache"
	"github.com/eoghan2t9/Irongrid-DNS/internal/catalog"
	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
	"github.com/eoghan2t9/Irongrid-DNS/internal/dhcp"
	"github.com/eoghan2t9/Irongrid-DNS/internal/dnsserver"
	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
	"github.com/eoghan2t9/Irongrid-DNS/internal/firewall"
	"github.com/eoghan2t9/Irongrid-DNS/internal/geoip"
	"github.com/eoghan2t9/Irongrid-DNS/internal/querylog"
	"github.com/eoghan2t9/Irongrid-DNS/internal/recursive"
	"github.com/eoghan2t9/Irongrid-DNS/internal/tunnel"
	"github.com/eoghan2t9/Irongrid-DNS/internal/upstream"
)

// Handler implements the REST endpoints. It is created by main and injected
// into the router.
type Handler struct {
	cfgMu      sync.Mutex // guards Cfg mutations + SaveConfig
	Cfg        *config.Config
	ConfigPath string
	SaveConfig func() error
	// Reload rebinds listeners, cache, TLS and the web server from the
	// current in-memory config. Wired up by main; nil when unavailable.
	Reload func() error
	// ReloadTLS regenerates the TLS config and rebinds only the DNS listeners
	// (DoT/DoH/DoQ + plain). Used after the dashboard generates or uploads a
	// certificate, without touching the cache or upstreams.
	ReloadTLS func() error
	// ACME is the Let's Encrypt manager; nil when disabled.
	ACME interface {
		GetStatus() acme.Status
		ForceIssue(context.Context) error
		NeedsRenewal() bool
	}

	Engine *filter.Engine
	Lists  *filter.ListManager
	Cache  *cache.Cache
	Log    *querylog.Log

	// hostOnce/hosts and asnOnce/asns back the cached reverse-DNS and
	// BGP/ISP-owner lookups for the query-log and blocked-clients views
	// (see hostname.go and asn.go).
	hostOnce sync.Once
	hosts    *hostCache
	asnOnce  sync.Once
	asns     *asnCache
	// hostFlight/asnFlight coalesce concurrent enrichment lookups for the
	// same IP so parallel dashboard polls share one external round trip
	// (see resolveHostname and resolveASN).
	hostFlight singleflight.Group
	asnFlight  singleflight.Group
	DNS        *dnsserver.Handler
	DNSManager *dnsserver.Manager // listener manager; reports bound UDP/DoQ socket counts
	Tunnel     *tunnel.Manager
	Upstreams  []*upstream.Upstream
	// Hints is the authoritative root-hints manager for recursive://
	// upstreams; nil when no recursive upstream is configured.
	Hints     *recursive.HintsManager
	Catalog   *catalog.Catalog
	StartedAt time.Time
	Version   string

	// Geo is the country-data manager behind geo-blocking; nil when geo
	// blocking was never enabled. RebuildGeo (re)loads country data and
	// swaps the DNS handler's blocker; wired up by main, nil when
	// unavailable. Firewall is the host-firewall manager that mirrors the
	// blocked countries at the packet level (nftables/iptables); nil when
	// unavailable.
	Geo        *geoip.Manager
	Firewall   *firewall.Manager
	RebuildGeo func(cfg config.GeoBlockConfig) error
	// GroupASN is the pruned IP→ASN table covering every client group's ASN
	// list, refreshed by main whenever the config changes; nil when no group
	// matches by ASN. RebuildClientGroups (re)loads it from a fresh config
	// and rebuilds the client router — the async sibling of RebuildGeo, so a
	// dataset download never stalls the save.
	GroupASN            atomic.Pointer[geoip.ASNTable]
	RebuildClientGroups func(cfg *config.Config) error

	// Warmer is the proactive cache warmer; nil when not wired (tests).
	Warmer *dnsserver.Warmer

	// DHCP is the built-in DHCP server (DHCPv4 + DHCPv6); nil when not wired
	// (tests) or the feature is unused on this host.
	DHCP *dhcp.Server

	// lastInstalledVersion is set after a successful in-place update and
	// cleared on restart (process exit). It guards against installing twice
	// before the restart, which would clobber the .prev rollback copy.
	lastInstalledVersion string
}

// ConfigMu exposes the mutex that guards Cfg mutations so the App's auth
// checks (authorize/issueSession/validSession) can snapshot config fields
// under the same lock applyPayload uses when it rotates the session secret.
func (h *Handler) ConfigMu() *sync.Mutex { return &h.cfgMu }

// HandleAPI dispatches /api/* requests.
func (h *Handler) HandleAPI(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/")
	path = strings.TrimSuffix(path, "/")
	parts := strings.Split(path, "/")

	ctx := r.Context()
	switch {
	case len(parts) == 1 && parts[0] == "status" && r.Method == http.MethodGet:
		h.getStatus(w)
	case len(parts) == 1 && parts[0] == "logout" && r.Method == http.MethodPost:
		h.logout(w)
	case len(parts) == 1 && parts[0] == "stats" && r.Method == http.MethodGet:
		h.getStats(ctx, w)
	case len(parts) == 1 && parts[0] == "log" && r.Method == http.MethodGet:
		h.getLog(ctx, w, r)
	case len(parts) == 1 && parts[0] == "log" && r.Method == http.MethodDelete:
		h.clearLog(ctx, w)
	case len(parts) == 2 && parts[0] == "log" && parts[1] == "hostnames" && r.Method == http.MethodGet:
		h.logHostnames(w, r)
	case len(parts) == 2 && parts[0] == "log" && parts[1] == "asn" && r.Method == http.MethodGet:
		h.logASN(w, r)
	case len(parts) == 1 && parts[0] == "lists" && r.Method == http.MethodGet:
		h.getLists(w)
	case len(parts) == 1 && parts[0] == "lists" && r.Method == http.MethodPost:
		h.addList(w, r)
	case len(parts) == 2 && parts[0] == "lists" && r.Method == http.MethodPut:
		h.updateList(w, r, parts[1])
	case len(parts) == 2 && parts[0] == "lists" && r.Method == http.MethodDelete:
		h.deleteList(w, parts[1])
	case len(parts) == 2 && parts[0] == "lists" && parts[1] == "refresh" && r.Method == http.MethodPost:
		h.refreshAllLists(ctx, w)
	case len(parts) == 3 && parts[0] == "lists" && parts[2] == "fetch" && r.Method == http.MethodPost:
		h.refreshList(ctx, w, parts[1])
	case len(parts) == 3 && parts[0] == "lists" && parts[2] == "content" && r.Method == http.MethodGet:
		h.getListContent(w, parts[1])
	case len(parts) == 2 && parts[0] == "lists" && parts[1] == "catalog" && r.Method == http.MethodGet:
		h.getCatalog(w)
	case len(parts) == 2 && parts[0] == "filter" && parts[1] == "whitelist" && r.Method == http.MethodGet:
		h.getFilterList(w, "whitelist")
	case len(parts) == 2 && parts[0] == "filter" && parts[1] == "whitelist" && r.Method == http.MethodPost:
		h.addFilterEntry(w, r, "whitelist")
	case len(parts) == 2 && parts[0] == "filter" && parts[1] == "blacklist" && r.Method == http.MethodGet:
		h.getFilterList(w, "blacklist")
	case len(parts) == 2 && parts[0] == "filter" && parts[1] == "blacklist" && r.Method == http.MethodPost:
		h.addFilterEntry(w, r, "blacklist")
	case len(parts) == 2 && parts[0] == "filter" && parts[1] == "delete" && r.Method == http.MethodPost:
		h.deleteFilterEntry(w, r)
	case len(parts) == 2 && parts[0] == "filter" && parts[1] == "check" && r.Method == http.MethodPost:
		h.checkFilter(w, r)
	case len(parts) == 2 && parts[0] == "filter" && parts[1] == "site" && r.Method == http.MethodPost:
		h.siteCheck(ctx, w, r)
	case len(parts) == 2 && parts[0] == "tools" && parts[1] == "resolve" && r.Method == http.MethodPost:
		h.toolsResolve(ctx, w, r)
	case len(parts) == 2 && parts[0] == "tools" && parts[1] == "mail" && r.Method == http.MethodPost:
		h.toolsMail(ctx, w, r)
	case len(parts) == 2 && parts[0] == "tools" && parts[1] == "rbl" && r.Method == http.MethodPost:
		h.toolsRBL(ctx, w, r)
	case len(parts) == 2 && parts[0] == "tools" && parts[1] == "axfr" && r.Method == http.MethodPost:
		h.toolsAXFR(ctx, w, r)
	case len(parts) == 2 && parts[0] == "tools" && parts[1] == "subdomains" && r.Method == http.MethodPost:
		h.toolsSubdomains(ctx, w, r)
	case len(parts) == 2 && parts[0] == "tools" && parts[1] == "fastest" && r.Method == http.MethodPost:
		h.toolsFastest(ctx, w, r)
	case len(parts) == 2 && parts[0] == "cache" && parts[1] == "flush" && r.Method == http.MethodPost:
		h.flushCache(ctx, w)
	case len(parts) == 2 && parts[0] == "cache" && parts[1] == "warm" && r.Method == http.MethodPost:
		h.warmCache(w)
	case len(parts) == 2 && parts[0] == "tunnel" && parts[1] == "status" && r.Method == http.MethodGet:
		h.tunnelStatus(w)
	case len(parts) == 2 && parts[0] == "tunnel" && parts[1] == "start" && r.Method == http.MethodPost:
		h.tunnelStart(w, r)
	case len(parts) == 2 && parts[0] == "tunnel" && parts[1] == "stop" && r.Method == http.MethodPost:
		h.tunnelStop(w)
	case len(parts) == 2 && parts[0] == "tunnel" && parts[1] == "log" && r.Method == http.MethodGet:
		h.tunnelLog(w)
	case len(parts) == 2 && parts[0] == "tunnel" && parts[1] == "cloudflared-update" && r.Method == http.MethodPost:
		h.installCloudflaredUpdate(ctx, w)
	case len(parts) == 1 && parts[0] == "config" && r.Method == http.MethodGet:
		h.getConfig(w)
	case len(parts) == 1 && parts[0] == "config" && r.Method == http.MethodPut:
		h.putConfig(w, r)
	case len(parts) == 2 && parts[0] == "config" && parts[1] == "reload" && r.Method == http.MethodPost:
		h.reloadConfig(w)
	case len(parts) == 2 && parts[0] == "config" && parts[1] == "backup" && r.Method == http.MethodGet:
		h.backupConfig(w, r)
	case len(parts) == 2 && parts[0] == "config" && parts[1] == "restore" && r.Method == http.MethodPost:
		h.restoreConfig(w, r)
	case len(parts) == 2 && parts[0] == "diag" && parts[1] == "dns" && r.Method == http.MethodGet:
		h.diagDNS(ctx, w, r)
	case len(parts) == 2 && parts[0] == "update" && parts[1] == "check" && r.Method == http.MethodGet:
		h.checkUpdate(ctx, w)
	case len(parts) == 2 && parts[0] == "update" && parts[1] == "changelog" && r.Method == http.MethodGet:
		h.updateChangelog(ctx, w)
	case len(parts) == 2 && parts[0] == "update" && parts[1] == "install" && r.Method == http.MethodPost:
		h.installUpdate(ctx, w)
	case len(parts) == 1 && parts[0] == "tls" && r.Method == http.MethodGet:
		h.getTLS(w)
	case len(parts) == 2 && parts[0] == "tls" && parts[1] == "generate" && r.Method == http.MethodPost:
		h.generateTLS(w, r)
	case len(parts) == 2 && parts[0] == "tls" && parts[1] == "upload" && r.Method == http.MethodPost:
		h.uploadTLS(w, r)
	case len(parts) == 2 && parts[0] == "tls" && parts[1] == "cert" && r.Method == http.MethodGet:
		h.downloadCert(w)
	case len(parts) == 3 && parts[0] == "tls" && parts[1] == "acme" && parts[2] == "issue" && r.Method == http.MethodPost:
		h.issueACME(ctx, w)
	case len(parts) == 2 && parts[0] == "rate" && parts[1] == "blocked" && r.Method == http.MethodGet:
		h.rateBlocked(w)
	case len(parts) == 2 && parts[0] == "rate" && parts[1] == "unblock" && r.Method == http.MethodPost:
		h.rateUnblock(w, r)
	case len(parts) == 2 && parts[0] == "geo" && parts[1] == "status" && r.Method == http.MethodGet:
		h.geoStatus(w)
	case len(parts) == 2 && parts[0] == "geo" && parts[1] == "refresh" && r.Method == http.MethodPost:
		h.geoRefresh(w)
	case len(parts) == 2 && parts[0] == "geo" && parts[1] == "blocked" && r.Method == http.MethodGet:
		h.geoBlocked(w)
	case len(parts) == 2 && parts[0] == "geo" && parts[1] == "unblock" && r.Method == http.MethodPost:
		h.geoUnblock(w, r)
	case len(parts) == 2 && parts[0] == "geo" && parts[1] == "blockip" && r.Method == http.MethodPost:
		h.geoBlockIP(w, r)
	case len(parts) == 2 && parts[0] == "abuse" && parts[1] == "report" && r.Method == http.MethodPost:
		h.abuseReport(w, r)
	case len(parts) == 2 && parts[0] == "abuse" && parts[1] == "export" && r.Method == http.MethodGet:
		h.abuseExport(w)
	case len(parts) == 2 && parts[0] == "abuse" && parts[1] == "asn" && r.Method == http.MethodPost:
		h.abuseASN(w, r)
	case len(parts) == 2 && parts[0] == "dhcp" && parts[1] == "leases" && r.Method == http.MethodGet:
		h.dhcpLeases(w)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}
func (h *Handler) logout(w http.ResponseWriter) {
	h.cfgMu.Lock()
	secure := h.Cfg.Server.WebTLS
	h.cfgMu.Unlock()
	//nolint:gosec // G124: Secure mirrors the login cookie (plain-HTTP LAN mode).
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
	})
	writeJSON(w, http.StatusOK, map[string]string{"ok": "logged out"})
}

// sessionSecretFor returns the session secret to persist when applying a
// config: the existing secret unless a new plaintext password was supplied,
// in which case a fresh secret is generated so all previously issued session
// cookies stop validating (session rotation).
func sessionSecretFor(newPassword, currentSecret string) (string, error) {
	if newPassword == "" {
		return currentSecret, nil
	}
	return config.NewSessionSecret()
}

func contains(list []string, s string) bool {
	return slices.Contains(list, s)
}

func removeStr(list []string, s string) []string {
	out := list[:0]
	for _, v := range list {
		if v != s {
			out = append(out, v)
		}
	}
	return out
}
