package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/eoghan2t9/Irongrid-DNS/internal/update"
	"github.com/eoghan2t9/Irongrid-DNS/internal/version"
)

// ---- updates ----

// checkUpdate queries GitHub Releases for a newer version. Failures (offline,
// rate limit, no releases yet) are folded into the payload as a non-empty
// "error" field so the UI can degrade quietly.
func (h *Handler) checkUpdate(ctx context.Context, w http.ResponseWriter) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cur := h.Version
	if cur == "" {
		cur = version.Version
	}
	client := &update.Client{Repo: update.DefaultRepo, Current: cur}
	writeJSON(w, http.StatusOK, client.Check(ctx))
}

// updateChangelog returns the recent stable releases for the in-app
// changelog page. Failures are folded into an error field (the page shows a
// quiet notice) rather than an HTTP error.
func (h *Handler) updateChangelog(ctx context.Context, w http.ResponseWriter) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cur := h.Version
	if cur == "" {
		cur = version.Version
	}
	client := &update.Client{Repo: update.DefaultRepo, Current: cur}
	releases, err := client.List(ctx)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"current_version": cur,
			"error":           err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"current_version": cur,
		"releases":        releases,
	})
}

// installUpdateMu serialises in-place updates so two tabs can't race.
var installUpdateMu sync.Mutex

// installUpdate downloads the release asset for this platform, verifies it
// against SHA256SUMS.txt, atomically swaps the running binary and — when the
// service is systemd-managed — schedules a restart via a detached systemd-run
// transient unit, so the restart outlives this process and the HTTP response
// is guaranteed to flush first.
func (h *Handler) installUpdate(ctx context.Context, w http.ResponseWriter) {
	installUpdateMu.Lock()
	defer installUpdateMu.Unlock()

	// h.Version is the version the process started with. Once a swap has
	// happened it is stale, so refuse a second install until the restart —
	// this also preserves the .prev rollback copy from being overwritten.
	// lastInstalledVersion is a GitHub release tag ("v1.4.1"), already
	// v-prefixed — do not add a second one.
	if h.lastInstalledVersion != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("%s was already installed and is pending a restart", h.lastInstalledVersion),
		})
		return
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	// The web server's http.Server has a 30s WriteTimeout (sane for every
	// other endpoint), fixed at connection-accept time before this handler
	// even starts. A download + checksum verify + binary swap can easily run
	// past that on a slow link, so the connection would get killed out from
	// under a perfectly successful install — the browser reports "Failed to
	// fetch" with no clue the server kept working. Push the deadline out
	// past the context timeout above so our own error responses win instead.
	// (SetWriteDeadline no-ops with http.ErrNotSupported if the underlying
	// writer doesn't support it — never possible here, but safe either way.)
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(6 * time.Minute))

	cur := h.Version
	if cur == "" {
		cur = version.Version
	}
	client := &update.Client{Repo: update.DefaultRepo, Current: cur}
	res, err := client.Install(ctx, "")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	payload := map[string]any{
		"previous_version": res.PreviousVersion,
		"new_version":      res.NewVersion,
		"installed_to":     res.InstalledTo,
		"rollback_path":    res.InstalledTo + ".prev",
		"asset_name":       res.AssetName,
		"asset_size":       res.AssetSize,
	}

	// Only claim (and guard) a restart when it can actually happen: systemd
	// must be running, systemd-run on PATH, and the systemd-run invocation
	// itself (which just registers a timer unit and returns — the actual
	// restart still happens on its own detached unit after a short delay,
	// independent of this process) has to actually succeed. Run it
	// synchronously so a registration failure (e.g. a stale same-named unit
	// left over from a previous attempt) is caught here instead of only
	// logged from an unobserved goroutine — the previous fire-and-forget
	// version set lastInstalledVersion unconditionally, so a failed
	// registration permanently wedged every future install behind a
	// "pending restart" that would never happen. --collect auto-unloads the
	// transient unit on completion (success or failure) so a retry never
	// collides with a leftover unit from an earlier attempt. The swap
	// itself is safe to retry regardless — a repeated install simply
	// re-downloads and re-verifies.
	unit := update.UnitName()
	_, systemdRunOK := exec.LookPath("systemd-run")
	restartable := unit != "" && systemdRunOK == nil
	if restartable {
		if _, err := os.Stat("/run/systemd/system"); err != nil {
			restartable = false
		}
	}
	if restartable {
		// Half a second is enough for the small JSON response below to flush,
		// while avoiding the old 1s timer plus 1.5s dashboard polling cadence.
		cmd := exec.Command("systemd-run", "--unit=irongrid-update", "--collect", "--on-active=500ms", "systemctl", "restart", unit)
		if out, err := cmd.CombinedOutput(); err != nil {
			slog.Error("update schedule restart failed", "error", err, "output", string(out))
			payload["restarting"] = false
			payload["note"] = "Binary updated, but scheduling the restart failed. Restart Irongrid manually to run the new version."
		} else {
			h.lastInstalledVersion = res.NewVersion
			payload["restarting"] = true
			payload["unit"] = unit
		}
	} else {
		payload["restarting"] = false
		payload["note"] = "Binary updated. Restart Irongrid manually to run the new version."
	}
	writeJSON(w, http.StatusOK, payload)
}

func (h *Handler) diagDNS(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSuffix(r.URL.Query().Get("name"), ".")
	qtype := r.URL.Query().Get("type")
	if qtype == "" {
		qtype = "A"
	}
	t, ok := dns.StringToType[strings.ToUpper(qtype)]
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad qtype"})
		return
	}
	q := dns.Question{Name: dns.Fqdn(name), Qtype: t, Qclass: dns.ClassINET}
	msg := new(dns.Msg)
	msg.SetQuestion(q.Name, q.Qtype)
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	h.cfgMu.Lock()
	ups := slices.Clone(h.Upstreams)
	h.cfgMu.Unlock()
	var lastErr error
	for _, up := range ups {
		resp, err := up.Query(cctx, msg)
		if err == nil {
			answers := make([]string, 0, len(resp.Answer))
			for _, rr := range resp.Answer {
				answers = append(answers, rr.String())
			}
			blockedByIP, reason := h.Engine.CheckIPs(extractIPs(resp))
			writeJSON(w, http.StatusOK, map[string]any{
				"domain": name, "type": qtype, "upstream": up.Name(),
				"rcode": resp.Rcode, "answers": answers,
				"blocked_by_ip": blockedByIP, "reason": reason,
			})
			return
		}
		lastErr = err
	}
	// No upstreams configured (or all failed): report cleanly. The config
	// validator requires at least one upstream, so this is unreachable in a
	// normal boot — but a nil deref on lastErr is never acceptable.
	if lastErr == nil {
		lastErr = errors.New("no upstreams configured")
	}
	writeJSON(w, http.StatusInternalServerError, map[string]any{"error": lastErr.Error()})
}

func extractIPs(m *dns.Msg) []net.IP {
	var ips []net.IP
	if m == nil {
		return ips
	}
	for _, rr := range m.Answer {
		switch v := rr.(type) {
		case *dns.A:
			ips = append(ips, v.A)
		case *dns.AAAA:
			ips = append(ips, v.AAAA)
		}
	}
	return ips
}

// logout clears the signed session cookie in the browser. The cookie is
// stateless (HMAC-signed), so expiring it client-side is all the server
// needs to do — no server-side session store exists.
