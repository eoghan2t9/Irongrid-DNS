package api

import (
	"net"
	"testing"

	"github.com/eoghan2t9/Irongrid-DNS/internal/dhcp"
)

// TestResolveHostnamePrefersDHCPLease verifies a client holding a DHCP
// reservation is named from the lease table without any upstream PTR query:
// the handler has no upstreams, so an upstream lookup could not produce it.
func TestResolveHostnamePrefersDHCPLease(t *testing.T) {
	t.Parallel()
	s := dhcp.New(t.TempDir())
	s.SetConfig(dhcp.Config{
		Domain: "lan",
		Static: []dhcp.StaticLease{{MAC: "aa:bb:cc:dd:ee:08", IP: net.ParseIP("192.168.1.77"), Hostname: "nas"}},
	})
	h := &Handler{DHCP: s}

	if got := h.resolveHostname(t.Context(), "192.168.1.77"); got != "nas.lan" {
		t.Fatalf("resolveHostname = %q, want nas.lan", got)
	}
}
