package api

import (
	"testing"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
)

// TestDurationOrEmptyMatchesDropdownPresets guards against a real bug: the
// frontend's blocklist auto-update <select> matches its value by exact
// string against hour-based presets ("6h"/"24h"/"168h"). Go's default
// Duration.String() for whole-hour values is "24h0m0s", not "24h" — which
// never matches any <option>, so the select silently falls back to its
// first option ("Never") even though the value round-tripped and saved
// correctly. durationOrEmpty must emit the compact form for every preset
// the UI offers.
func TestDurationOrEmptyMatchesDropdownPresets(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   time.Duration
		want string
	}{
		{0, ""},
		{-time.Hour, ""},
		{6 * time.Hour, "6h"},
		{24 * time.Hour, "24h"},
		{168 * time.Hour, "168h"},
	}
	for _, c := range cases {
		if got := durationOrEmpty(c.in); got != c.want {
			t.Errorf("durationOrEmpty(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestDurationOrEmptyNonHourAligned verifies a non-hour-aligned duration
// (not offered by the dropdown, but still a legal manually-edited config
// value) still round-trips through Go's standard format rather than
// panicking or truncating.
func TestDurationOrEmptyNonHourAligned(t *testing.T) {
	t.Parallel()
	got := durationOrEmpty(90 * time.Minute)
	want := (90 * time.Minute).String()
	if got != want {
		t.Errorf("durationOrEmpty(90m) = %q, want %q", got, want)
	}
}

// TestPayloadFromConfigIncludesVPN guards against a real bug: vpn.* was
// added to config.Config but never wired into configPayload/
// payloadFromConfig, so GET /api/config silently omitted the whole vpn
// section (including provider credentials) — the dashboard's "Save & apply"
// then round-tripped an empty vpn block straight back over whatever was on
// disk, making a saved NordVPN token disappear on the very next load.
func TestPayloadFromConfigIncludesVPN(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{
		VPN: config.VPNConfig{
			Enabled: true,
			Providers: config.VPNProviders{
				NordVPN: config.NordVPNCreds{Token: "nord-token-123"},
				PIA:     config.PIACreds{Username: "pia-user", Password: "pia-pass"},
			},
			Profiles: []config.VPNProfile{
				{ID: "uk-iplayer", Provider: "pia", Region: "uk_london"},
			},
			Routes: []config.VPNRoute{
				{Profile: "uk-iplayer", Domains: []string{"bbc.co.uk", "bbci.co.uk"}},
			},
		},
	}

	got := payloadFromConfig(cfg)

	if !got.VPN.Enabled {
		t.Error("VPN.Enabled dropped by payloadFromConfig")
	}
	if got.VPN.Providers.NordVPN.Token != "nord-token-123" {
		t.Errorf("NordVPN token = %q, want %q", got.VPN.Providers.NordVPN.Token, "nord-token-123")
	}
	if got.VPN.Providers.PIA.Username != "pia-user" || got.VPN.Providers.PIA.Password != "pia-pass" {
		t.Errorf("PIA creds = %+v, want username=pia-user password=pia-pass", got.VPN.Providers.PIA)
	}
	if len(got.VPN.Profiles) != 1 || got.VPN.Profiles[0].ID != "uk-iplayer" {
		t.Errorf("Profiles = %+v, want one profile uk-iplayer", got.VPN.Profiles)
	}
	if len(got.VPN.Routes) != 1 || len(got.VPN.Routes[0].Domains) != 2 {
		t.Errorf("Routes = %+v, want one route with 2 domains", got.VPN.Routes)
	}
}
