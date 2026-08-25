package api

import (
	"testing"
	"time"
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
