package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// TestInstallUpdatePendingMessageNoDoubleV is a regression test for a typo
// bug: lastInstalledVersion is a GitHub release tag ("v1.4.1", already
// v-prefixed), but the guard message used to prepend a second "v", showing
// "vv1.4.1 was already installed and is pending a restart".
func TestInstallUpdatePendingMessageNoDoubleV(t *testing.T) {
	h := &Handler{lastInstalledVersion: "v1.4.1"}
	w := httptest.NewRecorder()
	h.installUpdate(t.Context(), w)

	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	const want = "v1.4.1 was already installed and is pending a restart"
	if body["error"] != want {
		t.Errorf("error = %q, want %q", body["error"], want)
	}
}
