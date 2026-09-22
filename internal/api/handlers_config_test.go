package api

import (
	"testing"

	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
)

func TestResolveWebUsersEditKeepsHashWhenPasswordBlank(t *testing.T) {
	t.Parallel()
	existing := []config.WebUser{{ID: "1", Username: "admin", Password: "$2a$hash", Role: "admin"}}
	incoming := []userPayload{{ID: "1", Username: "admin", Password: "", Role: "admin"}}
	users, err := resolveWebUsers(existing, incoming)
	if err != nil {
		t.Fatalf("resolveWebUsers: %v", err)
	}
	if len(users) != 1 || users[0].Password != "$2a$hash" {
		t.Fatalf("expected existing hash kept, got %+v", users)
	}
}

func TestResolveWebUsersEditWithNewPasswordReplacesHash(t *testing.T) {
	t.Parallel()
	existing := []config.WebUser{{ID: "1", Username: "admin", Password: "$2a$hash", Role: "admin"}}
	incoming := []userPayload{{ID: "1", Username: "admin", Password: "new-plaintext", Role: "admin"}}
	users, err := resolveWebUsers(existing, incoming)
	if err != nil {
		t.Fatalf("resolveWebUsers: %v", err)
	}
	if users[0].Password != "new-plaintext" {
		t.Fatalf("expected new plaintext password to replace the hash (hashed later by Config.Save), got %q", users[0].Password)
	}
}

func TestResolveWebUsersNewUserRequiresPassword(t *testing.T) {
	t.Parallel()
	incoming := []userPayload{{ID: "", Username: "newbie", Password: "", Role: "viewer"}}
	if _, err := resolveWebUsers(nil, incoming); err == nil {
		t.Fatal("new user with no password accepted")
	}
}

func TestResolveWebUsersNewUserGetsGeneratedID(t *testing.T) {
	t.Parallel()
	incoming := []userPayload{{ID: "", Username: "newbie", Password: "hunter2", Role: "viewer"}}
	users, err := resolveWebUsers(nil, incoming)
	if err != nil {
		t.Fatalf("resolveWebUsers: %v", err)
	}
	if len(users) != 1 || users[0].ID == "" {
		t.Fatalf("expected a generated id, got %+v", users)
	}
}

// TestResolveWebUsersUnknownIDTreatedAsNew verifies an id that doesn't match
// any existing user (e.g. a stale/tampered client payload) is treated as a
// new user rather than silently adopting an existing password.
func TestResolveWebUsersUnknownIDTreatedAsNew(t *testing.T) {
	t.Parallel()
	existing := []config.WebUser{{ID: "1", Username: "admin", Password: "$2a$hash", Role: "admin"}}
	incoming := []userPayload{{ID: "does-not-exist", Username: "sneaky", Password: "", Role: "admin"}}
	if _, err := resolveWebUsers(existing, incoming); err == nil {
		t.Fatal("unknown id with no password should require a password like any new user")
	}
}

func TestRotateSecretIfUsersChangedKeepsSecretWhenUnchanged(t *testing.T) {
	t.Parallel()
	users := []config.WebUser{{ID: "1", Username: "admin", Password: "$2a$hash", Role: "admin"}}
	const current = "0123456789abcdef0123456789abcdef"
	secret, err := rotateSecretIfUsersChanged(users, users, current)
	if err != nil {
		t.Fatalf("rotateSecretIfUsersChanged: %v", err)
	}
	if secret != current {
		t.Fatalf("expected secret to be kept when Users is unchanged, got %q", secret)
	}
}

func TestRotateSecretIfUsersChangedRotatesOnChange(t *testing.T) {
	t.Parallel()
	oldUsers := []config.WebUser{{ID: "1", Username: "admin", Password: "$2a$hash", Role: "admin"}}
	newUsers := []config.WebUser{{ID: "1", Username: "admin", Password: "$2a$newhash", Role: "admin"}}
	const current = "0123456789abcdef0123456789abcdef"
	secret, err := rotateSecretIfUsersChanged(oldUsers, newUsers, current)
	if err != nil {
		t.Fatalf("rotateSecretIfUsersChanged: %v", err)
	}
	if secret == "" || secret == current {
		t.Fatalf("expected a freshly rotated secret, got %q", secret)
	}
}

// TestPayloadFromConfigNeverReturnsUserPasswords verifies GET /api/config
// never leaks a user's password hash, mirroring the old single web.password
// field's "empty unless the user wants to change it" convention.
func TestPayloadFromConfigNeverReturnsUserPasswords(t *testing.T) {
	t.Parallel()
	c := &config.Config{
		Web: config.WebConfig{
			Users: []config.WebUser{
				{ID: "1", Username: "admin", Password: "$2a$supersecrethash", Role: "admin"},
				{ID: "2", Username: "viewer1", Password: "$2a$anotherhash", Role: "viewer"},
			},
		},
	}
	p := payloadFromConfig(c)
	if len(p.Web.Users) != 2 {
		t.Fatalf("expected 2 users in payload, got %d", len(p.Web.Users))
	}
	for _, u := range p.Web.Users {
		if u.Password != "" {
			t.Errorf("user %q: password leaked in payload: %q", u.Username, u.Password)
		}
	}
}
