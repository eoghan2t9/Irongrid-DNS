package installer

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeHost records the commands removeLegacyDragonfly runs and answers
// `docker inspect` from a name -> image table.
type fakeHost struct {
	cmds   []string
	images map[string]string // container name -> image
	docker bool
}

func (f *fakeHost) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.cmds = append(f.cmds, name+" "+strings.Join(args, " "))
	if name == "docker" && len(args) >= 4 && args[0] == "inspect" {
		img, ok := f.images[args[3]]
		if !ok {
			return nil, errors.New("no such container")
		}
		return []byte(img + "\n"), nil
	}
	return nil, nil
}

func (f *fakeHost) lookPath(string) (string, error) {
	if f.docker {
		return "/usr/bin/docker", nil
	}
	return "", errors.New("not found")
}

func (f *fakeHost) ran(prefix string) bool {
	for _, c := range f.cmds {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func legacyFixture(t *testing.T, unitBody string) (legacyEnv, *fakeHost) {
	t.Helper()
	dir := t.TempDir()
	env := legacyEnv{
		unitPath: filepath.Join(dir, "dragonfly.service"),
		binaries: []string{filepath.Join(dir, "dragonfly"), filepath.Join(dir, "dragonfly.prev")},
		isRoot:   true,
	}
	for _, b := range env.binaries {
		if err := os.WriteFile(b, []byte("bin"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if unitBody != "" {
		if err := os.WriteFile(env.unitPath, []byte(unitBody), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	host := &fakeHost{}
	env.run, env.lookPath = host.run, host.lookPath
	return env, host
}

const ourUnit = "[Unit]\nDescription=" + legacyUnitMarker + "\n\n[Service]\nExecStart=/usr/local/bin/dragonfly --port=6379\n"

func TestRemoveLegacyDragonflyOurUnit(t *testing.T) {
	t.Parallel()
	env, host := legacyFixture(t, ourUnit)
	var out bytes.Buffer
	removeLegacyDragonfly(env, &out)

	if _, err := os.Stat(env.unitPath); !os.IsNotExist(err) {
		t.Errorf("unit file should be removed, stat err = %v", err)
	}
	for _, b := range env.binaries {
		if _, err := os.Stat(b); !os.IsNotExist(err) {
			t.Errorf("binary %s should be removed, stat err = %v", b, err)
		}
	}
	for _, want := range []string{"systemctl disable --now dragonfly.service", "systemctl daemon-reload"} {
		if !host.ran(want) {
			t.Errorf("expected command %q, ran %v", want, host.cmds)
		}
	}
	if !strings.Contains(out.String(), "Removed the old Dragonfly cache") {
		t.Errorf("expected a removal summary, got:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "not migrated") {
		t.Errorf("summary must say the old data is left and not migrated:\n%s", out.String())
	}
}

// A dragonfly.service that is NOT the one Irongrid's installer wrote belongs to
// the operator and must never be touched.
func TestRemoveLegacyDragonflyLeavesForeignUnit(t *testing.T) {
	t.Parallel()
	env, host := legacyFixture(t, "[Unit]\nDescription=my own dragonfly\n")
	var out bytes.Buffer
	removeLegacyDragonfly(env, &out)

	if _, err := os.Stat(env.unitPath); err != nil {
		t.Errorf("foreign unit must be left alone: %v", err)
	}
	for _, b := range env.binaries {
		if _, err := os.Stat(b); err != nil {
			t.Errorf("binary %s must be left alone: %v", b, err)
		}
	}
	if len(host.cmds) != 0 {
		t.Errorf("no commands should run for a foreign unit, ran %v", host.cmds)
	}
	if out.Len() != 0 {
		t.Errorf("expected no output, got:\n%s", out.String())
	}
}

func TestRemoveLegacyDragonflyNeedsRoot(t *testing.T) {
	t.Parallel()
	env, host := legacyFixture(t, ourUnit)
	env.isRoot = false
	var out bytes.Buffer
	removeLegacyDragonfly(env, &out)

	if _, err := os.Stat(env.unitPath); err != nil {
		t.Errorf("without root the unit must not be removed: %v", err)
	}
	if host.ran("systemctl") {
		t.Errorf("without root no systemctl should run, ran %v", host.cmds)
	}
	if !strings.Contains(out.String(), "needs root") || !strings.Contains(out.String(), "sudo systemctl disable --now dragonfly.service") {
		t.Errorf("expected manual root instructions, got:\n%s", out.String())
	}
}

func TestRemoveLegacyDragonflyContainers(t *testing.T) {
	t.Parallel()
	env, host := legacyFixture(t, "")
	host.docker = true
	host.images = map[string]string{
		"irongrid-dragonfly": "docker.dragonflydb.io/dragonfly/dragonfly",
		"dragonfly":          "someone/other-thing:latest", // same name, not a Dragonfly image
	}
	var out bytes.Buffer
	removeLegacyDragonfly(env, &out)

	if !host.ran("docker rm -f irongrid-dragonfly") {
		t.Errorf("the compose container should be removed, ran %v", host.cmds)
	}
	if host.ran("docker rm -f dragonfly") {
		t.Errorf("a container whose image is not Dragonfly must be left alone, ran %v", host.cmds)
	}
	if !strings.Contains(out.String(), "container irongrid-dragonfly") {
		t.Errorf("summary should list the container, got:\n%s", out.String())
	}
}

func TestRemoveLegacyDragonflyNothingToDo(t *testing.T) {
	t.Parallel()
	env, host := legacyFixture(t, "")
	var out bytes.Buffer
	removeLegacyDragonfly(env, &out)
	if out.Len() != 0 {
		t.Errorf("a clean host should produce no output, got:\n%s", out.String())
	}
	if len(host.cmds) != 0 {
		t.Errorf("a clean host should run no commands, ran %v", host.cmds)
	}
}
