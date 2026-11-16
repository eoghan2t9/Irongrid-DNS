package vpn

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Runner abstracts process execution so tests can record the exact commands
// this package issues without touching real network interfaces or a real
// firewall. Mirrors internal/firewall's Runner.
type Runner interface {
	LookPath(name string) (string, error)
	Run(name string, args ...string) error
	RunStdin(name string, args []string, stdin []byte) error
}

type execRunner struct{}

func (execRunner) LookPath(name string) (string, error) { return exec.LookPath(name) }

const execTimeout = 30 * time.Second

func (execRunner) Run(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func (execRunner) RunStdin(name string, args []string, stdin []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}
