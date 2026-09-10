package main

import (
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
)

// newLogger builds the application slog.Logger from logging.level /
// logging.json. Text output at info level (lc's zero value) matches the
// server's historical behavior, so this is safe to call before config.Load
// too (with an empty config.LoggingConfig{}).
func newLogger(lc config.LoggingConfig) *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(strings.TrimSpace(lc.Level)) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{
		Level: level,
		// UTC timestamps, matching the previous log.LUTC flag — the box
		// running this may be in any timezone, but log lines should compare
		// cleanly across a multi-instance deployment.
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				a.Value = slog.StringValue(a.Value.Time().UTC().Format(time.RFC3339))
			}
			return a
		},
	}
	if lc.JSON {
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}
