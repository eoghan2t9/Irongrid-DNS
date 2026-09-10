package main

import (
	"log/slog"
	"testing"

	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
)

func TestNewLoggerLevels(t *testing.T) {
	tests := []struct {
		level         string
		wantDebug     bool
		wantInfo      bool
		wantWarnError bool
	}{
		{"debug", true, true, true},
		{"", false, true, true}, // default: info
		{"info", false, true, true},
		{"warn", false, false, true},
		{"warning", false, false, true},
		{"error", false, false, true},
		{"ERROR", false, false, true}, // case-insensitive
	}
	for _, tt := range tests {
		l := newLogger(config.LoggingConfig{Level: tt.level})
		if got := l.Enabled(nil, slog.LevelDebug); got != tt.wantDebug {
			t.Errorf("level %q: debug enabled = %v, want %v", tt.level, got, tt.wantDebug)
		}
		if got := l.Enabled(nil, slog.LevelInfo); got != tt.wantInfo {
			t.Errorf("level %q: info enabled = %v, want %v", tt.level, got, tt.wantInfo)
		}
		if got := l.Enabled(nil, slog.LevelError); got != tt.wantWarnError {
			t.Errorf("level %q: error enabled = %v, want %v", tt.level, got, tt.wantWarnError)
		}
	}
}

func TestNewLoggerJSONHandlerType(t *testing.T) {
	if _, ok := newLogger(config.LoggingConfig{JSON: true}).Handler().(*slog.JSONHandler); !ok {
		t.Fatalf("logging.json=true should produce a *slog.JSONHandler, got %T", newLogger(config.LoggingConfig{JSON: true}).Handler())
	}
	if _, ok := newLogger(config.LoggingConfig{}).Handler().(*slog.TextHandler); !ok {
		t.Fatalf("default logging should produce a *slog.TextHandler, got %T", newLogger(config.LoggingConfig{}).Handler())
	}
}
