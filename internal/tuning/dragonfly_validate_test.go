package tuning

import "testing"

func TestParseMemoryString(t *testing.T) {
	cases := []struct {
		input string
		want  uint64
	}{
		{"512mb", 512 << 20},
		{"2917mb", 2917 << 20},
		{"1gb", 1 << 30},
		{"2gb", 2 << 30},
		{"16gb", 16 << 30},
		{"2048", 2048},
		{"  2gb  ", 2 << 30},
	}
	for _, c := range cases {
		if got := parseMemoryString(c.input); got != c.want {
			t.Errorf("parseMemoryString(%q) = %d, want %d", c.input, got, c.want)
		}
	}
}

func TestSplitArgs(t *testing.T) {
	cases := []struct {
		input string
		want  []string
	}{
		{
			"--port=6379 --bind=127.0.0.1 --cache_mode=true",
			[]string{"--port=6379", "--bind=127.0.0.1", "--cache_mode=true"},
		},
		{
			`--port=6379 "--snapshot_cron=0 * * * *" --dbfilename=irongrid-dump`,
			[]string{"--port=6379", "--snapshot_cron=0 * * * *", "--dbfilename=irongrid-dump"},
		},
		{
			"--maxmemory=512mb --proactor_threads=2",
			[]string{"--maxmemory=512mb", "--proactor_threads=2"},
		},
		{"", nil},
	}
	for _, c := range cases {
		got := splitArgs(c.input)
		if len(got) != len(c.want) {
			t.Errorf("splitArgs(%q) returned %d args, want %d: %v", c.input, len(got), len(c.want), got)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("splitArgs(%q)[%d] = %q, want %q", c.input, i, got[i], c.want[i])
			}
		}
	}
}

func TestUpdateDflyArgs(t *testing.T) {
	flags := DragonflyFlags{MaxMemory: "4gb", ProactorThreads: 8}

	cases := []struct {
		name    string
		oldArgs string
		want    string
	}{
		{
			name:    "replace existing flags",
			oldArgs: "--port=6379 --bind=127.0.0.1 --cache_mode=true --maxmemory=512mb --proactor_threads=2 --dir=/data",
			want:    "--port=6379 --bind=127.0.0.1 --cache_mode=true --maxmemory=4gb --proactor_threads=8 --dir=/data",
		},
		{
			name:    "add missing flags",
			oldArgs: "--port=6379 --bind=127.0.0.1 --cache_mode=true --dir=/data",
			want:    "--port=6379 --bind=127.0.0.1 --cache_mode=true --dir=/data --maxmemory=4gb --proactor_threads=8",
		},
		{
			name:    "with quoted snapshot_cron",
			oldArgs: `--port=6379 --maxmemory=512mb "--snapshot_cron=0 * * * *" --proactor_threads=2`,
			want:    `--port=6379 --maxmemory=4gb "--snapshot_cron=0 * * * *" --proactor_threads=8`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := updateDflyArgs(c.oldArgs, flags)
			if got != c.want {
				t.Errorf("updateDflyArgs(%q) =\n  %q\nwant:\n  %q", c.oldArgs, got, c.want)
			}
		})
	}
}

func TestParseExecStart(t *testing.T) {
	content := `[Unit]
Description=DragonflyDB

[Service]
ExecStart=/usr/local/bin/dragonfly --port=6379 --maxmemory=512mb --proactor_threads=2
Restart=on-failure
`
	base, args := parseExecStart(content)
	if base != "/usr/local/bin/dragonfly" {
		t.Errorf("basePath = %q, want /usr/local/bin/dragonfly", base)
	}
	if args != "--port=6379 --maxmemory=512mb --proactor_threads=2" {
		t.Errorf("args = %q, want --port=6379 --maxmemory=512mb --proactor_threads=2", args)
	}
}

func TestFormatBytesV(t *testing.T) {
	cases := []struct {
		b    uint64
		want string
	}{
		{512 << 20, "512MiB"},
		{1 << 30, "1.0GiB"},
		{2917 << 20, "2.9GiB"},
		{16 << 30, "16.0GiB"},
	}
	for _, c := range cases {
		if got := formatBytesV(c.b); got != c.want {
			t.Errorf("formatBytesV(%d) = %q, want %q", c.b, got, c.want)
		}
	}
}
