package tuning

import "testing"

func TestParseMemoryString(t *testing.T) {
	t.Parallel()
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

func TestFormatBytesV(t *testing.T) {
	t.Parallel()
	cases := []struct {
		b    uint64
		want string
	}{
		{512 << 20, "512MiB"},
		{1 << 30, "1.0GiB"},
		{2917 << 20, "2.8GiB"},
		{16 << 30, "16.0GiB"},
	}
	for _, c := range cases {
		if got := formatBytesV(c.b); got != c.want {
			t.Errorf("formatBytesV(%d) = %q, want %q", c.b, got, c.want)
		}
	}
}
