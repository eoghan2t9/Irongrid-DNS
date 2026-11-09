package filter

import (
	"math/rand"
	"strings"
	"testing"

	"golang.org/x/net/idna"
)

// refNormalizeDomain is the original normalizeDomain, kept verbatim as the
// oracle the canonical-name fast path must agree with on every input.
func refNormalizeDomain(d string) string {
	d = strings.TrimSpace(d)
	d = strings.TrimSuffix(d, ".")
	d = strings.ToLower(d)
	if !isASCII(d) {
		if ascii, err := idna.Lookup.ToASCII(d); err == nil {
			d = ascii
		}
	}
	return d
}

func TestNormalizeDomainMatchesReference(t *testing.T) {
	cases := []string{
		"", ".", "..", "a", "A", "example.com", "Example.COM", "example.com.",
		"example.com..", " example.com", "example.com ", "\texample.com\n",
		"  Example.Com.  ", "a b.com", "xn--bcher-kva.example", "BÜCHER.example",
		"bücher.example.", " example.com", "例え.jp", "例え.jp.", "EXAMPLEK.com",
		"a\x00b.com", "_dmarc.example.com", "*.example.com", "1.2.3.4", "\v\f\r.",
		"tracking.pixel.analytics.example.co.uk",
	}
	for _, in := range cases {
		if got, want := normalizeDomain(in), refNormalizeDomain(in); got != want {
			t.Errorf("normalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}
	alphabet := []byte("abcXYZ019-_. \t\n\v\f\r\x00\x7f\x80\xc3\x9c\xa0\x85")
	rng := rand.New(rand.NewSource(2))
	for range 200000 {
		b := make([]byte, rng.Intn(12))
		for i := range b {
			b[i] = alphabet[rng.Intn(len(alphabet))]
		}
		in := string(b)
		if got, want := normalizeDomain(in), refNormalizeDomain(in); got != want {
			t.Fatalf("normalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeDomainFastPathNoAllocs(t *testing.T) {
	const name = "www.example.com"
	if n := testing.AllocsPerRun(1000, func() { _ = normalizeDomain(name) }); n != 0 {
		t.Fatalf("normalizeDomain on a canonical name allocated %v times, want 0", n)
	}
}
