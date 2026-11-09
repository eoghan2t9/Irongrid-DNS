package dnsname

import (
	"math/rand"
	"strings"
	"testing"
)

// refCanonical is the original implementation, kept verbatim as the oracle the
// fast path must agree with on every input.
func refCanonical(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}

var canonicalCases = []string{
	"", ".", "..", "a", "A", "example.com", "Example.COM", "example.com.",
	"example.com..", " example.com", "example.com ", "\texample.com\n",
	"  Example.Com.  ", "a b.com", "ex ample.com.", "xn--bcher-kva.example",
	"BÜCHER.example", "bücher.example.", " example.com", "example.com ",
	"\u0085example.com", "EXAMPLEK.com", "a\x00b.com", "-", "_dmarc.example.com",
	"*.example.com", "1.2.3.4", "::1", "\v\f\r.", " . ", "A.", ".A",
}

func TestCanonicalDomainMatchesReference(t *testing.T) {
	for _, in := range canonicalCases {
		if got, want := CanonicalDomain(in), refCanonical(in); got != want {
			t.Errorf("CanonicalDomain(%q) = %q, want %q", in, got, want)
		}
	}
	// Random byte soup biased towards the characters the function cares about.
	alphabet := []byte("abcXYZ019-_. \t\n\v\f\r\x00\x7f\x80\xc3\x9c\xa0\x85")
	rng := rand.New(rand.NewSource(1))
	for range 200000 {
		b := make([]byte, rng.Intn(12))
		for i := range b {
			b[i] = alphabet[rng.Intn(len(alphabet))]
		}
		in := string(b)
		if got, want := CanonicalDomain(in), refCanonical(in); got != want {
			t.Fatalf("CanonicalDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestIsCanonicalImpliesIdentity: whenever the fast-path predicate says a
// string is canonical, the reference must leave it untouched. (The converse
// need not hold — non-canonical is merely "take the slow path".)
func TestIsCanonicalImpliesIdentity(t *testing.T) {
	for _, in := range canonicalCases {
		if IsCanonical(in) && refCanonical(in) != in {
			t.Errorf("IsCanonical(%q) is true but canonicalization changes it to %q", in, refCanonical(in))
		}
	}
	for _, in := range []string{"example.com", "a", "", "sub.example.co.uk", "_dmarc.example.com", "1.2.3.4"} {
		if !IsCanonical(in) {
			t.Errorf("IsCanonical(%q) = false, want true", in)
		}
	}
	for _, in := range []string{"Example.com", "example.com.", " example.com", "example.com ", "bücher.example", "."} {
		if IsCanonical(in) {
			t.Errorf("IsCanonical(%q) = true, want false", in)
		}
	}
}

func TestCanonicalDomainFastPathNoAllocs(t *testing.T) {
	const name = "www.example.com"
	if n := testing.AllocsPerRun(1000, func() { _ = CanonicalDomain(name) }); n != 0 {
		t.Fatalf("CanonicalDomain on a canonical name allocated %v times, want 0", n)
	}
}

func BenchmarkCanonicalDomain(b *testing.B) {
	for _, in := range []string{"www.example.com", "WWW.Example.COM.", "tracking.pixel.analytics.example.co.uk"} {
		b.Run(in, func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				_ = CanonicalDomain(in)
			}
		})
	}
}
