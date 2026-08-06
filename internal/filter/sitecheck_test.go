package filter

import (
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestExtractSitePage(t *testing.T) {
	base, _ := url.Parse("https://example.com/shop/index.html")
	page := `<html><head>
		<title> Shop — Example </title>
		<link rel="stylesheet" href="//cdn2.example.net/site.css">
	</head><body>
		<style>.btn { background: url('/icons/btn.png'); border: 0 }</style>
		<script src="/app.js"></script>
		<script>
			fetch('/api/data');
			var x = new XMLHttpRequest();
			x.open('GET', '/api/items');
			importScripts('//worker.example.org/w.js');
		</script>
		<img src="logo.png">
		<img srcset="a.png 1x, https://img.example.org/b.png 2x">
		<a href="https://other.org/page">x</a>
		<a href="mailto:hi@example.com">mail</a>
		<a href="javascript:void(0)">js</a>
		<div style="background: url(https://bg.example.com/wall.jpg)"></div>
	</body></html>`

	domains, title := ExtractSitePage(strings.NewReader(page), base)

	if title != "Shop — Example" {
		t.Errorf("title = %q, want %q", title, "Shop — Example")
	}
	want := []string{
		"bg.example.com",     // inline style url() — absolute
		"cdn2.example.net",   // protocol-relative link href
		"example.com",        // page host + every relative URL
		"img.example.org",    // srcset absolute candidate
		"other.org",          // plain <a href>
		"worker.example.org", // importScripts() protocol-relative
	}
	if !reflect.DeepEqual(domains, want) {
		t.Errorf("domains = %v, want %v", domains, want)
	}
}

func TestExtractSitePageBaseHref(t *testing.T) {
	base, _ := url.Parse("https://example.com/page")
	page := `<html><head><base href="https://cdn.example.com/assets/"></head>
		<body>
			<script src="root.js"></script>
			<script src="/lib.js"></script>
			<img src="https://abs.example.org/i.png">
		</body></html>`

	domains, _ := ExtractSitePage(strings.NewReader(page), base)

	want := []string{
		"abs.example.org", // absolute ignores <base>
		"cdn.example.com", // relative + root-relative resolve against <base>
	}
	if !reflect.DeepEqual(domains, want) {
		t.Errorf("domains = %v, want %v", domains, want)
	}
}

func TestExtractSitePageJunk(t *testing.T) {
	base, _ := url.Parse("https://example.com/")

	// Garbage input must not panic and yields at most the page's own host.
	domains, title := ExtractSitePage(strings.NewReader("<html><script>'}{<?>"), base)
	if title != "" {
		t.Errorf("title = %q, want empty", title)
	}
	if !reflect.DeepEqual(domains, []string{"example.com"}) {
		t.Errorf("domains = %v, want just the page host", domains)
	}

	// Empty body: same.
	domains, _ = ExtractSitePage(strings.NewReader(""), base)
	if !reflect.DeepEqual(domains, []string{"example.com"}) {
		t.Errorf("empty page domains = %v, want just the page host", domains)
	}
}
