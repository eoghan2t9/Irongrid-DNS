package filter

import (
	"io"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/net/html"
)

var (
	// cssURLRe matches url(...) references in CSS text and inline styles.
	cssURLRe = regexp.MustCompile(`url\(\s*['"]?([^'")]+)['"]?\s*\)`)
	// absURLRe matches absolute http(s) URLs inside script text.
	absURLRe = regexp.MustCompile(`https?://[^\s'"<>]+`)
	// fetchRe matches the URL argument of the dynamic-loading calls a page's
	// inline scripts most commonly use.
	fetchRe = regexp.MustCompile(`(?:fetch|XMLHttpRequest|importScripts)\s*\(\s*['"]([^'"]+)['"]`)
)

// ExtractSitePage scans a rendered HTML page and returns every distinct
// hostname the page references — element src/href attributes (scripts,
// stylesheets, images, iframes…), srcset candidates, CSS url(...) references
// (inline styles and <style> blocks), and absolute URLs or fetch() /
// XMLHttpRequest() / importScripts() calls found inside <script> text — plus
// the page's <title>. Relative URLs are resolved against base (a <base
// href> in the document wins over it). Scheme-relative (//host/…) URLs are
// supported; non-http(s) schemes (data:, mailto:, javascript:…) and bare IP
// literals are ignored.
//
// This is a static scan: URLs a script builds dynamically at runtime are
// invisible to it, so a result is a strong signal, not a complete inventory.
func ExtractSitePage(r io.Reader, base *url.URL) (domains []string, title string) {
	doc, err := html.Parse(r)
	if err != nil {
		return nil, ""
	}

	raw := map[string]bool{}
	add := func(u string) {
		if u = strings.TrimSpace(u); u != "" {
			raw[u] = true
		}
	}

	var baseHref *url.URL
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch strings.ToLower(n.Data) {
			case "base":
				if href := attr(n, "href"); href != "" {
					if b, err := base.Parse(href); err == nil {
						baseHref = b
					}
				}
			}
			for _, a := range n.Attr {
				switch strings.ToLower(a.Key) {
				case "href", "src":
					add(a.Val)
				case "srcset":
					for part := range strings.SplitSeq(a.Val, ",") {
						if f := strings.Fields(part); len(f) > 0 {
							add(f[0])
						}
					}
				case "style":
					extractCSSURLs(a.Val, add)
				}
			}
		} else if n.Type == html.TextNode && n.Parent != nil {
			switch strings.ToLower(n.Parent.Data) {
			case "style":
				extractCSSURLs(n.Data, add)
			case "script":
				for _, m := range absURLRe.FindAllString(n.Data, -1) {
					add(m)
				}
				for _, m := range fetchRe.FindAllStringSubmatch(n.Data, -1) {
					add(m[1])
				}
			case "title":
				if title == "" {
					title = strings.TrimSpace(n.Data)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)

	resolveBase := base
	if baseHref != nil {
		resolveBase = baseHref
	}
	hosts := map[string]bool{}
	if h := hostOf(resolveBase); h != "" {
		hosts[h] = true // the page's own hostname
	}
	for u := range raw {
		if h := resolveHost(u, resolveBase); h != "" {
			hosts[h] = true
		}
	}

	domains = make([]string, 0, len(hosts))
	for h := range hosts {
		domains = append(domains, h)
	}
	slices.Sort(domains)
	return domains, title
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val
		}
	}
	return ""
}

// resolveHost parses a (possibly relative) URL against base and returns the
// normalized hostname, or "" when it isn't a fetchable http(s) URL.
func resolveHost(u string, base *url.URL) string {
	u = strings.TrimSpace(u)
	if u == "" {
		return ""
	}
	var parsed *url.URL
	var err error
	if base != nil {
		parsed, err = base.Parse(u)
	} else {
		parsed, err = url.Parse(u)
	}
	if err != nil {
		return ""
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return ""
	}
	h := hostOf(parsed)
	// IP literals are never matched by domain blocklists, so they'd only add
	// noise to the results.
	if ip := net.ParseIP(h); ip != nil {
		return ""
	}
	return h
}

func hostOf(u *url.URL) string {
	if u == nil {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
}

func extractCSSURLs(s string, add func(string)) {
	for _, m := range cssURLRe.FindAllStringSubmatch(s, -1) {
		add(m[1])
	}
}
