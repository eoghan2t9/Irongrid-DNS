package main

import (
	"net"
	"net/http"
	"strings"
)

// HTTPS redirect and web-listen address helpers.

// httpsRedirect returns a handler that 301s a plain-HTTP request to the same
// path over HTTPS. The hostname is taken from the request (so real domains
// and proxies work); the port is the HTTPS web server's port, with the
// default 443 omitted for clean URLs.
func httpsRedirect(httpsPort string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(r.Host); err == nil {
			host = h
		}
		if host == "" || strings.ContainsAny(host, "/\\@?# \t\r\n") {
			http.Error(w, "invalid host", http.StatusBadRequest)
			return
		}
		target := "https://" + host
		if httpsPort != "443" && httpsPort != "" {
			target += ":" + httpsPort
		}
		reqURI := r.URL.RequestURI()
		for strings.HasPrefix(reqURI, "//") {
			reqURI = reqURI[1:]
		}
		target += reqURI
		//nolint:gosec // G710 open redirect: the target host is validated above
		// (no slashes, @, ?, #, or whitespace) and comes from the Host header.
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	}
}

// webTLSPort extracts the port of the HTTPS web server address
// ("0.0.0.0:8443" -> "8443", "0.0.0.0" -> "").
func webTLSPort(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return port
}

// hostOnly strips the port from a listen address ("0.0.0.0:8443" ->
// "0.0.0.0") so it can be displayed in logs.
func hostOnly(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
