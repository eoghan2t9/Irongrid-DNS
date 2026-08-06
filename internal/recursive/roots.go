// Package recursive implements iterative DNS resolution: starting from the
// root servers and following NS referrals (root -> TLD -> authoritative)
// itself, as an alternative to forwarding every query to a third-party
// recursive resolver.
package recursive

// DefaultRootHints lists the 13 root server letters' well-known addresses
// (IANA's "named.root" hint file), IPv4 first across the whole list so a
// host without IPv6 connectivity never pays for a failed dial attempt before
// reaching a working address.
var DefaultRootHints = []string{
	"198.41.0.4:53",     // a.root-servers.net
	"170.247.170.2:53",  // b.root-servers.net
	"192.33.4.12:53",    // c.root-servers.net
	"199.7.91.13:53",    // d.root-servers.net
	"192.203.230.10:53", // e.root-servers.net
	"192.5.5.241:53",    // f.root-servers.net
	"192.112.36.4:53",   // g.root-servers.net
	"198.97.190.53:53",  // h.root-servers.net
	"192.36.148.17:53",  // i.root-servers.net
	"192.58.128.30:53",  // j.root-servers.net
	"193.0.14.129:53",   // k.root-servers.net
	"199.7.83.42:53",    // l.root-servers.net
	"202.12.27.33:53",   // m.root-servers.net

	"[2001:503:ba3e::2:30]:53", // a.root-servers.net
	"[2801:1b8:10::b]:53",      // b.root-servers.net
	"[2001:500:2::c]:53",       // c.root-servers.net
	"[2001:500:2d::d]:53",      // d.root-servers.net
	"[2001:500:a8::e]:53",      // e.root-servers.net
	"[2001:500:2f::f]:53",      // f.root-servers.net
	"[2001:500:12::d0d]:53",    // g.root-servers.net
	"[2001:500:1::53]:53",      // h.root-servers.net
	"[2001:7fe::53]:53",        // i.root-servers.net
	"[2001:503:c27::2:30]:53",  // j.root-servers.net
	"[2001:7fd::1]:53",         // k.root-servers.net
	"[2001:500:9f::42]:53",     // l.root-servers.net
	"[2001:dc3::35]:53",        // m.root-servers.net
}
