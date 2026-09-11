// Package vpn implements domain-based split-tunnel VPN routing: the
// resolved answers for configured domains are routed through a dedicated
// WireGuard tunnel to a NordVPN or PIA server instead of the host's normal
// default route, while every other domain is unaffected — e.g. sending
// only bbc.co.uk/bbci.co.uk through a UK server so iPlayer works while
// traveling, with everything else on the normal path.
//
// A Manager owns one WireGuard interface per configured profile (brought up
// with the `ip`/`wg` CLIs — Linux's wireguard-tools package) and a shared
// nftables table that marks packets destined for a route's resolved IPs so
// Linux's policy routing (`ip rule`/`ip route`) sends them out that
// interface instead of the main table.
//
// The DNS hot path only ever calls Manager.Observe, which does a cheap
// route match and hands IP extraction off to a bounded background worker —
// it never blocks or shells out on the query path itself.
//
// Linux only. Requires root or CAP_NET_ADMIN/CAP_NET_RAW, and the `ip`,
// `wg` and `nft` binaries on PATH.
package vpn

import (
	"context"
	"net"
	"time"
)

// PeerConfig is everything needed to bring up a WireGuard interface to one
// VPN server: our own private key plus the server's peer info. Fetched
// fresh from the vendor's account API on every profile (re)connect — never
// persisted to disk.
type PeerConfig struct {
	PrivateKey    string   // ours, base64 — never logged
	Address       string   // our tunnel address in CIDR form, e.g. "10.5.0.2/16"
	PeerPublicKey string   // the VPN server's WireGuard public key
	Endpoint      string   // "host:port"
	AllowedIPs    []string // normally {"0.0.0.0/0"}
	DNS           []string // provider's recommended in-tunnel resolver (informational only — Irongrid never uses it)
}

// Provider fetches a fresh WireGuard peer configuration for one region from
// a VPN vendor's account API. Connect is called once per profile bring-up
// (boot, config reload, reconnect after failure) — never per DNS query — so
// it is fine for it to be slow (a network round trip to the vendor).
type Provider interface {
	Name() string
	Connect(ctx context.Context, region string) (PeerConfig, error)
}

// Answer is the pre-extracted result of one DNS response, handed to Observe
// by internal/dnsserver — this package never imports github.com/miekg/dns
// itself, the caller does the RR-type switch.
type Answer struct {
	Name string   // query name (lowercased, no trailing dot)
	IPs  []net.IP // every A/AAAA address in the response
	TTL  time.Duration
}
