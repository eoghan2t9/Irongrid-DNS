package vpn

import (
	"fmt"
	"hash/crc32"
	"strings"
)

// ifaceName derives a deterministic, kernel-safe (<=15-byte IFNAMSIZ-1)
// WireGuard interface name for a profile ID, so arbitrary user-chosen
// profile IDs always produce a valid interface name.
func ifaceName(profileID string) string {
	return fmt.Sprintf("igvpn%08x", crc32.ChecksumIEEE([]byte(profileID)))
}

// wireguardUp brings up a WireGuard interface for peer. On any failure it
// removes whatever partial interface it created, so a failed bring-up never
// leaves a half-configured interface behind.
func wireguardUp(r Runner, iface string, peer PeerConfig) error {
	if err := r.Run("ip", "link", "add", "dev", iface, "type", "wireguard"); err != nil {
		return fmt.Errorf("creating interface %s: %w", iface, err)
	}
	wgArgs := []string{
		"set", iface,
		"private-key", "/dev/stdin",
		"peer", peer.PeerPublicKey,
		"endpoint", peer.Endpoint,
		"allowed-ips", strings.Join(peer.AllowedIPs, ","),
		"persistent-keepalive", "25",
	}
	if err := r.RunStdin("wg", wgArgs, []byte(peer.PrivateKey+"\n")); err != nil {
		_ = r.Run("ip", "link", "del", "dev", iface)
		return fmt.Errorf("configuring WireGuard peer on %s: %w", iface, err)
	}
	if err := r.Run("ip", "address", "add", peer.Address, "dev", iface); err != nil {
		_ = r.Run("ip", "link", "del", "dev", iface)
		return fmt.Errorf("assigning address %s to %s: %w", peer.Address, iface, err)
	}
	if err := r.Run("ip", "link", "set", "up", "dev", iface); err != nil {
		_ = r.Run("ip", "link", "del", "dev", iface)
		return fmt.Errorf("bringing up %s: %w", iface, err)
	}
	return nil
}

// wireguardDown removes a previously brought-up interface. Deleting it also
// removes its address and any routes/rules that reference it.
func wireguardDown(r Runner, iface string) error {
	if err := r.Run("ip", "link", "del", "dev", iface); err != nil {
		return fmt.Errorf("removing interface %s: %w", iface, err)
	}
	return nil
}
