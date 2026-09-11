package vpn

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const nordBaseURL = "https://api.nordvpn.com"

// nordWireguardTech is NordVPN's internal technology id for WireGuard
// (NordLynx) servers — core.WireguardTech in nordvpn-linux.
const nordWireguardTech = 35

// nordLynxPort is NordLynx's fixed WireGuard listening port
// (daemon/vpn/nordlynx.defaultPort in nordvpn-linux).
const nordLynxPort = 51820

// nordLynxAddress is the fixed client tunnel address NordLynx assigns every
// account (daemon/vpn/nordlynx.DefaultPrefix in nordvpn-linux) — every
// NordLynx connection uses this same /16 regardless of server.
const nordLynxAddress = "10.5.0.2/16"

// NordVPN talks to NordVPN's account API to fetch the account's NordLynx
// (WireGuard) private key and a recommended server for a country.
//
// These endpoints are not a published public API — they are the same ones
// NordVPN's own open-source Linux client
// (github.com/NordSecurity/nordvpn-linux) uses, read from that source
// rather than documented by NordVPN, so they can change without notice.
// Generate Token at nordvpn.com -> Account -> "Set up NordVPN manually"
// (the same token `nordvpn login --token` uses).
type NordVPN struct {
	Token string
	HTTP  *http.Client
}

func (n *NordVPN) Name() string { return "nordvpn" }

func (n *NordVPN) client() *http.Client {
	if n.HTTP != nil {
		return n.HTTP
	}
	return &http.Client{Timeout: 15 * time.Second}
}

// Connect resolves region (an ISO 3166-1 alpha-2 code like "gb", or a full
// country name) to a recommended NordLynx server and fetches the account's
// persistent NordLynx private key.
func (n *NordVPN) Connect(ctx context.Context, region string) (PeerConfig, error) {
	if n.Token == "" {
		return PeerConfig{}, fmt.Errorf("nordvpn: no account token configured")
	}
	countryID, err := n.countryID(ctx, region)
	if err != nil {
		return PeerConfig{}, err
	}
	server, err := n.recommendedServer(ctx, countryID)
	if err != nil {
		return PeerConfig{}, err
	}
	privKey, err := n.credentials(ctx)
	if err != nil {
		return PeerConfig{}, err
	}
	return PeerConfig{
		PrivateKey:    privKey,
		Address:       nordLynxAddress,
		PeerPublicKey: server.publicKey,
		Endpoint:      fmt.Sprintf("%s:%d", server.station, nordLynxPort),
		AllowedIPs:    []string{"0.0.0.0/0"},
	}, nil
}

type nordCountry struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Code string `json:"code"`
}

// countryID resolves a country by ISO code (e.g. "gb") or name (e.g.
// "United Kingdom"), case-insensitively.
func (n *NordVPN) countryID(ctx context.Context, region string) (int, error) {
	var countries []nordCountry
	if err := n.get(ctx, "/v1/servers/countries", &countries); err != nil {
		return 0, fmt.Errorf("nordvpn: fetching country list: %w", err)
	}
	needle := strings.ToLower(region)
	for _, c := range countries {
		if strings.ToLower(c.Code) == needle || strings.ToLower(c.Name) == needle {
			return c.ID, nil
		}
	}
	return 0, fmt.Errorf("nordvpn: no country matches region %q (use an ISO 3166-1 alpha-2 code like \"gb\", or the full country name)", region)
}

type nordServerTechnology struct {
	ID       int `json:"id"`
	Metadata []struct {
		Name  string `json:"name"`
		Value any    `json:"value"`
	} `json:"metadata"`
}

type nordServer struct {
	Station      string                 `json:"station"`
	Hostname     string                 `json:"hostname"`
	Technologies []nordServerTechnology `json:"technologies"`
}

type nordRecommendation struct {
	station   string
	publicKey string
}

func (n *NordVPN) recommendedServer(ctx context.Context, countryID int) (nordRecommendation, error) {
	path := fmt.Sprintf("/v1/servers/recommendations?limit=1&filters[country_id]=%d&filters[servers_technologies]=%d",
		countryID, nordWireguardTech)
	var servers []nordServer
	if err := n.get(ctx, path, &servers); err != nil {
		return nordRecommendation{}, fmt.Errorf("nordvpn: fetching recommended server: %w", err)
	}
	if len(servers) == 0 {
		return nordRecommendation{}, fmt.Errorf("nordvpn: no WireGuard server available for this region")
	}
	s := servers[0]
	var pubKey string
	for _, tech := range s.Technologies {
		if tech.ID != nordWireguardTech {
			continue
		}
		for _, meta := range tech.Metadata {
			if meta.Name != "public_key" {
				continue
			}
			if v, ok := meta.Value.(string); ok {
				pubKey = strings.TrimSpace(v)
			}
		}
	}
	if pubKey == "" || s.Station == "" {
		return nordRecommendation{}, fmt.Errorf("nordvpn: recommended server response missing station/public key")
	}
	return nordRecommendation{station: s.Station, publicKey: pubKey}, nil
}

type nordCredentials struct {
	NordlynxPrivateKey string `json:"nordlynx_private_key"`
}

func (n *NordVPN) credentials(ctx context.Context) (string, error) {
	var creds nordCredentials
	if err := n.getAuth(ctx, "/v1/users/services/credentials", &creds); err != nil {
		return "", fmt.Errorf("nordvpn: fetching NordLynx credentials: %w", err)
	}
	if creds.NordlynxPrivateKey == "" {
		return "", fmt.Errorf("nordvpn: account has no NordLynx private key — is the token valid and the account active?")
	}
	return creds.NordlynxPrivateKey, nil
}

func (n *NordVPN) get(ctx context.Context, path string, out any) error {
	return n.do(ctx, path, "", out)
}

func (n *NordVPN) getAuth(ctx context.Context, path string, out any) error {
	// NordVPN's own client sends "Bearer token:<token>" (not a bare bearer
	// token) — read from request/request.go in nordvpn-linux.
	return n.do(ctx, path, "Bearer token:"+n.Token, out)
}

func (n *NordVPN) do(ctx context.Context, path, auth string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, nordBaseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "irongrid-dns")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := n.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %s from %s", resp.Status, path)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
