package vpn

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// piaCACert is PIA's own publicly-published CA certificate, used to verify
// the identity of the per-region WireGuard servers during key exchange —
// copied verbatim from
// github.com/pia-foss/manual-connections/ca.rsa.4096.crt (PIA's official,
// MIT-licensed reference implementation of this connection flow). A CA
// certificate is public by design, not a secret.
const piaCACert = `
-----BEGIN CERTIFICATE-----
MIIHqzCCBZOgAwIBAgIJAJ0u+vODZJntMA0GCSqGSIb3DQEBDQUAMIHoMQswCQYD
VQQGEwJVUzELMAkGA1UECBMCQ0ExEzARBgNVBAcTCkxvc0FuZ2VsZXMxIDAeBgNV
BAoTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMSAwHgYDVQQLExdQcml2YXRlIElu
dGVybmV0IEFjY2VzczEgMB4GA1UEAxMXUHJpdmF0ZSBJbnRlcm5ldCBBY2Nlc3Mx
IDAeBgNVBCkTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMS8wLQYJKoZIhvcNAQkB
FiBzZWN1cmVAcHJpdmF0ZWludGVybmV0YWNjZXNzLmNvbTAeFw0xNDA0MTcxNzQw
MzNaFw0zNDA0MTIxNzQwMzNaMIHoMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0Ex
EzARBgNVBAcTCkxvc0FuZ2VsZXMxIDAeBgNVBAoTF1ByaXZhdGUgSW50ZXJuZXQg
QWNjZXNzMSAwHgYDVQQLExdQcml2YXRlIEludGVybmV0IEFjY2VzczEgMB4GA1UE
AxMXUHJpdmF0ZSBJbnRlcm5ldCBBY2Nlc3MxIDAeBgNVBCkTF1ByaXZhdGUgSW50
ZXJuZXQgQWNjZXNzMS8wLQYJKoZIhvcNAQkBFiBzZWN1cmVAcHJpdmF0ZWludGVy
bmV0YWNjZXNzLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALVk
hjumaqBbL8aSgj6xbX1QPTfTd1qHsAZd2B97m8Vw31c/2yQgZNf5qZY0+jOIHULN
De4R9TIvyBEbvnAg/OkPw8n/+ScgYOeH876VUXzjLDBnDb8DLr/+w9oVsuDeFJ9K
V2UFM1OYX0SnkHnrYAN2QLF98ESK4NCSU01h5zkcgmQ+qKSfA9Ny0/UpsKPBFqsQ
25NvjDWFhCpeqCHKUJ4Be27CDbSl7lAkBuHMPHJs8f8xPgAbHRXZOxVCpayZ2SND
fCwsnGWpWFoMGvdMbygngCn6jA/W1VSFOlRlfLuuGe7QFfDwA0jaLCxuWt/BgZyl
p7tAzYKR8lnWmtUCPm4+BtjyVDYtDCiGBD9Z4P13RFWvJHw5aapx/5W/CuvVyI7p
Kwvc2IT+KPxCUhH1XI8ca5RN3C9NoPJJf6qpg4g0rJH3aaWkoMRrYvQ+5PXXYUzj
tRHImghRGd/ydERYoAZXuGSbPkm9Y/p2X8unLcW+F0xpJD98+ZI+tzSsI99Zs5wi
jSUGYr9/j18KHFTMQ8n+1jauc5bCCegN27dPeKXNSZ5riXFL2XX6BkY68y58UaNz
meGMiUL9BOV1iV+PMb7B7PYs7oFLjAhh0EdyvfHkrh/ZV9BEhtFa7yXp8XR0J6vz
1YV9R6DYJmLjOEbhU8N0gc3tZm4Qz39lIIG6w3FDAgMBAAGjggFUMIIBUDAdBgNV
HQ4EFgQUrsRtyWJftjpdRM0+925Y6Cl08SUwggEfBgNVHSMEggEWMIIBEoAUrsRt
yWJftjpdRM0+925Y6Cl08SWhge6kgeswgegxCzAJBgNVBAYTAlVTMQswCQYDVQQI
EwJDQTETMBEGA1UEBxMKTG9zQW5nZWxlczEgMB4GA1UEChMXUHJpdmF0ZSBJbnRl
cm5ldCBBY2Nlc3MxIDAeBgNVBAsTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMSAw
HgYDVQQDExdQcml2YXRlIEludGVybmV0IEFjY2VzczEgMB4GA1UEKRMXUHJpdmF0
ZSBJbnRlcm5ldCBBY2Nlc3MxLzAtBgkqhkiG9w0BCQEWIHNlY3VyZUBwcml2YXRl
aW50ZXJuZXRhY2Nlc3MuY29tggkAnS7684Nkme0wDAYDVR0TBAUwAwEB/zANBgkq
hkiG9w0BAQ0FAAOCAgEAJsfhsPk3r8kLXLxY+v+vHzbr4ufNtqnL9/1Uuf8NrsCt
pXAoyZ0YqfbkWx3NHTZ7OE9ZRhdMP/RqHQE1p4N4Sa1nZKhTKasV6KhHDqSCt/dv
Em89xWm2MVA7nyzQxVlHa9AkcBaemcXEiyT19XdpiXOP4Vhs+J1R5m8zQOxZlV1G
tF9vsXmJqWZpOVPmZ8f35BCsYPvv4yMewnrtAC8PFEK/bOPeYcKN50bol22QYaZu
LfpkHfNiFTnfMh8sl/ablPyNY7DUNiP5DRcMdIwmfGQxR5WEQoHL3yPJ42LkB5zs
6jIm26DGNXfwura/mi105+ENH1CaROtRYwkiHb08U6qLXXJz80mWJkT90nr8Asj3
5xN2cUppg74nG3YVav/38P48T56hG1NHbYF5uOCske19F6wi9maUoto/3vEr0rnX
JUp2KODmKdvBI7co245lHBABWikk8VfejQSlCtDBXn644ZMtAdoxKNfR2WTFVEwJ
iyd1Fzx0yujuiXDROLhISLQDRjVVAvawrAtLZWYK31bY7KlezPlQnl/D9Asxe85l
8jO5+0LdJ6VyOs/Hd4w52alDW/MFySDZSfQHMTIc30hLBJ8OnCEIvluVQQ2UQvoW
+no177N9L2Y+M9TcTA62ZyMXShHQGeh20rb4kK8f+iFX8NxtdHVSkxMEFSfDDyQ=
-----END CERTIFICATE-----
`

const (
	piaServerListURL = "https://serverlist.piaservers.net/vpninfo/servers/v6"
	//nolint:gosec // G101: this is PIA's public token-issuance endpoint URL,
	// not a credential — the pattern matcher just sees the word "token".
	piaTokenURL = "https://www.privateinternetaccess.com/api/client/v2/token"
)

// PIA talks to Private Internet Access's officially published WireGuard
// connection API (github.com/pia-foss/manual-connections) using a regular
// PIA account login.
type PIA struct {
	Username string
	Password string
	HTTP     *http.Client
}

func (p *PIA) Name() string { return "pia" }

func (p *PIA) client() *http.Client {
	if p.HTTP != nil {
		return p.HTTP
	}
	return &http.Client{Timeout: 15 * time.Second}
}

// Connect resolves region (a PIA region id, e.g. "uk_london" — see PIA's
// published region list) to a WireGuard server, authenticates, and
// performs PIA's key exchange with a fresh ephemeral keypair.
func (p *PIA) Connect(ctx context.Context, region string) (PeerConfig, error) {
	if p.Username == "" || p.Password == "" {
		return PeerConfig{}, fmt.Errorf("pia: no account credentials configured")
	}
	server, err := p.regionServer(ctx, region)
	if err != nil {
		return PeerConfig{}, err
	}
	token, err := p.token(ctx)
	if err != nil {
		return PeerConfig{}, err
	}
	privKey, pubKey, err := generateKeypair()
	if err != nil {
		return PeerConfig{}, fmt.Errorf("pia: generating WireGuard keypair: %w", err)
	}
	peer, err := p.addKey(ctx, server, token, pubKey)
	if err != nil {
		return PeerConfig{}, err
	}
	return PeerConfig{
		PrivateKey:    privKey,
		Address:       peer.PeerIP + "/32",
		PeerPublicKey: peer.ServerKey,
		Endpoint:      fmt.Sprintf("%s:%d", server.ip, peer.ServerPort),
		AllowedIPs:    []string{"0.0.0.0/0"},
		DNS:           peer.DNSServers,
	}, nil
}

type piaServer struct {
	ip       string
	hostname string
}

type piaRegion struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Servers struct {
		WG []struct {
			IP string `json:"ip"`
			CN string `json:"cn"`
		} `json:"wg"`
	} `json:"servers"`
}

type piaServerList struct {
	Regions []piaRegion `json:"regions"`
}

func (p *PIA) regionServer(ctx context.Context, region string) (piaServer, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, piaServerListURL, nil)
	if err != nil {
		return piaServer{}, err
	}
	resp, err := p.client().Do(req)
	if err != nil {
		return piaServer{}, fmt.Errorf("pia: fetching server list: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return piaServer{}, fmt.Errorf("pia: server list returned status %s", resp.Status)
	}
	// The response body is one line of JSON followed by a detached
	// signature block; only the first line is the server list itself —
	// matches PIA's own get_region.sh (`curl ... | head -1`).
	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	if err != nil && line == "" {
		return piaServer{}, fmt.Errorf("pia: reading server list: %w", err)
	}
	var list piaServerList
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &list); err != nil {
		return piaServer{}, fmt.Errorf("pia: decoding server list: %w", err)
	}
	needle := strings.ToLower(region)
	for _, r := range list.Regions {
		if strings.ToLower(r.ID) != needle && strings.ToLower(r.Name) != needle {
			continue
		}
		if len(r.Servers.WG) == 0 {
			return piaServer{}, fmt.Errorf("pia: region %q has no WireGuard servers", region)
		}
		return piaServer{ip: r.Servers.WG[0].IP, hostname: r.Servers.WG[0].CN}, nil
	}
	return piaServer{}, fmt.Errorf("pia: no region matches %q (see PIA's region list, e.g. \"uk_london\", \"us_new_york\")", region)
}

type piaTokenResponse struct {
	Token string `json:"token"`
}

func (p *PIA) token(ctx context.Context) (string, error) {
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	_ = w.WriteField("username", p.Username)
	_ = w.WriteField("password", p.Password)
	_ = w.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, piaTokenURL, &body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	resp, err := p.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("pia: requesting auth token: %w", err)
	}
	defer resp.Body.Close()
	var tr piaTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("pia: decoding token response: %w", err)
	}
	if tr.Token == "" {
		return "", fmt.Errorf("pia: authentication failed — check vpn.providers.pia.username/password")
	}
	return tr.Token, nil
}

type piaAddKeyResponse struct {
	Status     string   `json:"status"`
	ServerKey  string   `json:"server_key"`
	ServerPort int      `json:"server_port"`
	PeerIP     string   `json:"peer_ip"`
	DNSServers []string `json:"dns_servers"`
}

// addKey performs PIA's WireGuard key exchange against server, verifying
// the server's identity against PIA's own CA (not the system trust store)
// and its hostname. This mirrors curl's --connect-to in PIA's reference
// connect_to_wireguard_with_token.sh: dial the server's real IP directly
// (its hostname may not resolve outside PIA's own infrastructure) but keep
// verifying the TLS certificate against that hostname and PIA's CA.
func (p *PIA) addKey(ctx context.Context, server piaServer, token, pubKey string) (piaAddKeyResponse, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(piaCACert)) {
		return piaAddKeyResponse{}, fmt.Errorf("pia: failed to parse embedded CA certificate")
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			raw, err := dialer.DialContext(ctx, network, net.JoinHostPort(server.ip, port))
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(raw, &tls.Config{
				ServerName: server.hostname,
				RootCAs:    pool,
				MinVersion: tls.VersionTLS12,
			})
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = raw.Close()
				return nil, err
			}
			return tlsConn, nil
		},
	}
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}

	u := fmt.Sprintf("https://%s:1337/addKey?pt=%s&pubkey=%s",
		server.hostname, url.QueryEscape(token), url.QueryEscape(pubKey))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return piaAddKeyResponse{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return piaAddKeyResponse{}, fmt.Errorf("pia: WireGuard key exchange failed: %w", err)
	}
	defer resp.Body.Close()
	var ar piaAddKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&ar); err != nil {
		return piaAddKeyResponse{}, fmt.Errorf("pia: decoding key exchange response: %w", err)
	}
	if ar.Status != "OK" {
		return piaAddKeyResponse{}, fmt.Errorf("pia: server did not accept the key exchange (status %q)", ar.Status)
	}
	return ar, nil
}
