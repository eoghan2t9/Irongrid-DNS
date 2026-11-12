package acme

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ACME Renewal Information (ARI, RFC 9773): the CA tells the client when it
// wants a certificate renewed. Normally that is a window late in the
// certificate's life, but the CA moves it to "now" when it needs to revoke or
// replace certificates early (a mass revocation, a compromised key, a changed
// validation rule). A client that only counts days never hears about that.
//
// golang.org/x/crypto/acme has no ARI support, so this is the small client
// for it. ARI is advisory and only ever brings a renewal earlier: the
// renew_before_days rule still applies on its own, and any ARI failure (the CA
// does not offer it, the request errors, the reply is malformed) is treated as
// "no opinion".

var errNoARI = errors.New("acme server does not advertise renewalInfo")

// ariInfo is the CA's suggested renewal window for one certificate.
type ariInfo struct {
	Start, End     time.Time
	ExplanationURL string
	// RetryAfter is how long the CA asks clients to wait before asking again.
	RetryAfter time.Duration
	// fetched and serial bind the answer to the moment it was obtained and to
	// the certificate it describes, so a renewed certificate never inherits
	// the previous one's window.
	fetched time.Time
	serial  string
}

const (
	ariMaxBody = 1 << 20
	// ariDefaultRetry applies when the CA sends no Retry-After; ariMaxRetry
	// stops a misbehaving CA from silencing renewal hints for days.
	ariDefaultRetry = 6 * time.Hour
	ariMaxRetry     = 24 * time.Hour
)

// ariCertID builds the renewalInfo path component for a certificate: the
// unpadded base64url of its Authority Key Identifier, a dot, and the unpadded
// base64url of the DER content octets of its serial number (RFC 9773 §4.1).
func ariCertID(leaf *x509.Certificate) (string, error) {
	if len(leaf.AuthorityKeyId) == 0 {
		return "", errors.New("certificate has no Authority Key Identifier")
	}
	if leaf.SerialNumber == nil || leaf.SerialNumber.Sign() <= 0 {
		return "", errors.New("certificate has no positive serial number")
	}
	serial := leaf.SerialNumber.Bytes()
	// DER INTEGER content is two's complement: a leading zero octet keeps a
	// positive serial whose top bit is set from reading as negative.
	if serial[0]&0x80 != 0 {
		serial = append([]byte{0}, serial...)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(leaf.AuthorityKeyId) + "." + enc.EncodeToString(serial), nil
}

// fetchARI asks the CA behind dirURL for leaf's renewal window.
func fetchARI(ctx context.Context, hc *http.Client, dirURL string, leaf *x509.Certificate) (*ariInfo, error) {
	id, err := ariCertID(leaf)
	if err != nil {
		return nil, err
	}

	var dir struct {
		RenewalInfo string `json:"renewalInfo"`
	}
	if _, err := getJSON(ctx, hc, dirURL, &dir); err != nil {
		return nil, fmt.Errorf("read ACME directory: %w", err)
	}
	if dir.RenewalInfo == "" {
		return nil, errNoARI
	}

	var body struct {
		SuggestedWindow struct {
			Start time.Time `json:"start"`
			End   time.Time `json:"end"`
		} `json:"suggestedWindow"`
		ExplanationURL string `json:"explanationURL"`
	}
	hdr, err := getJSON(ctx, hc, strings.TrimRight(dir.RenewalInfo, "/")+"/"+id, &body)
	if err != nil {
		return nil, fmt.Errorf("read renewalInfo: %w", err)
	}
	w := body.SuggestedWindow
	if w.Start.IsZero() || w.End.IsZero() || w.End.Before(w.Start) {
		return nil, errors.New("renewalInfo has no valid suggestedWindow")
	}

	retry := ariDefaultRetry
	if s := hdr.Get("Retry-After"); s != "" {
		if secs, err := strconv.Atoi(s); err == nil && secs > 0 {
			retry = time.Duration(secs) * time.Second
		}
	}
	retry = min(retry, ariMaxRetry)

	return &ariInfo{
		Start:          w.Start,
		End:            w.End,
		ExplanationURL: body.ExplanationURL,
		RetryAfter:     retry,
		fetched:        time.Now(),
		serial:         leaf.SerialNumber.String(),
	}, nil
}

func getJSON(ctx context.Context, hc *http.Client, url string, out any) (http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, ariMaxBody)).Decode(out); err != nil {
		return nil, err
	}
	return resp.Header, nil
}

// shouldRenew applies RFC 9773 §4.2: pick a moment uniformly inside the
// suggested window (pick is in [0,1)) and renew now when that moment falls
// before the next time this client will check again (within) — so the
// renewal is spread across the window instead of every client arriving at
// its start, and is never later than the window allows.
func (a *ariInfo) shouldRenew(now time.Time, within time.Duration, pick float64) bool {
	target := a.Start.Add(time.Duration(pick * float64(a.End.Sub(a.Start))))
	return !target.After(now.Add(within))
}
