package dnsserver

import (
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/upstream"
)

// dnssecValidateTimeout bounds one local DNSSEC chain-of-trust validation
// (see Handler.serve's step 6a) independent of the original query's own
// timeout budget — the extra DNSKEY/DS lookups it issues are new round
// trips the client's own deadline never accounted for. A cold cache (a
// zone/TLD never validated before) can need several of these; once cached,
// subsequent queries under the same zone are effectively free.
const dnssecValidateTimeout = 8 * time.Second

// upstreamByName returns the upstream in ups matching name (as returned by
// resolveUpstreams' usedUp), or nil if none matches — e.g. usedUp is empty
// because every upstream failed.
func upstreamByName(ups []*upstream.Upstream, name string) *upstream.Upstream {
	for _, up := range ups {
		if up.Name() == name {
			return up
		}
	}
	return nil
}
