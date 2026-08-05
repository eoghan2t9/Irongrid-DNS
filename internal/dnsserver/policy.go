package dnsserver

import (
	"log"

	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
	"github.com/eoghan2t9/Irongrid-DNS/internal/upstream"
)

// BuildRewriter compiles the local DNS records (config.Rewrites) into a
// filter.Rewriter ready to hand to a Handler. Shared by main's startup path
// and the API's live config-apply path so they can't drift.
func BuildRewriter(specs []config.RewriteSpec) *filter.Rewriter {
	rw := filter.NewRewriter()
	fspecs := make([]filter.RewriteSpec, 0, len(specs))
	for _, s := range specs {
		fspecs = append(fspecs, filter.RewriteSpec{Domain: s.Domain, Type: s.Type, Value: s.Value, TTL: s.TTL})
	}
	rw.Set(fspecs)
	return rw
}

// BuildRateLimiter returns a rate limiter for rl, or nil when disabled (nil
// is the Handler's "no rate limiting" state).
func BuildRateLimiter(rl config.RateLimitConfig) *RateLimiter {
	if !rl.Enabled {
		return nil
	}
	return NewRateLimiter(rl.QPS, rl.Burst)
}

// BuildClientRouter compiles cfg.ClientGroups into a ClientRouter: each
// enabled group gets its own filter.Engine, built from the same cached
// blocklist content the global engine uses (lists.GetContent avoids
// re-fetching anything over the network) restricted to the group's chosen
// list IDs, plus its own resolved upstream set when one is configured.
func BuildClientRouter(cfg *config.Config, lists *filter.ListManager) *ClientRouter {
	router := NewClientRouter()
	if len(cfg.ClientGroups) == 0 {
		return router
	}
	listNames := make(map[string]string, len(cfg.Filter.Blocklists))
	allIDs := make([]string, 0, len(cfg.Filter.Blocklists))
	for _, s := range cfg.Filter.Blocklists {
		listNames[s.ID] = s.Name
		if s.Enabled {
			allIDs = append(allIDs, s.ID)
		}
	}
	groups := make([]GroupCIDRs, 0, len(cfg.ClientGroups))
	for _, g := range cfg.ClientGroups {
		if !g.Enabled {
			continue
		}
		ids := g.Blocklists
		if len(ids) == 0 {
			ids = allIDs
		}
		engine := filter.NewEngine()
		for _, id := range ids {
			content := lists.GetContent(id)
			if content == nil {
				continue
			}
			if _, err := engine.LoadList(id, listNames[id], content); err != nil {
				log.Printf("[clients] group %s: list %s: %v", g.ID, id, err)
			}
		}
		engine.SetUserLists(g.Blacklist, g.Whitelist)
		engine.Compile()

		var groupUps []*upstream.Upstream
		for _, spec := range g.Upstreams {
			up, err := upstream.Parse(spec)
			if err != nil {
				log.Printf("[clients] group %s: upstream %q: %v", g.ID, spec, err)
				continue
			}
			groupUps = append(groupUps, up)
		}

		groups = append(groups, GroupCIDRs{
			CIDRs: g.CIDRs,
			Policy: &ClientPolicy{
				GroupID:   g.ID,
				GroupName: g.Name,
				Engine:    engine,
				Upstreams: groupUps,
			},
		})
	}
	router.SetPolicies(groups)
	return router
}
