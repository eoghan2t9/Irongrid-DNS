// Package catalog provides the curated, pre-made blocklist and whitelist
// presets offered in the web dashboard and the TUI installer. Keeping them in
// Go (rather than hardcoded in the frontend) lets both entry points share the
// same source of truth and makes them easy to extend.
package catalog

// Blocklist is one pre-made blocklist source.
type Blocklist struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	URL         string `json:"url"`
	AutoUpdate  string `json:"auto_update"` // duration string, e.g. "24h"
	Category    string `json:"category"`    // e.g. "comprehensive", "ads", "privacy"
}

// Whitelist is a curated set of domains that should always resolve,
// overriding any blocklist. One click adds every domain to the Allow list.
type Whitelist struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Domains     []string `json:"domains"`
}

// Catalog is the full set of presets served by GET /api/lists/catalog.
type Catalog struct {
	Blocklists []Blocklist `json:"blocklists"`
	Whitelists []Whitelist `json:"whitelists"`
}

// Default returns the curated catalog.
func Default() *Catalog {
	return &Catalog{
		Blocklists: []Blocklist{
			{
				ID: "oisd-big", Name: "OISD Big",
				Description: "Comprehensive ad/tracker/malware blocklist (~2M domains), balanced for daily use.",
				URL: "https://big.oisd.nl/", AutoUpdate: "24h", Category: "comprehensive",
			},
			{
				ID: "oisd-full", Name: "OISD Full",
				Description: "Everything in Big plus gambling, porn and more aggressive categories.",
				URL: "https://oisd.nl/", AutoUpdate: "24h", Category: "comprehensive",
			},
			{
				ID: "hagezi-multi", Name: "Hagezi Multi PRO",
				Description: "Multi-category blocklist: ads, tracking, malware, scams, phishing.",
				URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/multi.txt",
				AutoUpdate: "24h", Category: "comprehensive",
			},
			{
				ID: "stevenblack", Name: "StevenBlack hosts",
				Description: "The classic unified hosts file — ads, malware and fake news domains.",
				URL: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
				AutoUpdate: "168h", Category: "ads",
			},
			{
				ID: "adguard", Name: "AdGuard DNS filter",
				Description: "AdGuard's main DNS blocklist (ad, tracking and social widgets).",
				URL: "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
				AutoUpdate: "168h", Category: "ads",
			},
			{
				ID: "easylist", Name: "EasyList",
				Description: "The standard ad-blocking list used by most ad blockers.",
				URL: "https://easylist.to/easylist/easylist.txt",
				AutoUpdate: "168h", Category: "ads",
			},
			{
				ID: "easyprivacy", Name: "EasyPrivacy",
				Description: "Tracking protection companion to EasyList.",
				URL: "https://easylist.to/easylist/easyprivacy.txt",
				AutoUpdate: "168h", Category: "privacy",
			},
			{
				ID: "1hosts-lite", Name: "1Hosts (Lite)",
				Description: "Lightweight, high-quality blocklist of ads and trackers.",
				URL: "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/hosts.txt",
				AutoUpdate: "168h", Category: "privacy",
			},
			{
				ID: "1hosts-pro", Name: "1Hosts (Pro)",
				Description: "Stricter 1Hosts variant that also blocks adult content.",
				URL: "https://raw.githubusercontent.com/badmojr/1Hosts/master/Pro/hosts.txt",
				AutoUpdate: "168h", Category: "privacy",
			},
			{
				ID: "yoyo", Name: "yoyo.org",
				Description: "Small, fast ad-server list with near-zero false positives.",
				URL: "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
				AutoUpdate: "168h", Category: "ads",
			},
			{
				ID: "adaway", Name: "AdAway hosts",
				Description: "Hosts list maintained by the AdAway project.",
				URL: "https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt",
				AutoUpdate: "168h", Category: "ads",
			},
			{
				ID: "notracking", Name: "NoTracking",
				Description: "Aggressive tracking-domain blocklist.",
				URL: "https://raw.githubusercontent.com/notracking/hosts-blocklists/master/hostnames.txt",
				AutoUpdate: "24h", Category: "privacy",
			},
		},
		Whitelists: []Whitelist{
			{
				ID: "os-updates", Name: "OS & security updates",
				Description: "Microsoft, Apple, Google and Linux update endpoints must always resolve.",
				Domains: []string{
					"update.microsoft.com", "download.microsoft.com", "windowsupdate.microsoft.com",
					"windowsupdate.com", "delivery.mp.microsoft.com", "ctldl.windowsupdate.com",
					"swdist.apple.com", "mesu.apple.com", "gdmf.apple.com", "appldnld.apple.com",
					"updates.cdn-apple.com", "gspe1-ssl.ls.apple.com",
					"play.googleapis.com", "dl.google.com", "dl-ssl.google.com", "clients.google.com",
					"security.ubuntu.com", "archive.ubuntu.com", "deb.debian.org", "packages.microsoft.com",
					"cdn.kernel.org",
				},
			},
			{
				ID: "dev", Name: "Development & CI",
				Description: "Git, package registries and CI services.",
				Domains: []string{
					"github.com", "api.github.com", "codeload.github.com", "objects.githubusercontent.com",
					"gitlab.com", "bitbucket.org", "gitlab.freedesktop.org",
					"registry.npmjs.org", "registry.yarnpkg.com", "pypi.org", "files.pythonhosted.org",
					"crates.io", "static.crates.io", "proxy.golang.org", "storage.googleapis.com",
					"repo.maven.apache.org", "search.maven.org",
					"hub.docker.com", "registry-1.docker.io", "auth.docker.io", "ghcr.io",
					"cloudflare.com", "developers.cloudflare.com", "www.cloudflare.com",
					"jetbrains.com", "download.jetbrains.com", "stackoverflow.com",
				},
			},
			{
				ID: "cloud", Name: "Cloud & collaboration",
				Description: "Productivity suites, cloud drives and video calls.",
				Domains: []string{
					"microsoft.com", "office.com", "office365.com", "login.microsoftonline.com",
					"sharepoint.com", "onedrive.com", "live.com", "outlook.com",
					"google.com", "gmail.com", "accounts.google.com", "googleapis.com", "gstatic.com",
					"drive.google.com", "meet.google.com", "docs.google.com", "photos.google.com",
					"apple.com", "icloud.com", "icloud-content.com", "mzstatic.com",
					"slack.com", "zoom.us", "teams.microsoft.com", "discord.com", "discord.gg",
					"notion.so", "dropbox.com", "box.com", "evernote.com",
					"atlassian.com", "jira.com", "confluence.com", "trello.com", "figma.com",
					"aws.amazon.com", "amazonaws.com", "azure.microsoft.com", "azureedge.net", "windows.net",
				},
			},
			{
				ID: "banking", Name: "Banking & payments",
				Description: "Common financial services and payment processors.",
				Domains: []string{
					"paypal.com", "www.paypal.com", "paypalobjects.com", "stripe.com", "js.stripe.com",
					"plaid.com", "adyen.com", "adyenpayments.com", "venmo.com", "cash.app",
					"chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com",
					"capitalone.com", "amex.com", "americanexpress.com", "discover.com",
					"payoneer.com", "wise.com", "revolut.com", "monzo.com", "starlingbank.com",
					"intuit.com", "turbotax.intuit.com", "quickbooks.com", "squareup.com",
				},
			},
			{
				ID: "iot", Name: "Smart home & IoT",
				Description: "Smart home hubs, speakers and IoT cloud endpoints.",
				Domains: []string{
					"amazon.com", "amazon.co.uk", "amazon.de", "amazonaws.com",
					"alexa.amazon.com", "skills-alexa.amazon.com",
					"nest.com", "home.nest.com", "nestservices.google.com",
					"googlehome.com", "chromecast.com", "clients3.google.com",
					"apple.com", "icloud.com", "gs-loc.apple.com",
					"philips-hue.com", "meethue.com", "huebridge.com",
					"ring.com", "ringcloud.net", "arq.com", "arq.cloud",
					"ecobee.com", "smartthings.com", "tuya.com", "tuya.io", "tuyaus.com",
					"logitech.com", "samsung.com", "smartthings.eu",
				},
			},
			{
				ID: "news", Name: "News & reference",
				Description: "Major news outlets and reference sites.",
				Domains: []string{
					"nytimes.com", "wsj.com", "washingtonpost.com", "cnn.com", "bbc.com", "bbc.co.uk",
					"reuters.com", "apnews.com", "bloomberg.com", "ft.com", "economist.com",
					"theguardian.com", "theverge.com", "arstechnica.com", "wired.com",
					"wikipedia.org", "wikimedia.org", "wiktionary.org",
					"npr.org", "pbs.org", "cnbc.com", "businessinsider.com",
				},
			},
		},
	}
}
