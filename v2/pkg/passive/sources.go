package passive

import (
	"strings"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/alienvault"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/anubis"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/bevigil"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/binaryedge"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/bufferover"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/c99"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/censys"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/certspotter"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/chaos"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/chinaz"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/commoncrawl"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/crtsh"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/digitorus"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/dnsdb"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/dnsdumpster"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/dnsrepo"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/fofa"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/fullhunt"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/github"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/gitlab"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/hackertarget"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/hunter"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/intelx"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/passivetotal"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/quake"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/rapiddns"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/riddler"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/robtex"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/securitytrails"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/shodan"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/sitedossier"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/threatbook"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/virustotal"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/waybackarchive"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/whoisxmlapi"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/zoomeye"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/zoomeyeapi"
)

// NameSourceMap with names mapped to sources
var NameSourceMap = make(map[string]subscraping.Source)

var AllSources = [...]subscraping.Source{
	&alienvault.Source{},
	&anubis.Source{},
	&bevigil.Source{},
	&binaryedge.Source{},
	&bufferover.Source{},
	&c99.Source{},
	&censys.Source{},
	&certspotter.Source{},
	&chaos.Source{},
	&chinaz.Source{},
	&commoncrawl.Source{},
	&crtsh.Source{},
	&digitorus.Source{},
	&dnsdb.Source{},
	&dnsdumpster.Source{},
	&dnsrepo.Source{},
	&fofa.Source{},
	&fullhunt.Source{},
	&github.Source{},
	&gitlab.Source{},
	&hackertarget.Source{},
	&hunter.Source{},
	&intelx.Source{},
	&passivetotal.Source{},
	&quake.Source{},
	&rapiddns.Source{},
	&riddler.Source{},
	&robtex.Source{},
	&securitytrails.Source{},
	&shodan.Source{},
	&sitedossier.Source{},
	&threatbook.Source{},
	&virustotal.Source{},
	&waybackarchive.Source{},
	&whoisxmlapi.Source{},
	&zoomeye.Source{},
	&zoomeyeapi.Source{},
	// &threatminer.Source{}, // failing  api
	// &reconcloud.Source{}, // failing due to cloudflare bot protection
}

func init() {
	for _, currentSource := range AllSources {
		NameSourceMap[strings.ToLower(currentSource.Name())] = currentSource
	}
}
