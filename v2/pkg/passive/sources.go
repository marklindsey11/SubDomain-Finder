package passive

import (
	"fmt"
	"strings"

	"golang.org/x/exp/maps"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// var AllSources = [...]subscraping.Source{
// 	&alienvault.Source{},
// 	&anubis.Source{},
// 	&bevigil.Source{},
// 	&binaryedge.Source{},
// 	&bufferover.Source{},
// 	&c99.Source{},
// 	&censys.Source{},
// 	&certspotter.Source{},
// 	&chaos.Source{},
// 	&chinaz.Source{},
// 	&commoncrawl.Source{},
// 	&crtsh.Source{},
// 	&digitorus.Source{},
// 	&dnsdb.Source{},
// 	&dnsdumpster.Source{},
// 	&dnsrepo.Source{},
// 	&fofa.Source{},
// 	&fullhunt.Source{},
// 	&github.Source{},
// 	&gitlab.Source{},
// 	&hackertarget.Source{},
// 	&hunter.Source{},
// 	&intelx.Source{},
// 	&passivetotal.Source{},
// 	&quake.Source{},
// 	&rapiddns.Source{},
// 	&riddler.Source{},
// 	&robtex.Source{},
// 	&securitytrails.Source{},
// 	&shodan.Source{},
// 	&sitedossier.Source{},
// 	&threatbook.Source{},
// 	&virustotal.Source{},
// 	&waybackarchive.Source{},
// 	&whoisxmlapi.Source{},
// 	&zoomeye.Source{},
// 	&zoomeyeapi.Source{},
// 	// &threatminer.Source{}, // failing  api
// 	// &reconcloud.Source{}, // failing due to cloudflare bot protection
// }

var NameSourceMap = make(map[string]subscraping.Source)

func init() {
	// for _, currentSource := range AllSources {
	// 	NameSourceMap[strings.ToLower(currentSource.Name())] = currentSource
	// }
}

// Agent is a struct for running passive subdomain enumeration
// against a given host. It wraps subscraping package and provides
// a layer to build upon.
type Agent struct {
	sources []subscraping.Source
}

// New creates a new agent for passive subdomain discovery
func New(sourceNames, excludedSourceNames []string, useAllSources, useSourcesSupportingRecurse bool) *Agent {
	sources := make(map[string]subscraping.Source)

	if useAllSources {
		maps.Copy(sources, NameSourceMap)
	} else {
		if len(sourceNames) > 0 {
			for _, source := range sourceNames {
				if NameSourceMap[source] == nil {
					gologger.Warning().Msgf("There is no source with the name: '%s'", source)
				} else {
					sources[source] = NameSourceMap[source]
				}
			}
		} else {
			// for _, currentSource := range AllSources {
			// 	if currentSource.IsDefault() {
			// 		sources[currentSource.Name()] = currentSource
			// 	}
			// }
		}
	}

	if len(excludedSourceNames) > 0 {
		for _, sourceName := range excludedSourceNames {
			delete(sources, sourceName)
		}
	}

	if useSourcesSupportingRecurse {
		for sourceName, source := range sources {
			if !source.HasRecursiveSupport() {
				delete(sources, sourceName)
			}
		}
	}

	gologger.Debug().Msgf(fmt.Sprintf("Selected source(s) for this search: %s", strings.Join(maps.Keys(sources), ", ")))

	// Create the agent, insert the sources and remove the excluded sources
	agent := &Agent{sources: maps.Values(sources)}

	return agent
}
