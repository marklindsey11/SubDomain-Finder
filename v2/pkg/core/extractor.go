package core

import (
	"regexp"

	"github.com/projectdiscovery/gologger"
)

// Extracts valid subdomains from given data
type Extractor struct {
	regexes map[string]*regexp.Regexp
}

// Get returns pointer to subdomain regex and creates one if not available
func (e *Extractor) Get(domain string) *regexp.Regexp {
	if e.regexes[domain] == nil {
		var err error
		e.regexes[domain], err = regexp.Compile(`[a-zA-Z0-9\*_.-]+\.` + domain)
		if err != nil {
			gologger.Error().Msgf("failed to create regex extractor for %v", domain)
			panic(err)
		}
	}
	return e.regexes[domain]
}

func NewExtractor() *Extractor {
	return &Extractor{
		regexes: map[string]*regexp.Regexp{},
	}
}
