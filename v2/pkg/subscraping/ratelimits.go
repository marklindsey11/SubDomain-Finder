package subscraping

import (
	"math"
	"time"
)

// defaultRateLimits gathered from public sources
var DefaultRateLimits map[string]SourceRateLimit = map[string]SourceRateLimit{
	"github": {
		MaxCount: 30, Duration: time.Minute, //https://docs.github.com/en/rest/search?apiVersion=2022-11-28#rate-limit
	},
	"gitlab": {
		MaxCount: 2000, Duration: time.Minute, // https://docs.gitlab.com/ee/user/gitlab_com/index.html#gitlabcom-specific-rate-limits
	},
	"fullhunt": {
		MaxCount: 60, Duration: time.Minute, // https://api-docs.fullhunt.io/#get-domain-details
	},
	"robotex": {
		MaxCount: math.MaxUint, Duration: time.Millisecond, // https://www.robtex.com/api/
	},
	"securitytrails": {
		MaxCount: 1, Duration: time.Second, // https://docs.securitytrails.com/docs/quotas-rate-limits#:~:text=Rate%20limiting,second%20before%20making%20additional%20requests.
	},
	"shodan": {
		MaxCount: 1, Duration: time.Second, // https://twitter.com/shodanhq/status/860334085373272064?lang=en
	},
	"virustotal": {
		MaxCount: 4, Duration: time.Minute, // https://developers.virustotal.com/reference/public-vs-premium-api
	},

	// Unauthenticated
	"hackertarget": {
		MaxCount: 2, Duration: time.Second, // https://hackertarget.com/ip-tools/
	},
	"threatminer": {
		MaxCount: 10, Duration: time.Minute, // https://www.threatminer.org/api.php
	},
	"waybackarchive": {
		MaxCount: 15, Duration: time.Minute, // https://archive.org/details/toomanyrequests_20191110
	},
	"whoisxmlapi": {
		MaxCount: 50, Duration: time.Second, // https://whois.whoisxmlapi.com/documentation/limits
	},

	// Cannot be Implemented
	"binaryedge": {
		MaxCount: 0, // 250 per month https://www.binaryedge.io/pricing.html
	},
	"bufferover": {
		MaxCount: 0, // 100 req per month https://tls.bufferover.run
	},
	"alienvault": {
		MaxCount: 0, Duration: time.Hour, // 1000 per hour  https://success.alienvault.com/s/question/0D53q00009oRt5pCAC/what-is-the-limit-on-queries-to-the-api-before-they-get-throttled
	},

	//Unverified
	"c99": {
		MaxCount: math.MaxUint, // possibly unlimited api.c99.nl
	},
	"censys": {
		MaxCount: 1, Duration: time.Duration(150) * time.Second,
	},
	"crt.sh": {
		MaxCount: 60, Duration: time.Minute,
	},
}

// SourceRateLimit contains rate limit of a particular source
type SourceRateLimit struct {
	MaxCount uint
	Duration time.Duration
}
