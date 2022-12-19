// Package passivetotal logic
package passivetotal

import (
	"bytes"
	"context"
	"net/http"
	"regexp"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/v2/pkg/core"
)

var passiveTotalFilterRegex = regexp.MustCompile(`^(?:\d{1,3}\.){3}\d{1,3}\\032`)

type response struct {
	Subdomains []string `json:"subdomains"`
}

// Source is the passive scraping agent
type Source struct {
	apiKeys []apiKey
}

type apiKey struct {
	username string
	password string
}

// Source Daemon
func (s *Source) Daemon(ctx context.Context, e *core.Executor) {
	ctxcancel, cancel := context.WithCancel(ctx)
	defer cancel()

	for {
		select {
		case <-ctxcancel.Done():
			return
		case domain, ok := <-e.Domain:
			if !ok {
				return
			}
			task := s.CreateTask(domain)
			task.RequestOpts.Cancel = cancel // Option to cancel source under certain conditions (ex: ratelimit)
			e.Task <- task
		}
	}
}

func (s *Source) CreateTask(domain string) core.Task {
	task := core.Task{
		Domain: domain,
	}
	randomApiKey := core.PickRandom(s.apiKeys, s.Name())
	if randomApiKey.username == "" || randomApiKey.password == "" {
		return task
	}
	// Create JSON Get body
	var request = []byte(`{"query":"` + domain + `"}`)
	task.RequestOpts = &core.Options{
		Method:      http.MethodGet,
		URL:         "https://api.passivetotal.org/v2/enrichment/subdomains",
		ContentType: "application/json",
		Body:        bytes.NewBuffer(request),
		BasicAuth:   core.BasicAuth{Username: randomApiKey.username, Password: randomApiKey.password},
		Source:      "passivetotal",
		UID:         randomApiKey.username,
	}

	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		var data response
		err := jsoniter.NewDecoder(resp.Body).Decode(&data)
		if err != nil {
			return err
		}

		for _, subdomain := range data.Subdomains {
			// skip entries like xxx.xxx.xxx.xxx\032domain.tld
			if passiveTotalFilterRegex.MatchString(subdomain) {
				continue
			}
			finalSubdomain := subdomain + "." + domain
			executor.Result <- core.Result{Source: s.Name(), Type: core.Subdomain, Value: finalSubdomain}
		}
		return nil
	}
	return task
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "passivetotal"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return true
}

func (s *Source) NeedsKey() bool {
	return true
}

func (s *Source) AddApiKeys(keys []string) {
	s.apiKeys = core.CreateApiKeys(keys, func(k, v string) apiKey {
		return apiKey{k, v}
	})
}
