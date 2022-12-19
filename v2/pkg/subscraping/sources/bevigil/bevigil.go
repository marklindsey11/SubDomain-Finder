// Package bevigil logic
package bevigil

import (
	"context"
	"fmt"
	"net/http"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type Response struct {
	Domain     string   `json:"domain"`
	Subdomains []string `json:"subdomains"`
}

type Source struct {
	subscraping.Base
	apiKeys []string
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
	task := core.Task{}

	randomApiKey := subscraping.PickRandom(s.apiKeys, s.Name())
	if randomApiKey == "" {
		// s.skipped = true
		return task
	}

	getUrl := fmt.Sprintf("https://osint.bevigil.com/api/%s/subdomains/", domain)

	task.RequestOpts = &core.Options{
		Method: http.MethodGet,
		URL:    getUrl,
		Headers: map[string]string{
			"X-Access-Token": randomApiKey, "User-Agent": "subfinder",
		},
		Source: "bevigil",
		UID:    randomApiKey,
	}

	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		var subdomains []string
		var response Response
		err := jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			return err
		}
		if len(response.Subdomains) > 0 {
			subdomains = response.Subdomains
		}
		for _, subdomain := range subdomains {
			executor.Result <- core.Result{Source: s.Name(), Type: core.Subdomain, Value: subdomain}
		}
		return nil
	}
	return task
}

func (s *Source) Name() string {
	return "bevigil"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return false
}

func (s *Source) NeedsKey() bool {
	return true
}

func (s *Source) AddApiKeys(keys []string) {
	s.apiKeys = keys
}
