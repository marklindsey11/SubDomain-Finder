// Package whoisxmlapi logic
package whoisxmlapi

import (
	"context"
	"fmt"
	"net/http"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/core"
)

type response struct {
	Search string `json:"search"`
	Result Result `json:"result"`
}

type Result struct {
	Count   int      `json:"count"`
	Records []Record `json:"records"`
}

type Record struct {
	Domain    string `json:"domain"`
	FirstSeen int    `json:"firstSeen"`
	LastSeen  int    `json:"lastSeen"`
}

// Source is the passive scraping agent
type Source struct {
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
	task := core.Task{
		Domain: domain,
	}
	randomApiKey := core.PickRandom(s.apiKeys, s.Name())
	if randomApiKey == "" {
		return task
	}
	task.RequestOpts = &core.Options{
		Method: http.MethodGet,
		URL:    fmt.Sprintf("https://subdomains.whoisxmlapi.com/api/v1?apiKey=%s&domainName=%s", randomApiKey, domain),
		Source: "whoisxmlapi",
		UID:    randomApiKey,
	}

	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		var data response
		err := jsoniter.NewDecoder(resp.Body).Decode(&data)
		if err != nil {
			return err
		}
		for _, record := range data.Result.Records {
			executor.Result <- core.Result{Source: s.Name(), Type: core.Subdomain, Value: record.Domain}
		}
		return nil
	}
	return task
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "whoisxmlapi"
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
