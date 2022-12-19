// Package anubis logic
package anubis

import (
	"context"
	"fmt"
	"net/http"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/v2/pkg/core"
)

// Source is the passive scraping agent
type Source struct {
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
	task.RequestOpts = &core.Options{
		Method: http.MethodGet, URL: fmt.Sprintf("https://jonlu.ca/anubis/subdomains/%s", domain),
		Source: "anubis",
	}

	task.OnResponse = func(t *core.Task, resp *http.Response, e *core.Executor) error {
		defer resp.Body.Close()
		var subdomains []string
		err := jsoniter.NewDecoder(resp.Body).Decode(&subdomains)
		if err != nil {
			return err
		}
		for _, record := range subdomains {
			e.Result <- core.Result{Source: s.Name(), Type: core.Subdomain, Value: record}
		}
		return nil
	}

	return task
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "anubis"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return false
}

func (s *Source) NeedsKey() bool {
	return false
}

func (s *Source) AddApiKeys(_ []string) {
	// no key needed
}
