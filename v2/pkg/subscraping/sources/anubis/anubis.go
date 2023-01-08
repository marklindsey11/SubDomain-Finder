// Package anubis logic
package anubis

import (
	"context"
	"fmt"
	"net/http"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// Source is the passive scraping agent
type Source struct {
	subscraping.BaseSource
}

// Source Daemon
func (s *Source) Daemon(ctx context.Context, e *core.Extractor, input <-chan string, output chan<- core.Task) {
	s.BaseSource.Name = s.Name()
	s.init()
	s.BaseSource.Daemon(ctx, e, nil, input, output)
}

// inits the source before passing to daemon
func (s *Source) init() {
	s.BaseSource.RequiresKey = false
	s.BaseSource.CreateTask = s.dispatcher
}

func (s *Source) dispatcher(domain string) core.Task {
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
