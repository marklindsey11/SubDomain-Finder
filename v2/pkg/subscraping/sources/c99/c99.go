// Package c99 logic
package c99

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// Source is the passive scraping agent
type Source struct {
	subscraping.BaseSource
}

type dnsdbLookupResponse struct {
	Success    bool `json:"success"`
	Subdomains []struct {
		Subdomain  string `json:"subdomain"`
		IP         string `json:"ip"`
		Cloudflare bool   `json:"cloudflare"`
	} `json:"subdomains"`
	Error string `json:"error"`
}

// Source Daemon
func (s *Source) Daemon(ctx context.Context, e *core.Extractor, input <-chan string, output chan<- core.Task) {
	s.BaseSource.Name = s.Name()
	s.init()
	s.BaseSource.Daemon(ctx, e, nil, input, output)
}

// inits the source before passing to daemon
func (s *Source) init() {
	s.BaseSource.RequiresKey = true
	s.BaseSource.CreateTask = s.dispatcher
}

// Run function returns all subdomains found with the service
func (s *Source) dispatcher(domain string) core.Task {
	task := core.Task{
		Domain: domain,
	}

	randomApiKey := s.BaseSource.GetRandomKey()
	task.RequestOpts = &core.Options{
		Method: http.MethodGet,
		URL:    fmt.Sprintf("https://api.c99.nl/subdomainfinder?key=%s&domain=%s&json", randomApiKey, domain),
		Source: "c99",
		UID:    randomApiKey,
	}

	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		var response dnsdbLookupResponse
		err := jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			return err
		}
		if response.Error != "" {
			return fmt.Errorf("%v", response.Error)
		}
		for _, data := range response.Subdomains {
			if !strings.HasPrefix(data.Subdomain, ".") {
				executor.Result <- core.Result{Source: "c99", Type: core.Subdomain, Value: data.Subdomain}
			}
		}
		return nil
	}
	return task
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "c99"
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
	s.BaseSource.AddKeys(keys...)
}
