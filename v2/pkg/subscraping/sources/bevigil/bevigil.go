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
	s.BaseSource.RequiresKey = true
	s.BaseSource.CreateTask = s.dispatcher
}

func (s *Source) dispatcher(domain string) core.Task {
	task := core.Task{}
	randomApiKey := s.BaseSource.GetRandomKey()
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
			executor.Result <- core.Result{Source: "bevigil", Type: core.Subdomain, Value: subdomain}
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
	s.BaseSource.AddKeys(keys...)
}
