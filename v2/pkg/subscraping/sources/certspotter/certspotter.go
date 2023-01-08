// Package certspotter logic
package certspotter

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type certspotterObject struct {
	ID       string   `json:"id"`
	DNSNames []string `json:"dns_names"`
}

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
	s.BaseSource.RequiresKey = true
	s.BaseSource.CreateTask = s.dispatcher
}

// Run function returns all subdomains found with the service
func (s *Source) dispatcher(domain string) core.Task {
	task := core.Task{
		Domain: domain,
	}
	randomApiKey := s.BaseSource.GetRandomKey()

	headers := map[string]string{"Authorization": "Bearer " + randomApiKey}

	task.RequestOpts = &core.Options{
		Method:  http.MethodGet,
		URL:     fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain),
		Headers: headers,
		UID:     randomApiKey,
		Source:  "certspotter",
	}

	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		var response []certspotterObject
		err := jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			return err
		}
		for _, cert := range response {
			for _, subdomain := range cert.DNSNames {
				executor.Result <- core.Result{Source: s.Name(), Type: core.Subdomain, Value: subdomain}
			}
		}
		// recursively check until response len is zero https://sslmate.com/help/reference/ct_search_api_v1
		if len(response) == 0 {
			return nil
		}
		id := response[len(response)-1].ID

		core.Dispatch(func(wg *sync.WaitGroup) {
			tx := t.Clone()
			tx.RequestOpts.URL = fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names&after=%s", domain, id)
		})
		return nil
	}
	return task
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "certspotter"
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
	s.BaseSource.AddKeys(keys...)
}
