// Package alienvault logic
package alienvault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type alienvaultResponse struct {
	Detail     string `json:"detail"`
	Error      string `json:"error"`
	PassiveDNS []struct {
		Hostname string `json:"hostname"`
	} `json:"passive_dns"`
}

// Source is the passive scraping agent
type Source struct {
	subscraping.BaseSource
}

// Source Daemon
func (s *Source) Daemon(ctx context.Context, e *core.Extractor, input <-chan string, output chan<- core.Task) {
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
		Method: http.MethodGet,
		URL:    fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain),
		Source: "alienvault",
	}

	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		var response alienvaultResponse
		// Get the response body and decode
		err := json.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			return err
		}
		if response.Error != "" {
			return fmt.Errorf("%s, %s", response.Detail, response.Error)
		}
		for _, record := range response.PassiveDNS {
			executor.Result <- core.Result{Source: "alienvault", Type: core.Subdomain, Value: record.Hostname}
		}
		return nil
	}
	return task
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "alienvault"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return true
}

func (s *Source) NeedsKey() bool {
	return false
}

func (s *Source) AddApiKeys([]string) {
	// no key needed
}
