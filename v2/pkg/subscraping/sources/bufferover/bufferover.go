// Package bufferover is a bufferover Scraping Engine in Golang
package bufferover

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type response struct {
	Meta struct {
		Errors []string `json:"Errors"`
	} `json:"Meta"`
	FDNSA   []string `json:"FDNS_A"`
	RDNS    []string `json:"RDNS"`
	Results []string `json:"Results"`
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

// Run function returns all subdomains found with the service
func (s *Source) CreateTask(domain string) core.Task {
	task := core.Task{
		Domain: domain,
	}
	randomApiKey := subscraping.PickRandom(s.apiKeys, s.Name())
	if randomApiKey == "" {
		return task
	}

	task.RequestOpts = &core.Options{
		Method:  http.MethodGet,
		URL:     fmt.Sprintf("https://tls.bufferover.run/dns?q=.%s", domain),
		Headers: map[string]string{"x-api-key": randomApiKey},
		Source:  "bufferover",
		UID:     randomApiKey,
	}

	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		var bufforesponse response
		err := jsoniter.NewDecoder(resp.Body).Decode(&bufforesponse)
		if err != nil {
			return err
		}
		metaErrors := bufforesponse.Meta.Errors
		if len(metaErrors) > 0 {
			return fmt.Errorf("%s", strings.Join(metaErrors, ", "))
		}

		var subdomains []string
		if len(bufforesponse.FDNSA) > 0 {
			subdomains = bufforesponse.FDNSA
			subdomains = append(subdomains, bufforesponse.RDNS...)
		} else if len(bufforesponse.Results) > 0 {
			subdomains = bufforesponse.Results
		}

		for _, subdomain := range subdomains {
			for _, value := range executor.Extractor.Get(t.Domain).FindAllString(subdomain, -1) {
				executor.Result <- core.Result{Source: s.Name(), Type: core.Subdomain, Value: value}
			}
		}
		return nil
	}
	return task
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "bufferover"
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
	s.apiKeys = keys
}
