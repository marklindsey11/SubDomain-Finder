// Package dnsdb logic
package dnsdb

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type dnsdbResponse struct {
	Name string `json:"rrname"`
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

	randomApiKey := s.GetRandomKey()

	headers := map[string]string{
		"X-API-KEY":    randomApiKey,
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	task.RequestOpts = &core.Options{
		Method:  http.MethodGet,
		URL:     fmt.Sprintf("https://api.dnsdb.info/lookup/rrset/name/*.%s?limit=1000000000000", domain),
		Headers: headers,
		Source:  "dnsdb",
		UID:     randomApiKey,
	}

	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}
			var response dnsdbResponse
			err := jsoniter.NewDecoder(bytes.NewBufferString(line)).Decode(&response)
			if err != nil {
				return err
			}
			executor.Result <- core.Result{
				Source: s.Name(), Type: core.Subdomain, Value: strings.TrimSuffix(response.Name, "."),
			}
		}
		return nil
	}
	return task
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "dnsdb"
}

func (s *Source) IsDefault() bool {
	return false
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
