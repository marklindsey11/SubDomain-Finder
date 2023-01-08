// Package robtex logic
package robtex

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"sync"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

const (
	addrRecord     = "A"
	iPv6AddrRecord = "AAAA"
	baseURL        = "https://proapi.robtex.com/pdns"
)

// Source is the passive scraping agent
type Source struct {
	subscraping.BaseSource
}

type result struct {
	Rrname string `json:"rrname"`
	Rrdata string `json:"rrdata"`
	Rrtype string `json:"rrtype"`
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
	task := core.Task{
		Domain: domain,
	}
	randomApiKey := s.GetRandomKey()

	task.RequestOpts = &core.Options{
		Method:      http.MethodGet,
		URL:         fmt.Sprintf("%s/forward/%s?key=%s", baseURL, domain, randomApiKey),
		Source:      "robtex",
		ContentType: "application/x-ndjson",
		UID:         randomApiKey,
	}

	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()

		results := []result{}
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}
			var response result
			err := jsoniter.NewDecoder(bytes.NewBufferString(line)).Decode(&response)
			if err != nil {
				return err
			}
			results = append(results, response)
		}

		if len(results) > 0 {
			core.Dispatch(func(wg *sync.WaitGroup) {
				defer wg.Done()
				for _, scanres := range results {
					if scanres.Rrtype == addrRecord || scanres.Rrtype == iPv6AddrRecord {
						tx := core.Task{
							Domain: domain,
						}
						rkey := s.GetRandomKey()

						tx.RequestOpts = &core.Options{
							Method:      http.MethodGet,
							URL:         fmt.Sprintf("%s/reverse/%s?key=%s", baseURL, scanres.Rrdata, rkey),
							Source:      "robtex",
							ContentType: "application/x-ndjson",
							UID:         rkey,
						}

						tx.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
							defer resp.Body.Close()
							scanner := bufio.NewScanner(resp.Body)
							for scanner.Scan() {
								line := scanner.Text()
								if line == "" {
									continue
								}
								var response result
								err := jsoniter.NewDecoder(bytes.NewBufferString(line)).Decode(&response)
								if err != nil {
									return err
								}
								if response.Rrdata != "" {
									executor.Result <- core.Result{Source: s.Name(), Type: core.Subdomain, Value: response.Rrdata}
								}
							}
							return nil
						}
						executor.Task <- tx
					}
				}
			})
		}
		return nil
	}
	return task
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "robtex"
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
	s.AddKeys(keys...)
}
