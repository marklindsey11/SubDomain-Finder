// Package threatbook logic
package threatbook

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type threatBookResponse struct {
	ResponseCode int64  `json:"response_code"`
	VerboseMsg   string `json:"verbose_msg"`
	Data         struct {
		Domain     string `json:"domain"`
		SubDomains struct {
			Total string   `json:"total"`
			Data  []string `json:"data"`
		} `json:"sub_domains"`
	} `json:"data"`
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

func (s *Source) dispatcher(domain string) core.Task {
	task := core.Task{
		Domain: domain,
	}
	randomApiKey := s.GetRandomKey()

	task.RequestOpts = &core.Options{
		Method: http.MethodGet,
		URL:    fmt.Sprintf("https://api.threatbook.cn/v3/domain/sub_domains?apikey=%s&resource=%s", randomApiKey, domain),
		Source: "threatbook",
		UID:    randomApiKey,
	}

	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()

		var response threatBookResponse
		err := jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			return err
		}
		if response.ResponseCode != 0 {
			return fmt.Errorf("code %d, %s", response.ResponseCode, response.VerboseMsg)
		}

		total, err := strconv.ParseInt(response.Data.SubDomains.Total, 10, 64)
		if err != nil {
			return err
		}

		if total > 0 {
			for _, subdomain := range response.Data.SubDomains.Data {
				executor.Result <- core.Result{Source: s.Name(), Type: core.Subdomain, Value: subdomain}
			}
		}
		return nil
	}

	return task
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "threatbook"
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
	s.AddKeys(keys...)
}
