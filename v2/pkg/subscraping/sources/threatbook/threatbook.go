// Package threatbook logic
package threatbook

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/core"
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

func (s *Source) CreateTask(domain string) core.Task {
	task := core.Task{
		Domain: domain,
	}
	randomApiKey := core.PickRandom(s.apiKeys, s.Name())
	if randomApiKey == "" {
		return task
	}
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
	s.apiKeys = keys
}
