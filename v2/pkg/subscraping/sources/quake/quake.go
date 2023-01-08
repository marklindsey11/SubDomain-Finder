// Package quake logic
package quake

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type quakeResults struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    []struct {
		Service struct {
			HTTP struct {
				Host string `json:"host"`
			} `json:"http"`
		}
	} `json:"data"`
	Meta struct {
		Pagination struct {
			Total int `json:"total"`
		} `json:"pagination"`
	} `json:"meta"`
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
	// quake api doc https://quake.360.cn/quake/#/help
	var requestBody = []byte(fmt.Sprintf(`{"query":"domain: *.%s", "start":0, "size":500}`, domain))
	task.RequestOpts = &core.Options{
		Method: http.MethodPost,
		URL:    "https://quake.360.cn/api/v3/search/quake_service",
		Headers: map[string]string{
			"Content-Type": "application/json", "X-QuakeToken": randomApiKey,
		},
		Body:   bytes.NewReader(requestBody),
		Source: "quake",
		UID:    randomApiKey,
	}

	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		var response quakeResults
		err := jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			return err
		}
		if response.Code != 0 {
			return fmt.Errorf("%s", response.Message)
		}
		if response.Meta.Pagination.Total > 0 {
			for _, quakeDomain := range response.Data {
				subdomain := quakeDomain.Service.HTTP.Host
				if strings.ContainsAny(subdomain, "暂无权限") {
					subdomain = ""
				}
				executor.Result <- core.Result{Source: s.Name(), Type: core.Subdomain, Value: subdomain}
			}
		}
		return nil
	}
	return task
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "quake"
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
