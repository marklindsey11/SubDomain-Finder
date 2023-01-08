// Package fofa logic
package fofa

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type fofaResponse struct {
	Error   bool     `json:"error"`
	ErrMsg  string   `json:"errmsg"`
	Size    int      `json:"size"`
	Results []string `json:"results"`
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
	apiusername, apisecret, _ := subscraping.GetMultiPartKey(s.GetRandomKey())

	qbase64 := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("domain=\"%s\"", domain)))
	task.RequestOpts = &core.Options{
		Method: http.MethodGet,
		URL:    fmt.Sprintf("https://fofa.info/api/v1/search/all?full=true&fields=host&page=1&size=10000&email=%s&key=%s&qbase64=%s", apiusername, apisecret, qbase64),
		Source: "fofa",
		UID:    apisecret,
	}

	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		var response fofaResponse
		err := jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			return err
		}
		if response.Error {
			return fmt.Errorf("%s", response.ErrMsg)
		}
		if response.Size > 0 {
			for _, subdomain := range response.Results {
				if strings.HasPrefix(strings.ToLower(subdomain), "http://") || strings.HasPrefix(strings.ToLower(subdomain), "https://") {
					subdomain = subdomain[strings.Index(subdomain, "//")+2:]
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
	return "fofa"
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
