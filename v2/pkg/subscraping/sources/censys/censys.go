// Package censys logic
package censys

import (
	"bytes"
	"context"
	"math"
	"net/http"
	"strconv"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

const maxCensysPages = 10

type resultsq struct {
	Data  []string `json:"parsed.extensions.subject_alt_name.dns_names"`
	Data1 []string `json:"parsed.names"`
}

type response struct {
	Results  []resultsq `json:"results"`
	Metadata struct {
		Pages int `json:"pages"`
	} `json:"metadata"`
}

// Source is the passive scraping agent
type Source struct {
	apiKeys []apiKey
}

type apiKey struct {
	token  string
	secret string
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
	if randomApiKey.token == "" || randomApiKey.secret == "" {
		return task
	}

	task.RequestOpts = &core.Options{
		Method:    http.MethodPost,
		URL:       "https://search.censys.io/api/v1/search/certificates",
		Headers:   map[string]string{"Content-Type": "application/json", "Accept": "application/json"},
		Body:      getRequestBody(domain, 1),
		BasicAuth: core.BasicAuth{Username: randomApiKey.token, Password: randomApiKey.secret},
		Source:    "censys",
		UID:       randomApiKey.token,
	}
	task.Metdata = 1

	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		var censysResponse response
		err := jsoniter.NewDecoder(resp.Body).Decode(&censysResponse)
		if err != nil {
			return err
		}

		for _, res := range censysResponse.Results {
			for _, part := range res.Data {
				executor.Result <- core.Result{Source: t.RequestOpts.Source, Type: core.Subdomain, Value: part}
			}
			for _, part := range res.Data1 {
				executor.Result <- core.Result{Source: t.RequestOpts.Source, Type: core.Subdomain, Value: part}
			}
		}

		// fetch next pages
		if currentPage, ok := t.Metdata.(int); ok {
			minfloat := math.Min(float64(censysResponse.Metadata.Pages), maxCensysPages)
			min := int(minfloat)
			if currentPage < min {
				for currentPage < min {
					currentPage++
					newtask := t.Clone()
					t.Metdata = currentPage
					newtask.RequestOpts.Body = getRequestBody(t.Domain, currentPage)
					executor.Task <- *newtask
				}
			}
		}
		return nil
	}
	return task
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "censys"
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
	s.apiKeys = subscraping.CreateApiKeys(keys, func(k, v string) apiKey {
		return apiKey{k, v}
	})
}

func getRequestBody(domain string, currentPage int) *bytes.Reader {
	body := []byte(`{"query":"` + domain + `", "page":` + strconv.Itoa(currentPage) + `, "fields":["parsed.names","parsed.extensions.subject_alt_name.dns_names"], "flatten":true}`)
	return bytes.NewReader(body)
}
