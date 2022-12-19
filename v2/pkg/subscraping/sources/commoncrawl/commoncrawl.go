// Package commoncrawl logic
package commoncrawl

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/core"
)

const (
	indexURL     = "https://index.commoncrawl.org/collinfo.json"
	maxYearsBack = 5
)

var year = time.Now().Year()

type indexResponse struct {
	ID     string `json:"id"`
	APIURL string `json:"cdx-api"`
}

// Source is the passive scraping agent
type Source struct{}

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

	task.RequestOpts = &core.Options{
		Method: http.MethodGet,
		URL:    indexURL,
		Source: "commoncrawl",
	}

	// search page response
	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()

		var indexes []indexResponse
		err := jsoniter.NewDecoder(resp.Body).Decode(&indexes)
		if err != nil {
			return err
		}
		years := make([]string, 0)
		for i := 0; i < maxYearsBack; i++ {
			years = append(years, strconv.Itoa(year-i))
		}

		searchIndexes := make(map[string]string)
		for _, year := range years {
			for _, index := range indexes {
				if strings.Contains(index.ID, year) {
					if _, ok := searchIndexes[year]; !ok {
						searchIndexes[year] = index.APIURL
						break
					}
				}
			}
		}
		// get subdomains
		core.Dispatch(func(wg *sync.WaitGroup) {
			defer wg.Done()
			for _, apiURL := range searchIndexes {
				executor.Task <- getSubdomains(apiURL, t.Domain)
			}
		})
		return nil
	}
	return task
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "commoncrawl"
}

func (s *Source) IsDefault() bool {
	return false
}

func (s *Source) HasRecursiveSupport() bool {
	return false
}

func (s *Source) NeedsKey() bool {
	return false
}

func (s *Source) AddApiKeys(_ []string) {
	// no key needed
}

func getSubdomains(searchURL, domain string) core.Task {
	task := core.Task{
		Domain: domain,
	}
	task.RequestOpts = &core.Options{
		Method:  http.MethodGet,
		URL:     fmt.Sprintf("%s?url=*.%s", searchURL, domain),
		Headers: map[string]string{"Host": "index.commoncrawl.org"},
		Source:  "commoncrawl",
	}
	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}
			line, _ = url.QueryUnescape(line)
			subdomain := executor.Extractor.Get(t.Domain).FindString(line)
			if subdomain != "" {
				// fix for triple encoded URL
				subdomain = strings.ToLower(subdomain)
				subdomain = strings.TrimPrefix(subdomain, "25")
				subdomain = strings.TrimPrefix(subdomain, "2f")

				executor.Result <- core.Result{Source: t.RequestOpts.Source, Type: core.Subdomain, Value: subdomain}
			}
		}
		return nil
	}
	return task
}
