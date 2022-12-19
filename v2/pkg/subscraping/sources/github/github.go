// Package github GitHub search package  (Not usable refactoring needed)
// Based on gwen001's https://github.com/gwen001/github-search github-subdomains
package github

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/tomnomnom/linkheader"
)

type textMatch struct {
	Fragment string `json:"fragment"`
}

type item struct {
	Name        string      `json:"name"`
	HTMLURL     string      `json:"html_url"`
	TextMatches []textMatch `json:"text_matches"`
}

type response struct {
	TotalCount int    `json:"total_count"`
	Items      []item `json:"items"`
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

	headers := map[string]string{
		"Accept": "application/vnd.github.v3.text-match+json", "Authorization": "token " + randomApiKey,
	}

	task.RequestOpts = &core.Options{
		Method:  http.MethodGet,
		URL:     fmt.Sprintf("https://api.github.com/search/code?per_page=1000&q=%s&sort=created&order=asc", domain),
		Headers: headers,
		Source:  "github",
		UID:     randomApiKey,
	}

	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		var data response
		// Marshall json response
		err := jsoniter.NewDecoder(resp.Body).Decode(&data)
		if err != nil {
			return err
		}

		if len(data.Items) > 0 {
			core.Dispatch(func(wg *sync.WaitGroup) {
				defer wg.Done()
				for _, v := range data.Items {
					executor.Task <- s.fetchRepoPage(v.HTMLURL, t.Domain)
				}
			})
		}
		// Links header, first, next, last...
		linksHeader := linkheader.Parse(resp.Header.Get("Link"))
		// Process the next link recursively

		if len(linksHeader) > 0 {
			core.Dispatch(func(wg *sync.WaitGroup) {
				for _, link := range linksHeader {
					if link.Rel == "next" {
						nextURL, err := url.QueryUnescape(link.URL)
						if err != nil {
							gologger.Debug().Label("github").Msg(err.Error())
							continue
						} else {
							tx := t.Clone()
							tx.RequestOpts.URL = nextURL
							executor.Task <- *tx
						}
					}
				}
			})
		}
		return nil
	}
	return task
}

// proccesItems procceses github response items
func (s *Source) fetchRepoPage(itemHtmlUrl string, domain string) core.Task {
	task := core.Task{
		Domain: domain,
	}
	// Note: Here public url is used to fetch commit and is very slow
	// it might be better to use api endpoint
	task.RequestOpts = &core.Options{
		Method: http.MethodGet,
		URL:    rawURL(itemHtmlUrl),
		Source: "github",
		UID:    "unauth",
	}

	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			scanner := bufio.NewScanner(resp.Body)
			for scanner.Scan() {
				line := scanner.Text()
				if line == "" {
					continue
				}
				for _, subdomain := range executor.Extractor.Get(domain).FindAllString(normalizeContent(line), -1) {
					executor.Result <- core.Result{Source: "github", Type: core.Subdomain, Value: subdomain}
				}
			}
		}
		return nil
	}
	return task
}

// Normalize content before matching, query unescape, remove tabs and new line chars
func normalizeContent(content string) string {
	normalizedContent, _ := url.QueryUnescape(content)
	normalizedContent = strings.ReplaceAll(normalizedContent, "\\t", "")
	normalizedContent = strings.ReplaceAll(normalizedContent, "\\n", "")
	return normalizedContent
}

// Raw URL to get the files code and match for subdomains
func rawURL(htmlURL string) string {
	domain := strings.ReplaceAll(htmlURL, "https://github.com/", "https://raw.githubusercontent.com/")
	return strings.ReplaceAll(domain, "/blob/", "/")
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "github"
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
