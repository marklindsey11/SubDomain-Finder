package gitlab

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sync"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/tomnomnom/linkheader"
)

// Source is the passive scraping agent
type Source struct {
	subscraping.BaseSource
}

type item struct {
	Data      string `json:"data"`
	ProjectId int    `json:"project_id"`
	Path      string `json:"path"`
	Ref       string `json:"ref"`
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
		Method:  http.MethodGet,
		URL:     fmt.Sprintf("https://gitlab.com/api/v4/search?scope=blobs&search=%s&per_page=100", domain),
		Headers: map[string]string{"PRIVATE-TOKEN": randomApiKey},
		Source:  "gitlab",
		UID:     randomApiKey,
	}

	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		var items []item
		err := jsoniter.NewDecoder(resp.Body).Decode(&items)
		if err != nil {
			return err
		}
		if len(items) > 0 {
			core.Dispatch(func(wg *sync.WaitGroup) {
				defer wg.Done()
				for _, v := range items {
					executor.Task <- s.fetchRepoPage(v, t.Domain)
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
							gologger.Debug().Label("gitlab").Msg(err.Error())
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

func (s *Source) fetchRepoPage(item item, domain string) core.Task {
	task := core.Task{
		Domain: domain,
	}
	randomApiKey := s.GetRandomKey()
	fileUrl := fmt.Sprintf("https://gitlab.com/api/v4/projects/%d/repository/files/%s/raw?ref=%s", item.ProjectId, url.QueryEscape(item.Path), item.Ref)
	task.RequestOpts = &core.Options{
		Method:  http.MethodGet,
		URL:     fileUrl,
		Headers: map[string]string{"PRIVATE-TOKEN": randomApiKey},
		Source:  "gitlab",
		UID:     randomApiKey,
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
				for _, subdomain := range executor.Extractor.Get(domain).FindAllString(line, -1) {
					executor.Result <- core.Result{Source: "gitlab", Type: core.Subdomain, Value: subdomain}
				}
			}
		}
		return nil
	}
	return task
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "gitlab"
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
