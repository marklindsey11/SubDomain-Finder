package hunter

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"sync"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type hunterResp struct {
	Code    int        `json:"code"`
	Data    hunterData `json:"data"`
	Message string     `json:"message"`
}

type infoArr struct {
	URL      string `json:"url"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Domain   string `json:"domain"`
	Protocol string `json:"protocol"`
}

type hunterData struct {
	InfoArr []infoArr `json:"arr"`
	Total   int       `json:"total"`
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

	// hunter api doc https://hunter.qianxin.com/home/helpCenter?r=5-1-2
	qbase64 := base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("domain=\"%s\"", domain)))
	page := 1
	task.RequestOpts = &core.Options{
		Method: http.MethodGet,
		URL:    fmt.Sprintf("https://hunter.qianxin.com/openApi/search?api-key=%s&search=%s&page=%v&page_size=100&is_web=3", randomApiKey, qbase64, page),
		Source: "hunter",
		UID:    randomApiKey,
	}

	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		var response hunterResp
		err := jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			return err
		}
		if response.Code == 401 || response.Code == 400 {
			return fmt.Errorf("%s", response.Message)
		}
		if response.Data.Total > 0 {
			for _, hunterInfo := range response.Data.InfoArr {
				subdomain := hunterInfo.Domain
				executor.Result <- core.Result{Source: "hunter", Type: core.Subdomain, Value: subdomain}
			}
		}
		pages := int(response.Data.Total/1000) + 1
		if pages > 1 {
			core.Dispatch(func(wg *sync.WaitGroup) {
				defer wg.Done()
				for i := 2; i < pages; i++ {
					tx := t.Clone()
					randomApiKey := s.GetRandomKey()
					tx.RequestOpts.URL = fmt.Sprintf("https://hunter.qianxin.com/openApi/search?api-key=%s&search=%s&page=%v&page_size=100&is_web=3", randomApiKey, qbase64, page)
					executor.Task <- task
				}
			})
		}
		return nil
	}
	return task
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "hunter"
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
