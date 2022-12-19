package hunter

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"sync"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/v2/pkg/core"
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

	// hunter api doc https://hunter.qianxin.com/home/helpCenter?r=5-1-2
	qbase64 := base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("domain=\"%s\"", domain)))
	page := 1
	task.RequestOpts = &core.Options{
		Method: http.MethodGet,
		URL:    fmt.Sprintf("https://hunter.qianxin.com/openApi/search?api-key=%s&search=%s&page=%s&page_size=100&is_web=3", randomApiKey, qbase64, page),
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
					tx.RequestOpts.URL = fmt.Sprintf("https://hunter.qianxin.com/openApi/search?api-key=%s&search=%s&page=%s&page_size=100&is_web=3", randomApiKey, qbase64, page)
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
	s.apiKeys = keys
}
