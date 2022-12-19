// Package reconcloud logic
package reconcloud

import (
	"context"
	"fmt"
	"net/http"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/v2/pkg/core"
)

type reconCloudResponse struct {
	MsgType         string            `json:"msg_type"`
	RequestID       string            `json:"request_id"`
	OnCache         bool              `json:"on_cache"`
	Step            string            `json:"step"`
	CloudAssetsList []cloudAssetsList `json:"cloud_assets_list"`
}

type cloudAssetsList struct {
	Key           string `json:"key"`
	Domain        string `json:"domain"`
	CloudProvider string `json:"cloud_provider"`
}

// Source is the passive scraping agent
type Source struct {
	timeTaken time.Duration
	errors    int
	results   int
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
	task.RequestOpts = &core.Options{
		Method: http.MethodGet,
		URL:    fmt.Sprintf("https://recon.cloud/api/search?domain=%s", domain),
		Source: "reconcloud",
	}

	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		var response reconCloudResponse
		err := jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			return err
		}
		if len(response.CloudAssetsList) > 0 {
			for _, cloudAsset := range response.CloudAssetsList {
				executor.Result <- core.Result{Source: s.Name(), Type: core.Subdomain, Value: cloudAsset.Domain}
			}
		}
		return nil
	}
	return task
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "reconcloud"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return true
}

func (s *Source) NeedsKey() bool {
	return false
}

func (s *Source) AddApiKeys(_ []string) {
	// no key needed
}
