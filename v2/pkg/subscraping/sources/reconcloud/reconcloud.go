// Package reconcloud logic
package reconcloud

import (
	"context"
	"fmt"
	"net/http"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
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
