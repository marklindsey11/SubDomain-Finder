// Package chaos logic
package chaos

import (
	"context"
	"fmt"

	"github.com/projectdiscovery/chaos-client/pkg/chaos"
	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

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
		RequestOpts: &core.Options{
			Source: "chaos",
		},
	}

	// should not reference any variables/methods outside of task
	task.Override = func(t *core.Task, ctx context.Context, executor *core.Executor) error {
		randomApiKey := subscraping.PickRandom(s.apiKeys, t.RequestOpts.Source)
		if randomApiKey == "" {
			// s.skipped = true
			return nil
		}

		chaosClient := chaos.New(randomApiKey)
		for result := range chaosClient.GetSubdomains(&chaos.SubdomainsRequest{
			Domain: t.Domain,
		}) {
			if result.Error != nil {
				executor.Result <- core.Result{Source: t.RequestOpts.Source, Type: core.Error, Error: result.Error}
				break
			}
			executor.Result <- core.Result{
				Source: t.RequestOpts.Source, Type: core.Subdomain, Value: fmt.Sprintf("%s.%s", result.Subdomain, domain),
			}
		}
		return nil // does not fallback to default task execution
	}
	return task
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "chaos"
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
