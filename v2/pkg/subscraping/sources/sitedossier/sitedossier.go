// Package sitedossier logic
package sitedossier

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"

	"github.com/projectdiscovery/subfinder/v2/pkg/core"
)

var reNext = regexp.MustCompile(`<a href="([A-Za-z0-9/.]+)"><b>`)

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
		URL:    fmt.Sprintf("http://www.sitedossier.com/parentdomain/%s", domain),
		Source: "sitedossier",
	}

	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("expected status code 200 got %v", resp.StatusCode)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		src := string(body)
		for _, match := range executor.Extractor.Get(domain).FindAllString(src, -1) {
			executor.Result <- core.Result{Source: "sitedossier", Type: core.Subdomain, Value: match}
		}
		match1 := reNext.FindStringSubmatch(src)
		if len(match1) > 0 {
			tx := t.Clone()
			tx.RequestOpts.URL = "http://www.sitedossier.com" + match1[1]
		}
		return nil
	}
	return task
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "sitedossier"
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
