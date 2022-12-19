// Package binaryedge logic
package binaryedge

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"sync"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

const (
	v1                = "v1"
	v2                = "v2"
	baseAPIURLFmt     = "https://api.binaryedge.io/%s/query/domains/subdomain/%s"
	v2SubscriptionURL = "https://api.binaryedge.io/v2/user/subscription"
	v1PageSizeParam   = "pagesize"
	pageParam         = "page"
	firstPage         = 1
	maxV1PageSize     = 10000
)

type subdomainsResponse struct {
	Message    string      `json:"message"`
	Title      string      `json:"title"`
	Status     interface{} `json:"status"` // string for v1, int for v2
	Subdomains []string    `json:"events"`
	Page       int         `json:"page"`
	PageSize   int         `json:"pagesize"`
	Total      int         `json:"total"`
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

// Run function returns all subdomains found with the service
func (s *Source) CreateTask(domain string) core.Task {
	task := core.Task{}

	randomApiKey := subscraping.PickRandom(s.apiKeys, s.Name())
	if randomApiKey == "" {
		// s.skipped = true
		return task
	}
	authHeader := map[string]string{"X-Key": randomApiKey}

	task.RequestOpts = &core.Options{
		Method:  http.MethodGet,
		URL:     v2SubscriptionURL,
		Headers: authHeader,
		UID:     randomApiKey,
		Source:  "binaryedge",
	}

	// executes task as described below if return is non-nil fall back to `OnResponse`
	task.Override = func(t *core.Task, ctx context.Context, executor *core.Executor) error {
		var baseURL string
		// check if it is v2
		if isV2(ctx, t.RequestOpts, executor.Session) {
			baseURL = fmt.Sprintf(baseAPIURLFmt, v2, domain)
		} else {
			v1URLWithPageSize, err := addURLParam(fmt.Sprintf(baseAPIURLFmt, v1, domain), v1PageSizeParam, strconv.Itoa(maxV1PageSize))
			if err != nil {
				executor.Result <- core.Result{
					Source: t.RequestOpts.Source, Type: core.Error, Error: err,
				}
				return nil // will not fallback to Onresponse
			}
			baseURL = v1URLWithPageSize.String()
		}
		if baseURL == "" {
			executor.Result <- core.Result{
				Source: t.RequestOpts.Source, Type: core.Error, Error: fmt.Errorf("can't get API URL"),
			}
			return nil // will not fallback to Onresponse
		}
		pageURL, err := addURLParam(baseURL, pageParam, strconv.Itoa(firstPage))
		if err != nil {
			executor.Result <- core.Result{
				Source: t.RequestOpts.Source, Type: core.Error, Error: err,
			}
			return nil // will not fallback to Onresponse
		}
		t.RequestOpts.URL = pageURL.String()
		return fmt.Errorf("fallback to Onresponse")
	}
	// s.enumerate(ctx, session, baseURL, firstPage, authHeader, results)

	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		var response subdomainsResponse
		err := jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			return err
		}
		// Check error messages
		if response.Message != "" && response.Status != nil {
			executor.Result <- core.Result{Source: s.Name(), Type: core.Error, Error: fmt.Errorf(response.Message)}
			return fmt.Errorf(response.Message)
		}
		for _, subdomain := range response.Subdomains {
			executor.Result <- core.Result{Source: s.Name(), Type: core.Subdomain, Value: subdomain}
		}

		// Create new tasks
		core.Dispatch(func(wg *sync.WaitGroup) {
			defer wg.Done()
			// recursion
			totalPages := int(math.Ceil(float64(response.Total) / float64(response.PageSize)))
			nextPage := response.Page + 1
			for currentPage := nextPage; currentPage <= totalPages; currentPage++ {
				tx := t.Clone()
				pageurl, _ := addURLParam(tx.RequestOpts.URL, pageParam, strconv.Itoa(firstPage))
				t.RequestOpts.URL = pageurl.String()
				executor.Task <- *tx
			}
		})
		return nil
	}
	return task
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "binaryedge"
}

func (s *Source) IsDefault() bool {
	return false
}

func (s *Source) HasRecursiveSupport() bool {
	return true
}

func (s *Source) NeedsKey() bool {
	return true
}

func (s *Source) AddApiKeys(keys []string) {
	s.apiKeys = keys
}

func isV2(ctx context.Context, reqopts *core.Options, session *core.Session) bool {
	resp, err := session.Do(ctx, reqopts)
	if err != nil {
		session.DiscardHTTPResponse(resp)
		return false
	}
	resp.Body.Close()
	return true
}

func addURLParam(targetURL, name, value string) (*url.URL, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return u, err
	}
	q, _ := url.ParseQuery(u.RawQuery)
	q.Set(name, value)
	u.RawQuery = q.Encode()
	return u, nil
}
