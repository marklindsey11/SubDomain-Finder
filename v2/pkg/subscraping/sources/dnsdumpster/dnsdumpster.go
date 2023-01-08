// Package dnsdumpster logic
package dnsdumpster

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// CSRFSubMatchLength CSRF regex submatch length
const CSRFSubMatchLength = 2

// wait until all tasks start subtasks if any
var wg *sync.WaitGroup = &sync.WaitGroup{}

var re = regexp.MustCompile("<input type=\"hidden\" name=\"csrfmiddlewaretoken\" value=\"(.*)\">")

// getCSRFToken gets the CSRF Token from the page
func getCSRFToken(page string) string {
	if subs := re.FindStringSubmatch(page); len(subs) == CSRFSubMatchLength {
		return strings.TrimSpace(subs[1])
	}
	return ""
}

// postForm posts a form for a domain and returns the response
func postForm(domain string, token string) core.Task {
	task := core.Task{
		Domain: domain,
	}
	params := url.Values{
		"csrfmiddlewaretoken": {token},
		"targetip":            {domain},
		"user":                {"free"},
	}
	task.RequestOpts = &core.Options{
		Method:  http.MethodPost,
		URL:     "https://dnsdumpster.com/",
		Cookies: fmt.Sprintf("csrftoken=%s; Domain=dnsdumpster.com", token),
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"Referer":      "https://dnsdumpster.com",
			"X-CSRF-Token": token,
		},
		Body:      strings.NewReader(params.Encode()),
		BasicAuth: core.BasicAuth{},
		Source:    "dnsdumpster",
	}

	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		in, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		data := string(in)
		for _, subdomain := range executor.Extractor.Get(domain).FindAllString(data, -1) {
			executor.Result <- core.Result{Source: "dnsdumpster", Type: core.Subdomain, Value: subdomain}
		}
		return nil
	}
	return task
}

// Source is the passive scraping agent
type Source struct {
	subscraping.BaseSource
}

// Source Daemon
func (s *Source) Daemon(ctx context.Context, e *core.Extractor, input <-chan string, output chan<- core.Task) {
	s.BaseSource.Name = s.Name()
	s.init()
	s.BaseSource.Daemon(ctx, e, wg, input, output)
}

// inits the source before passing to daemon
func (s *Source) init() {
	s.BaseSource.RequiresKey = false
	s.BaseSource.CreateTask = s.dispatcher
}

// Run function returns all subdomains found with the service
func (s *Source) dispatcher(domain string) core.Task {
	wg.Add(1)
	task := core.Task{
		Domain: domain,
	}

	task.RequestOpts = &core.Options{
		Method: http.MethodGet,
		URL:    "https://dnsdumpster.com/",
	}

	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		defer wg.Done()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		resp.Body.Close()
		csrfToken := getCSRFToken(string(body))
		if csrfToken == "" {
			return fmt.Errorf("failed to fetch csrf token")
		} else {
			executor.Task <- postForm(domain, csrfToken)
			return nil
		}
	}
	return task
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "dnsdumpster"
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
