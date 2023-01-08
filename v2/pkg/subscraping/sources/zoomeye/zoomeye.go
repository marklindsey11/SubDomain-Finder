// Package zoomeye logic
package zoomeye

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// zoomAuth holds the ZoomEye credentials
type zoomAuth struct {
	User string `json:"username"`
	Pass string `json:"password"`
}

type loginResp struct {
	JWT string `json:"access_token"`
}

// search results
type zoomeyeResults struct {
	Matches []struct {
		Site    string   `json:"site"`
		Domains []string `json:"domains"`
	} `json:"matches"`
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

	apiusername, apipassword, _ := subscraping.GetMultiPartKey(s.GetRandomKey())

	creds := &zoomAuth{
		User: apiusername,
		Pass: apipassword,
	}
	body, err := json.Marshal(&creds)
	if err != nil {
		return task
	}

	task.RequestOpts = &core.Options{
		Method:  http.MethodPost,
		URL:     "https://api.zoomeye.org/user/login",
		Cookies: "application/json",
		Body:    bytes.NewBuffer(body),
		Source:  "zoomeye",
	}

	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		var login loginResp
		err = json.NewDecoder(resp.Body).Decode(&login)
		if err != nil {
			return fmt.Errorf("failed to fetch jwt token after login: %v", err)
		}
		jwtToken := login.JWT
		if jwtToken == "" {
			return fmt.Errorf("jwt missing skipping source")
		}

		core.Dispatch(func(wg *sync.WaitGroup) {
			defer wg.Done()
			headers := map[string]string{
				"Authorization": fmt.Sprintf("JWT %s", jwtToken),
				"Accept":        "application/json",
				"Content-Type":  "application/json",
			}
			//TODO: check if it possible to fetch number of pages
			for currentPage := 0; currentPage <= 100; currentPage++ {
				tx := core.Task{
					Domain: domain,
				}
				tx.RequestOpts = &core.Options{
					Method:  http.MethodGet,
					URL:     fmt.Sprintf("https://api.zoomeye.org/web/search?query=hostname:%s&page=%d", domain, currentPage),
					Headers: headers,
					UID:     jwtToken,
					Source:  "zoomeye",
				}
				tx.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
					defer resp.Body.Close()
					if resp.StatusCode != 200 {
						return fmt.Errorf("got %v status code expected 200", resp.StatusCode)
					}
					var res zoomeyeResults
					err := json.NewDecoder(resp.Body).Decode(&res)
					if err != nil {
						return err
					}
					for _, r := range res.Matches {
						executor.Result <- core.Result{Source: s.Name(), Type: core.Subdomain, Value: r.Site}
						for _, domain := range r.Domains {
							executor.Result <- core.Result{Source: s.Name(), Type: core.Subdomain, Value: domain}
						}
					}
					return nil
				}
			}
		})
		return nil
	}
	return task
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "zoomeye"
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
