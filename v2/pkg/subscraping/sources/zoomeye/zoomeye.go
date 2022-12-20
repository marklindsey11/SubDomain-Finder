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
	apiKeys []apiKey
}

type apiKey struct {
	username string
	password string
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
	if randomApiKey.username == "" || randomApiKey.password == "" {
		return task
	}

	creds := &zoomAuth{
		User: randomApiKey.username,
		Pass: randomApiKey.password,
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
	s.apiKeys = core.CreateApiKeys(keys, func(k, v string) apiKey {
		return apiKey{k, v}
	})
}
