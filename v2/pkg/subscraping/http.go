package subscraping

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/corpix/uarand"
	"github.com/projectdiscovery/ratelimit"

	"github.com/projectdiscovery/gologger"
)

// Options contains request options
type Options struct {
	Method      string
	URL         string
	Cookies     string
	Headers     map[string]string
	ContentType string
	Body        io.Reader
	Source      string
	UID         string             // API Key (used for UID) in ratelimit
	Cancel      context.CancelFunc // To be used when ratelimit is hit
	BasicAuth   BasicAuth          // Basic Auth
}

func (o *Options) getRequest(ctx context.Context) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, o.Method, o.URL, o.Body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", uarand.GetRandom())
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en")
	req.Header.Set("Connection", "close")

	if o.BasicAuth.Username != "" || o.BasicAuth.Password != "" {
		req.SetBasicAuth(o.BasicAuth.Username, o.BasicAuth.Password)
	}

	if o.Cookies != "" {
		req.Header.Set("Cookie", o.Cookies)
	}
	if o.Headers != nil {
		for k, v := range o.Headers {
			req.Header.Add(k, v)
		}
	}
	if o.ContentType != "" {
		req.Header.Add("Content-Type", o.ContentType)
	}

	return req, nil
}

// NewSession creates a new session object for a domain
func NewSession(domain string, proxy string, rateLimit, timeout int) (*Session, error) {
	Transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		Dial: (&net.Dialer{
			Timeout: time.Duration(timeout) * time.Second,
		}).Dial,
	}

	// Add proxy
	if proxy != "" {
		proxyURL, _ := url.Parse(proxy)
		if proxyURL == nil {
			// Log warning but continue anyway
			gologger.Warning().Msgf("Invalid proxy provided: '%s'", proxy)
		} else {
			Transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := &http.Client{
		Transport: Transport,
		Timeout:   time.Duration(timeout) * time.Second,
	}

	session := &Session{Client: client}

	// Initiate rate limit instance
	if rateLimit != 0 {
		session.RateLimiter, _ = ratelimit.NewMultiLimiter(context.TODO(), &ratelimit.Options{
			Key:      "default", // for sources with unknown ratelimits
			MaxCount: uint(rateLimit),
			Duration: time.Minute, // from observations refer DefaultRateLimits
		})
	}

	// Create a new extractor object for the current domain
	extractor, err := NewSubdomainExtractor(domain)
	session.Extractor = extractor

	return session, err
}

func (s *Session) ratelimit(opts *Options) {
	// ratelimit disabled
	if s.RateLimiter == nil {
		return
	}
	sourceId := opts.Source
	if opts.UID != "" {
		sourceId += "-" + opts.UID
	}
	// check if ratelimit of this source is available
	source, ok := DefaultRateLimits[opts.Source]
	if !ok || source.MaxCount == 0 {
		// When ratelimit is unknown or not possible to implement
		// use default rate limit with user defined value
		sourceId = "default"
	}
	err := s.RateLimiter.Take(sourceId)
	if err != nil {
		// does not exist
		if err = s.RateLimiter.Add(&ratelimit.Options{
			Key:         sourceId,
			IsUnlimited: false,
			MaxCount:    source.MaxCount,
			Duration:    source.Duration,
		}); err != nil {
			gologger.Debug().Label("Err").Msgf("failed to create new ratelimit: %v", err)
		}
		if errx := s.RateLimiter.Take(sourceId); errx != nil {
			gologger.Debug().Label("Err").Msgf("failed to take ratelimit: %v", err)
		}
	}
}

// Do creates , sends http request and returns response
func (s *Session) Do(ctx context.Context, opts *Options) (*http.Response, error) {
	req, err := opts.getRequest(ctx)
	if err != nil {
		return nil, err
	}
	s.ratelimit(opts)
	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, err
	}
	// Check If Rate Limit was hit
	if resp.StatusCode == 429 || (resp.StatusCode == 204 && opts.Source == "censys") {
		// time after which ratelimit will be reset
		var rlwaittime time.Duration
		if rl, ok := DefaultRateLimits[opts.Source]; ok {
			rlwaittime = rl.Duration
		}
		if resp.Header.Get("Retry-After") != "" {
			retryAfter, er := strconv.Atoi(resp.Header.Get("Retry-After"))
			if er != nil {
				rlwaittime = time.Duration(retryAfter) * time.Second
			}
		}
		if rlwaittime == 0 || rlwaittime > time.Duration(5)*time.Second {
			if opts.Cancel != nil {
				opts.Cancel()
			} // Stop source completely
			gologger.Debug().Label("RTL").MsgFunc(func() string {
				if rlwaittime == 0 {
					return fmt.Sprintf("rate limit exceeded for source %v skipping...", opts.Source)
				} else {
					return fmt.Sprintf("rate limit exceeded for source %v refresh time too high %v.skipping source", opts.Source, rlwaittime)
				}
			})
		} else {
			// sleep and reset (will be implemented in retryablehttp-go)
			s.RateLimiter.SleepandReset(rlwaittime, &ratelimit.Options{
				Key:      opts.Source,
				MaxCount: 1,
				Duration: time.Second,
			})
		}
		return nil, fmt.Errorf("ratelimit hit")
	}
	if resp.StatusCode != http.StatusOK {
		requestURL, _ := url.QueryUnescape(req.URL.String())

		gologger.Debug().MsgFunc(func() string {
			buffer := new(bytes.Buffer)
			_, _ = buffer.ReadFrom(resp.Body)
			return fmt.Sprintf("Response for failed request against '%s':\n%s", requestURL, buffer.String())
		})
		return resp, fmt.Errorf("unexpected status code %d received from '%s'", resp.StatusCode, requestURL)
	}
	return resp, nil
}

// DiscardHTTPResponse discards the response content by demand
func (s *Session) DiscardHTTPResponse(response *http.Response) {
	if response != nil {
		_, err := io.Copy(io.Discard, response.Body)
		if err != nil {
			gologger.Warning().Msgf("Could not discard response body: %s\n", err)
			return
		}
		response.Body.Close()
	}
}
