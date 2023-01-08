// Package crtsh logic
package crtsh

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"strings"

	jsoniter "github.com/json-iterator/go"

	// postgres driver
	_ "github.com/lib/pq"

	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type subdomain struct {
	ID        int    `json:"id"`
	NameValue string `json:"name_value"`
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
	s.BaseSource.RequiresKey = false
	s.BaseSource.CreateTask = s.dispatcher
}

func (s *Source) dispatcher(domain string) core.Task {
	task := core.Task{}
	opts := &core.Options{
		Method: http.MethodGet,
		URL:    fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain),
		Source: "crtsh",
	}
	task.RequestOpts = opts

	task.Override = func(t *core.Task, ctx context.Context, executor *core.Executor) error {
		count, err := getSubdomainsFromSQL(domain, t.RequestOpts.Source, executor)
		if err != nil || count == 0 {
			return fmt.Errorf("fallback to default")
		}
		return nil
	}

	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		var subdomains []subdomain
		err := jsoniter.NewDecoder(resp.Body).Decode(&subdomains)
		if err != nil {
			return err
		}
		for _, subdomain := range subdomains {
			for _, sub := range strings.Split(subdomain.NameValue, "\n") {
				value := executor.Extractor.Get(domain).FindString(sub)
				if value != "" {
					executor.Result <- core.Result{Source: s.Name(), Type: core.Subdomain, Value: value}
				}
			}
		}
		return nil
	}
	return task
}

func getSubdomainsFromSQL(domain string, source string, e *core.Executor) (int, error) {
	db, err := sql.Open("postgres", "host=crt.sh user=guest dbname=certwatch sslmode=disable binary_parameters=yes")
	if err != nil {
		return 0, err
	}
	defer db.Close()

	query := `WITH ci AS (
				SELECT min(sub.CERTIFICATE_ID) ID,
					min(sub.ISSUER_CA_ID) ISSUER_CA_ID,
					array_agg(DISTINCT sub.NAME_VALUE) NAME_VALUES,
					x509_commonName(sub.CERTIFICATE) COMMON_NAME,
					x509_notBefore(sub.CERTIFICATE) NOT_BEFORE,
					x509_notAfter(sub.CERTIFICATE) NOT_AFTER,
					encode(x509_serialNumber(sub.CERTIFICATE), 'hex') SERIAL_NUMBER
					FROM (SELECT *
							FROM certificate_and_identities cai
							WHERE plainto_tsquery('certwatch', $1) @@ identities(cai.CERTIFICATE)
								AND cai.NAME_VALUE ILIKE ('%' || $1 || '%')
							LIMIT 10000
						) sub
					GROUP BY sub.CERTIFICATE
			)
			SELECT array_to_string(ci.NAME_VALUES, chr(10)) NAME_VALUE
				FROM ci
						LEFT JOIN LATERAL (
							SELECT min(ctle.ENTRY_TIMESTAMP) ENTRY_TIMESTAMP
								FROM ct_log_entry ctle
								WHERE ctle.CERTIFICATE_ID = ci.ID
						) le ON TRUE,
					ca
				WHERE ci.ISSUER_CA_ID = ca.ID
				ORDER BY le.ENTRY_TIMESTAMP DESC NULLS LAST;`
	rows, err := db.Query(query, domain)
	if err != nil {
		return 0, err
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}

	var count int
	var data string
	// Parse all the rows getting subdomains
	for rows.Next() {
		err := rows.Scan(&data)
		if err != nil {
			return 0, err
		}

		count++
		for _, subdomain := range strings.Split(data, "\n") {
			value := e.Extractor.Get(domain).FindString(subdomain)
			if value != "" {
				e.Result <- core.Result{Source: source, Type: core.Subdomain, Value: value}
			}
		}
	}
	return count, nil
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "crtsh"
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
