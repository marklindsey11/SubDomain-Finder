package subscraping

import (
	"context"
	"math/rand"
	"sync"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/core"
)

type BaseSource struct {
	CreateTask  func(domain string) core.Task
	Keys        []string
	RequiresKey bool   // Requires keys
	Name        string // Source Name
}

// Source Daemon
func (s *BaseSource) Daemon(ctx context.Context, e *core.Extractor, wg *sync.WaitGroup, input <-chan string, output chan<- core.Task) {
	ctxcancel, cancel := context.WithCancel(ctx)
	defer cancel()

	if s.RequiresKey && len(s.Keys) == 0 {
		// keys missing
		gologger.Debug().Label(s.Name).Msgf("missing api keys. skipping..")
	}
	for {
		select {
		case <-ctxcancel.Done():
			if wg != nil {
				wg.Wait()
			}
			close(output)
			return
		case domain, ok := <-input:
			if !ok {
				if wg != nil {
					wg.Wait()
				}
				gologger.Debug().Msgf("closing %v\n", s.Name)
				close(output)
				return
			}
			task := s.CreateTask(domain)
			task.RequestOpts.Cancel = cancel // Option to cancel source under certain conditions (ex: ratelimit)
			if task.RequestOpts != nil {
				output <- task
			}
		}
	}
}

func (s *BaseSource) AddKeys(key ...string) {
	if s.Keys == nil {
		s.Keys = []string{}
	}
	s.Keys = append(s.Keys, key...)
}

// GetKey returns a random key
func (s *BaseSource) GetRandomKey() string {
	length := len(s.Keys)
	return s.Keys[rand.Intn(length)]
}
