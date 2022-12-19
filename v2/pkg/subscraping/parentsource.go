package subscraping

import (
	"context"

	"github.com/projectdiscovery/subfinder/v2/pkg/core"
)

type Base struct {
	CreateTask func(string) core.Task
}

// Source Daemon
func (s *Base) Daemon(ctx context.Context, e *core.Executor) {
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
