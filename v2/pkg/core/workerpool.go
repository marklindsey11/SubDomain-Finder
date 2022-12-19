package core

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// Task
type Task struct {
	Domain      string
	Metdata     any                                                          // Optional metdata
	ExecTime    time.Duration                                                // Time taken to execute this task
	RequestOpts *Options                                                     // Request Options
	Override    func(t *Task, ctx context.Context, executor *Executor) error // Override ignores defined execution methodology and executes task if err is not nil default is executed
	OnResponse  func(t *Task, resp *http.Response, executor *Executor) error // On Response
}

// Executes given task
func (t *Task) Execute(ctx context.Context, e *Executor) {
	defer func(start time.Time) {
		t.ExecTime = time.Since(start)
	}(time.Now())

	if t.Override != nil {
		err := t.Override(t, ctx, e)
		if err == nil {
			return
		}
	}

	resp, err := e.Session.Do(ctx, t.RequestOpts)
	if err != nil && resp == nil {
		e.Result <- Result{
			Source: t.RequestOpts.Source, Type: Error, Error: err,
		}
		e.Session.DiscardHTTPResponse(resp)
		return
	}
	err = t.OnResponse(t, resp, e)
	if err != nil {
		e.Result <- Result{
			Source: t.RequestOpts.Source, Type: Error, Error: err,
		}
	}
}

// Clone // cross check
func (t *Task) Clone() *Task {
	req := *t.RequestOpts
	task := Task{
		Domain:      t.Domain,
		RequestOpts: &req,
		OnResponse:  t.OnResponse,
		Override:    t.Override,
	}
	return &task
}

// Callback function that creates new tasks
type DispatchFunc func(wg *sync.WaitGroup)

// Dispatch creates and adds new tasks to worker pool
// from existing ones and is non blocking in nature
// ex: pagination ,search page etc
func Dispatch(task DispatchFunc) {
	wg.Add(1)
	task(wg)
}
