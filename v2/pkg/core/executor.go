package core

import (
	"context"
	"sync"
)

// internal waitgroup for workers
var wg *sync.WaitGroup = &sync.WaitGroup{}

// Executor Config
type Config struct {
	InputBufferSize int
	TaskBufferSize  int
	MaxTasks        int
	Proxy           string
	RateLimit       int
	Timeout         int
}

// Executor is responsible for executing all tasks obtained from sources
type Executor struct {
	Result    chan Result
	Task      chan Task
	MaxTasks  int
	Session   *Session
	Extractor *Extractor
}

// Create Worker Goroutines
func (e *Executor) CreateWorkers(ctx context.Context) {
	for i := 0; i < e.MaxTasks; i++ {
		wg.Add(1)
		go e.worker(ctx, wg)
	}
}

// workers that execute tasks
func (e *Executor) worker(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case task, ok := <-e.Task:
			if !ok {
				// Task channel closed
				return
			}
			task.Execute(ctx, e)
		}
	}
}

// Wait until task completion
func (e *Executor) Wait() {
	wg.Wait()
	close(e.Result)
}

// NewExecutor returns tasks executor
func NewExecutor(cfg *Config, taskchan chan Task) *Executor {
	exec := Executor{
		Task:      taskchan,
		Result:    make(chan Result, 10),
		MaxTasks:  cfg.MaxTasks,
		Extractor: NewExtractor(),
		Session:   NewSession(cfg.Proxy, cfg.RateLimit, cfg.Timeout),
	}
	return &exec
}
