package core

import (
	"context"
	"sync"
)

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
	Domain    chan string
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

// Wait until task completion
func (e *Executor) Wait() {
	wg.Wait()
}

func NewExecutor(cfg *Config) *Executor {
	exec := Executor{
		Domain:    make(chan string, cfg.InputBufferSize),
		Task:      make(chan Task, cfg.TaskBufferSize),
		Result:    make(chan Result, 10),
		MaxTasks:  cfg.MaxTasks,
		Extractor: NewExtractor(),
		Session:   NewSession(cfg.Proxy, cfg.RateLimit, cfg.Timeout),
	}
	return &exec
}
