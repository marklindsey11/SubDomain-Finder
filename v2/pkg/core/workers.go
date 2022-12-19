package core

import (
	"context"
	"sync"
)

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
