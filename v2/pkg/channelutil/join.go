package channelutil

import (
	"context"
	"sync"

	errorutil "github.com/projectdiscovery/utils/errors"
)

type JoinChannels[T any] struct {
	// internal
	wg sync.WaitGroup
}

// JoinChannels Joins Many Channels to Create One
func (j *JoinChannels[T]) Join(ctx context.Context, sink chan T, sources ...<-chan T) error {
	if sink == nil {
		return errorutil.New("sink cannot be nil").WithTag("join", "channel")
	}
	if len(sources) == 0 {
		return errorutil.New("sources cannot be zero").WithTag("join", "channel")
	}
	for _, v := range sources {
		if v == nil {
			return errorutil.New("given source is nil").WithTag("join", "channel")
		}
	}

	// Worker only supports 5 channels
	if len(sources)%5 != 0 {
		remaining := 5 - (len(sources) % 5)
		for i := 0; i < remaining; i++ {
			// append nil to arr these are kicked out of select automatically
			sources = append(sources, nil)
		}
	}
	if len(sources) == 5 {
		j.wg.Add(1)
		go j.joinWorker(ctx, sink, sources...)
		return nil
	}

	/*
		If sources > 5
		relay channels are used that relay data from leaf nodes to root node (i.e in this case channel)

		1. sources are grouped into 5 with 1 relay channel for each group
		2. Each group is passed to worker
		3. Relay are fed to Join i.e Recursion
	*/
	/*
		Ex:
			$   $ $   $		 <-  Leaf Channels (i.e Sources)
			 \ /   \ /
		      $  	$		 <-  Relay Channels
			   \   /
			     $           <- Sink Channel

		*Simplicity purpose 2 childs are shown for each node but each node has 5 childs
	*/

	groups := [][]<-chan T{}
	tmp := []<-chan T{}
	for i, v := range sources {
		if i != 0 && i%5 == 0 {
			groups = append(groups, tmp)
			tmp = []<-chan T{}
		}
		tmp = append(tmp, v)
	}
	if len(tmp) > 0 {
		groups = append(groups, tmp)
	}

	relays := []<-chan T{}
	for _, v := range groups {
		relay := make(chan T)
		relays = append(relays, relay)
		j.wg.Add(1)
		go j.joinWorker(ctx, relay, v...)
	}

	// Recursion
	return j.Join(ctx, sink, relays...)
}

// joinWorker is worker goroutine that does actual joining
func (j *JoinChannels[T]) joinWorker(ctx context.Context, sink chan T, sources ...<-chan T) {
	defer j.wg.Done()
	if len(sources) != 5 {
		panic(errorutil.New("worker only supports 5 sources got %v", len(sources)).WithTag("join", "channel", "worker"))
	}
	if sink == nil {
		panic(errorutil.New("sink cannot be nil").WithTag("join", "channel", "worker"))
	}

	// recieve only channels
	src := map[int]<-chan T{}
	for k, v := range sources {
		src[k] = v
	}

	for src[0] != nil || src[1] != nil || src[2] != nil || src[3] != nil || src[4] != nil {
		select {
		case <-ctx.Done():
			close(sink)
			return
		case w, ok := <-src[0]:
			if !ok {
				src[0] = nil
				continue
			}
			sink <- w
		case w, ok := <-src[1]:
			if !ok {
				src[1] = nil
				continue
			}
			sink <- w
		case w, ok := <-src[2]:
			if !ok {
				src[2] = nil
				continue
			}
			sink <- w
		case w, ok := <-src[3]:
			if !ok {
				src[3] = nil
				continue
			}
			sink <- w
		case w, ok := <-src[4]:
			if !ok {
				src[4] = nil
				continue
			}
			sink <- w
		}
	}
	close(sink)
}

// Wait
func (j *JoinChannels[T]) Wait() {
	j.wg.Wait()
}
