package channelutil

import (
	"context"
	"sync"

	errorutil "github.com/projectdiscovery/utils/errors"
)

// SplitChannels provides method to split channels
type SplitChannels[T any] struct {
	MaxDrain  int // Max buffers to drain at once(default 3)
	Threshold int // Threshold(default 5) is buffer length at which drains are activated

	// Internal
	wg sync.WaitGroup
}

// Split takes data from source channel(src) and sends them to sinks(send only channel) without being unfair
func (s *SplitChannels[T]) Split(ctx context.Context, src chan T, sinks ...chan<- T) error {
	if src == nil {
		return errorutil.New("source channel is nil").WithTag("split", "channel")
	}

	for _, ch := range sinks {
		if ch == nil {
			return errorutil.New("nil sink found").WithTag("split", "channel")
		}
	}

	if s.MaxDrain == 0 {
		s.MaxDrain = 3
	}
	if s.Threshold == 0 {
		s.Threshold = 5
	}

	// Worker Only Supports 5 sinks for now
	if len(sinks)%5 != 0 {
		remaining := 5 - (len(sinks) % 5)
		for i := 0; i < remaining; i++ {
			// add nil channels these are automatically kicked out of select
			sinks = append(sinks, nil)
		}
	}

	if len(sinks) == 5 {
		s.wg.Add(1)
		go s.splitChanWorker(ctx, src, sinks...)
		return nil
	}

	/*
		If sinks > 5
		relay channels are used that relay data from root node to leaf node (i.e in this case channel)

		1. sinks are grouped into 5 with 1 relay channel for each group
		2. Each group is passed to worker
		3. Relay are fed to Split i.e Recursion
	*/
	/*
			Ex:
					   $ 			 <-  Source Channel
				     /   \
				    $  	  $			 <-  Relay Channels
			       / \ 	 / \
			      $   $ $   $		 <-  Leaf Channels (i.e Sinks)

		*Simplicity purpose 2 childs are shown for each node but each node has 5 childs
	*/

	groups := [][]chan<- T{}
	tmp := []chan<- T{}
	for i, v := range sinks {
		if i != 0 && i%5 == 0 {
			groups = append(groups, tmp)
			tmp = []chan<- T{}
		}
		tmp = append(tmp, v)
	}
	if len(tmp) > 0 {
		groups = append(groups, tmp)
	}

	relaychannels := []chan<- T{}
	// launch worker groups
	for _, v := range groups {
		relay := make(chan T)
		relaychannels = append(relaychannels, relay)
		s.wg.Add(1)
		go s.splitChanWorker(ctx, relay, v...)
	}

	// recursion use sources to feed relays
	return s.Split(ctx, src, relaychannels...)
}

// splitChanWorker is actual worker goroutine
func (s *SplitChannels[T]) splitChanWorker(ctx context.Context, src chan T, sinkchans ...chan<- T) {
	defer s.wg.Done()
	if src == nil {
		panic(errorutil.New("source channel is nil").WithTag("split", "channel", "worker"))
	}
	if len(sinkchans) != 5 {
		panic(errorutil.New("expected total sinks 5 but got %v", len(sinkchans)).WithTag("split", "channel", "worker"))
	}

	sink := map[int]chan<- T{}
	count := 0
	for _, v := range sinkchans {
		sink[count] = v
		count++
	}
	// backlog tracks sink channels whose buffers have reached threshold
	backlog := map[int]struct{}{}
	buffer := map[int][]T{}

	// Helper Functions
	// addToBuff adds data to buffers where data was not sent
	addToBuff := func(id int, value T) {
		for sid, ch := range sink {
			if ch != nil && id != sid {
				if buffer[sid] == nil {
					buffer[sid] = []T{}
				}
				// add to buffer
				buffer[sid] = append(buffer[sid], value)
				if len(buffer[sid]) == s.Threshold {
					backlog[sid] = struct{}{}
				}
			}
		}
	}

	//drain buffer of given channel
	drainAndReset := func() {
		// drain buffer of given channel since threshold has been breached
		// get pseudo random channel using map
		count := 0
		for chanID := range backlog {
			if sink[chanID] != nil {
				for _, item := range buffer[chanID] {
					select {
					case <-ctx.Done():
						return
					case sink[chanID] <- item:
					}
				}
				buffer[chanID] = []T{}
				delete(backlog, chanID)
				count++
				if count == s.MaxDrain {
					// skip for now
					return
				}
			}
		}
	}

forloop:
	for {
		switch {
		case len(backlog) > 0:
			// if buffer of any channel has reached threshold
			drainAndReset()
			// if it is true
		default:
			// send to sinks
			w, ok := <-src
			if !ok {
				break forloop
			}
			select {
			case <-ctx.Done():
				return
			case sink[0] <- w:
				addToBuff(0, w)
			case sink[1] <- w:
				addToBuff(1, w)
			case sink[2] <- w:
				addToBuff(2, w)
			case sink[3] <- w:
				addToBuff(3, w)
			case sink[4] <- w:
				addToBuff(4, w)
			}
		}
	}

	// empty all remaining buffer and close all channels
	for id, ch := range sink {
		if ch != nil {
			if len(buffer[id]) > 0 {
				for _, item := range buffer[id] {
					select {
					case <-ctx.Done():
						return
					case ch <- item:
					}
				}
			}
			close(ch)
		}
	}
}

// Waits until all work is completed
func (s *SplitChannels[T]) Wait() {
	s.wg.Wait()
}
