package passive

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/channelutil"
	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"golang.org/x/exp/maps"
)

// Agent contains and manages all sources for enumeration
type Agent struct {
	sources   []subscraping.Source
	InputChan chan string
	TaskChan  chan core.Task
	// Internal waitgroup
	srcgrp sync.WaitGroup
	joined channelutil.JoinChannels[core.Task]
	split  channelutil.SplitChannels[string]
}

// StartAll starts all sources in background(like a daemon)
func (a *Agent) StartAll(ctx context.Context, e *core.Extractor) error {
	inputChans := []chan string{}
	taskchans := []chan core.Task{}
	for i := 0; i < len(a.sources); i++ {
		inputChans = append(inputChans, make(chan string))
		taskchans = append(taskchans, make(chan core.Task))
	}
	for k, v := range a.sources {
		go v.Daemon(ctx, e, inputChans[k], taskchans[k])
	}

	// split input channel
	a.split = channelutil.SplitChannels[string]{
		MaxDrain:  3,
		Threshold: 5,
	}
	inputSndOnly := []chan<- string{}
	for _, v := range inputChans {
		inputSndOnly = append(inputSndOnly, v)
	}
	err := a.split.Split(ctx, a.InputChan, inputSndOnly...)
	if err != nil {
		return err
	}

	// join tasks channels
	a.joined = channelutil.JoinChannels[core.Task]{}
	tasksrecOnly := []<-chan core.Task{}
	for _, v := range taskchans {
		tasksrecOnly = append(tasksrecOnly, v)
	}
	err = a.joined.Join(ctx, a.TaskChan, tasksrecOnly...)
	if err != nil {
		return err
	}
	gologger.Debug().Msgf("started %v sources successfully\n", len(a.sources))
	return nil
}

// Wait until all sources are executed
func (a *Agent) Wait() {
	a.split.Wait()
	a.joined.Wait()
}

// New creates a new agent for passive subdomain discovery
func New(sourceNames, excludedSourceNames []string, useAllSources, useSourcesSupportingRecurse bool) *Agent {
	sources := make(map[string]subscraping.Source)

	if useAllSources {
		maps.Copy(sources, NameSourceMap)
	} else {
		if len(sourceNames) > 0 {
			for _, source := range sourceNames {
				if NameSourceMap[source] == nil {
					gologger.Warning().Msgf("There is no source with the name: '%s'", source)
				} else {
					sources[source] = NameSourceMap[source]
				}
			}
		} else {
			for _, currentSource := range AllSources {
				if currentSource.IsDefault() {
					sources[currentSource.Name()] = currentSource
				}
			}
		}
	}
	if len(excludedSourceNames) > 0 {
		for _, sourceName := range excludedSourceNames {
			delete(sources, sourceName)
		}
	}

	if useSourcesSupportingRecurse {
		for sourceName, source := range sources {
			if !source.HasRecursiveSupport() {
				delete(sources, sourceName)
			}
		}
	}
	gologger.Debug().Msgf(fmt.Sprintf("Selected source(s) for this search: %s", strings.Join(maps.Keys(sources), ", ")))

	// Create the agent, insert the sources and remove the excluded sources
	agent := &Agent{sources: maps.Values(sources)}
	agent.InputChan = make(chan string, 10)
	agent.TaskChan = make(chan core.Task, 10)
	return agent
}
