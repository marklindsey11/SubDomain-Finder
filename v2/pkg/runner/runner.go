package runner

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
)

// Runner is an instance of the subdomain enumeration
// client used to orchestrate the whole process.
type Runner struct {
	options        *Options
	passiveAgent   *passive.Agent
	resolverClient *resolve.Resolver
	executor       *core.Executor
}

// NewRunner creates a new runner struct instance by parsing
// the configuration options, configuring sources, reading lists
// and setting up loggers, etc.
func NewRunner(options *Options) (*Runner, error) {
	runner := &Runner{options: options}

	// Initialize the passive subdomain enumeration engine
	runner.initializePassiveEngine()

	// Initialize the subdomain resolver
	err := runner.initializeResolver()
	if err != nil {
		return nil, err
	}

	runner.initExecutor()

	return runner, nil
}

func (r *Runner) initExecutor() {
	r.executor = core.NewExecutor(&core.Config{
		InputBufferSize: 10,
		TaskBufferSize:  r.options.Threads,
		MaxTasks:        r.options.Concurrency,
		Proxy:           r.options.Proxy,
		RateLimit:       r.options.RateLimit,
		Timeout:         r.options.Timeout,
	}, r.passiveAgent.TaskChan)
}

// Run runs all sources and execute results
func (r *Runner) Run() error {
	wg := &sync.WaitGroup{}
	wg.Add(2)
	go r.handleInput(wg)
	go r.handleOutput(wg, r.executor.Result)

	r.executor.CreateWorkers(context.Background())
	err := r.passiveAgent.StartAll(context.Background(), r.executor.Extractor)
	if err != nil {
		return err
	}

	r.executor.Wait()
	wg.Wait()
	return nil
}

func (r *Runner) handleInput(sg *sync.WaitGroup) {
	defer sg.Done()
	var inputReader io.Reader

	if len(r.options.Domain) > 0 {
		inputReader = strings.NewReader(strings.Join(r.options.Domain, "\n"))
	}
	// If we have multiple domains as input,
	if r.options.DomainsFile != "" {
		f, err := os.Open(r.options.DomainsFile)
		if err != nil {
			gologger.Fatal().Msgf("failed to open file: %v", err)
		}
		inputReader = f
		defer f.Close()
	}
	if r.options.Stdin {
		inputReader = os.Stdin
	}

	// read input data and pass to input channel
	scanner := bufio.NewScanner(inputReader)
	ip, _ := regexp.Compile(`^([0-9\.]+$)`)
	for scanner.Scan() {
		domain, err := sanitize(scanner.Text())
		isIp := ip.MatchString(domain)
		if errors.Is(err, ErrEmptyInput) || (r.options.ExcludeIps && isIp) {
			continue
		}
		//else send to input
		r.passiveAgent.InputChan <- domain
	}
	close(r.passiveAgent.InputChan)
}

func (r *Runner) handleOutput(sg *sync.WaitGroup, resultChan chan core.Result) {
	defer sg.Done()
	uniqueMap := map[string]struct{}{}

	for {
		result, ok := <-resultChan
		// gologger.Debug().Msgf("got output %v\n", result)
		if !ok {
			break
		}

		// Log errors
		if result.Error != nil {
			gologger.Warning().Msgf("Could not run source '%s': %s\n", result.Source, result.Error)
			continue
		}

		// Filter and Match Results
		subdomain := strings.ReplaceAll(strings.ToLower(result.Value), "*.", "")
		if matchSubdomain := r.filterAndMatchSubdomain(subdomain); matchSubdomain {
			// skip everything as of now
			if _, ok := uniqueMap[subdomain]; !ok {
				uniqueMap[subdomain] = struct{}{}
			}
		}
	}
	for k := range uniqueMap {
		fmt.Fprintf(r.options.Output, "%v\n", k)
	}
}

// // RunEnumeration runs the subdomain enumeration flow on the targets specified
// func (r *Runner) RunEnumeration() error {
// 	outputs := []io.Writer{r.options.Output}

// 	if len(r.options.Domain) > 0 {
// 		domainsReader := strings.NewReader(strings.Join(r.options.Domain, "\n"))
// 		return r.EnumerateMultipleDomains(domainsReader, outputs)
// 	}

// 	// If we have multiple domains as input,
// 	if r.options.DomainsFile != "" {
// 		f, err := os.Open(r.options.DomainsFile)
// 		if err != nil {
// 			return err
// 		}
// 		err = r.EnumerateMultipleDomains(f, outputs)
// 		f.Close()
// 		return err
// 	}

// 	// If we have STDIN input, treat it as multiple domains
// 	if r.options.Stdin {
// 		return r.EnumerateMultipleDomains(os.Stdin, outputs)
// 	}
// 	return nil
// }

// // EnumerateMultipleDomains enumerates subdomains for multiple domains
// // We keep enumerating subdomains for a given domain until we reach an error
// func (r *Runner) EnumerateMultipleDomains(reader io.Reader, writers []io.Writer) error {
// 	scanner := bufio.NewScanner(reader)
// 	ip, _ := regexp.Compile(`^([0-9\.]+$)`)
// 	for scanner.Scan() {
// 		domain, err := sanitize(scanner.Text())
// 		isIp := ip.MatchString(domain)
// 		if errors.Is(err, ErrEmptyInput) || (r.options.ExcludeIps && isIp) {
// 			continue
// 		}

// 		var file *os.File
// 		// If the user has specified an output file, use that output file instead
// 		// of creating a new output file for each domain. Else create a new file
// 		// for each domain in the directory.
// 		if r.options.OutputFile != "" {
// 			outputWriter := NewOutputWriter(r.options.JSON)
// 			file, err = outputWriter.createFile(r.options.OutputFile, true)
// 			if err != nil {
// 				gologger.Error().Msgf("Could not create file %s for %s: %s\n", r.options.OutputFile, r.options.Domain, err)
// 				return err
// 			}

// 			err = r.EnumerateSingleDomain(domain, append(writers, file))

// 			file.Close()
// 		} else if r.options.OutputDirectory != "" {
// 			outputFile := path.Join(r.options.OutputDirectory, domain)
// 			if r.options.JSON {
// 				outputFile += ".json"
// 			} else {
// 				outputFile += ".txt"
// 			}

// 			outputWriter := NewOutputWriter(r.options.JSON)
// 			file, err = outputWriter.createFile(outputFile, false)
// 			if err != nil {
// 				gologger.Error().Msgf("Could not create file %s for %s: %s\n", r.options.OutputFile, r.options.Domain, err)
// 				return err
// 			}

// 			err = r.EnumerateSingleDomain(domain, append(writers, file))

// 			file.Close()
// 		} else {
// 			err = r.EnumerateSingleDomain(domain, writers)
// 		}
// 		if err != nil {
// 			return err
// 		}
// 	}
// 	return nil
// }
