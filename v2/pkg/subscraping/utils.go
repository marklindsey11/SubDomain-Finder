package subscraping

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"math/rand"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
)

const MultipleKeyPartsLength = 2

var subdomainExtractorMutex = &sync.Mutex{}
var sha hash.Hash = sha256.New()

func init() {
	rand.Seed(time.Now().UnixNano())
}

func HashID(x any) string {
	mystr := fmt.Sprintf("%v", x)
	return fmt.Sprintf("%v", sha.Sum([]byte(mystr)))
}

// NewSubdomainExtractor creates a new regular expression to extract
// subdomains from text based on the given domain.
func NewSubdomainExtractor(domain string) (*regexp.Regexp, error) {
	subdomainExtractorMutex.Lock()
	defer subdomainExtractorMutex.Unlock()
	extractor, err := regexp.Compile(`[a-zA-Z0-9\*_.-]+\.` + domain)
	if err != nil {
		return nil, err
	}
	return extractor, nil
}

func PickRandom[T any](v []T, sourceName string) T {
	var result T
	length := len(v)
	if length == 0 {
		gologger.Debug().Msgf("Cannot use the '%s' source because there was no API key/secret defined for it.", sourceName)
		return result
	}
	return v[rand.Intn(length)]
}

func GetMultiPartKey(key string) (partA, partB string, ok bool) {
	parts := strings.Split(key, ":")
	ok = (len(parts) == MultipleKeyPartsLength)
	if ok {
		partA = parts[0]
		partB = parts[1]
	}
	return
}

func CreateApiKeys[T any](keys []string, provider func(k, v string) T) []T {
	var result []T
	for _, key := range keys {
		if keyPartA, keyPartB, ok := createMultiPartKey(key); ok {
			result = append(result, provider(keyPartA, keyPartB))
		}
	}
	return result
}

func createMultiPartKey(key string) (keyPartA, keyPartB string, ok bool) {
	parts := strings.Split(key, ":")
	ok = len(parts) == MultipleKeyPartsLength

	if ok {
		keyPartA = parts[0]
		keyPartB = parts[1]
	}

	return
}
