package sanitags

import "sync"

type TagValue string

const (
	StripAll TagValue = "stripall"
	SafeUGC  TagValue = "safeugc"
)

// StripAll is a function that strips all html content from a string
type StripAllFunc func(s string) string

// UGCFunc is a function that strips all non-safe html content from a string
type SafeUGCFunc func(s string) string

// Config is a struct that holds sanitizing functions
type Config struct {
	StripAllFunc StripAllFunc
	UGCFunc      SafeUGCFunc
}

func (c *Config) StripAll(v string) string {
	return c.StripAllFunc(v)
}

func (c *Config) SafeUGC(v string) string {
	return c.UGCFunc(v)
}

var config Config
var mutex sync.Mutex

// Setup sets the config for sanitizing
func Setup(c Config) {
	mutex.Lock()
	defer mutex.Unlock()
	config = c
}
