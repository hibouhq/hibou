package depinventory

import (
	"fmt"
	"sync"
	"sync/atomic"

	scalibrlog "github.com/google/osv-scalibr/log"
)

// The engine logs through a process-wide logger that defaults to the
// standard library's, printing walk statistics on stdout. Hibou installs a
// forwarding logger once: info and debug are dropped, warnings and errors
// go to whatever sink the current extraction registered.

var (
	installLogger sync.Once
	warnSink      atomic.Pointer[func(string)]
)

type forwardingLogger struct{}

func (forwardingLogger) Errorf(format string, args ...any) { forward(fmt.Sprintf(format, args...)) }
func (forwardingLogger) Error(args ...any)                 { forward(fmt.Sprint(args...)) }
func (forwardingLogger) Warnf(format string, args ...any)  { forward(fmt.Sprintf(format, args...)) }
func (forwardingLogger) Warn(args ...any)                  { forward(fmt.Sprint(args...)) }
func (forwardingLogger) Infof(string, ...any)              {}
func (forwardingLogger) Info(...any)                       {}
func (forwardingLogger) Debugf(string, ...any)             {}
func (forwardingLogger) Debug(...any)                      {}

func forward(message string) {
	if sink := warnSink.Load(); sink != nil && *sink != nil {
		(*sink)(message)
	}
}

func useLogger(warn func(string)) {
	installLogger.Do(func() { scalibrlog.SetLogger(forwardingLogger{}) })
	warnSink.Store(&warn)
}
