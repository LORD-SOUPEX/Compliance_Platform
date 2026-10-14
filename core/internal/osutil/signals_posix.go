//go:build !windows

package osutil

import (
	"os"
	"os/signal"
	"syscall"
)

// NotifyTermination listens for SIGINT and SIGTERM.
func NotifyTermination(ch chan<- os.Signal) {
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
}
