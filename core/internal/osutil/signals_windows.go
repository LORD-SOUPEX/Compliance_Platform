//go:build windows

package osutil

import (
	"os"
	"os/signal"
)

// NotifyTermination listens for console interrupt on Windows.
func NotifyTermination(ch chan<- os.Signal) {
	signal.Notify(ch, os.Interrupt)
}
