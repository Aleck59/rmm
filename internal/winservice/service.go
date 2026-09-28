// Package winservice wraps installation and supervision of the InvMon
// server and agent as Windows services. On non-Windows platforms the
// management calls return an error and RunAsService runs the payload
// directly, so the same command-line code compiles and runs everywhere
// (useful for development on Linux/macOS).
package winservice

import "context"

// Config describes a Windows service to install.
type Config struct {
	Name        string   // service key name, e.g. "InvMonServer"
	DisplayName string   // human-readable name shown in services.msc
	Description string   // description shown in services.msc
	Arguments   []string // arguments passed to the binary when SCM starts it
}

// RunFunc is a long-running payload that must return when ctx is canceled.
type RunFunc func(ctx context.Context) error
