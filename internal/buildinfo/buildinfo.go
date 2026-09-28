// Package buildinfo carries version metadata stamped into the binaries at
// build time via -ldflags. Defaults keep `go run`/`go test` working without
// any linker flags.
package buildinfo

import "runtime"

// These variables are overridden at build time, e.g.:
//
//	go build -ldflags "-X github.com/Aleck59/rmm/internal/buildinfo.Version=1.0.0"
var (
	// Version is the release version (git tag without the leading "v"),
	// or "dev" for local builds.
	Version = "dev"
	// Commit is the short git commit the binary was built from.
	Commit = "none"
	// Date is the RFC 3339 build timestamp.
	Date = "unknown"
)

// Info is a serializable snapshot of the build metadata.
type Info struct {
	Version  string `json:"version"`
	Commit   string `json:"commit"`
	Date     string `json:"date"`
	Go       string `json:"go"`
	Platform string `json:"platform"`
}

// Get returns the current build metadata.
func Get() Info {
	return Info{
		Version:  Version,
		Commit:   Commit,
		Date:     Date,
		Go:       runtime.Version(),
		Platform: runtime.GOOS + "/" + runtime.GOARCH,
	}
}
