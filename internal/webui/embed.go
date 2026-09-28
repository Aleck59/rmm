// Package webui embeds the built single-page application so the server ships
// as a single executable. The committed dist/index.html is a placeholder used
// for local Go builds and tests; CI overwrites internal/webui/dist with the
// real Vite build (web/) before compiling the server.
package webui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// FS returns the file system rooted at the built SPA directory.
func FS() (fs.FS, error) {
	return fs.Sub(dist, "dist")
}
