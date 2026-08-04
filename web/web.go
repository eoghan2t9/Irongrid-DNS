// Package web embeds the compiled React frontend into the binary so the
// dashboard ships as part of the single executable.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// FS returns the embedded frontend files (the dist/ directory itself).
func FS() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return dist
	}
	return sub
}

// HasFrontend reports whether a real frontend build is embedded (as opposed
// to the committed placeholder page).
func HasFrontend() bool {
	data, err := fs.ReadFile(dist, "dist/index.html")
	if err != nil {
		return false
	}
	// The placeholder contains this marker; a real Vite build does not.
	const marker = "irongrid-placeholder"
	for i := 0; i+len(marker) <= len(data); i++ {
		if string(data[i:i+len(marker)]) == marker {
			return false
		}
	}
	return true
}
