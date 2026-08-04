// Package version holds build metadata for Irongrid DNS.
package version

import (
	"fmt"
	"runtime"
)

var (
	// Version is the semantic version of the release, overridable at build time
	// via: go build -ldflags "-X github.com/eoghan2t9/Irongrid-DNS/internal/version.Version=v1.0.0"
	Version = "v0.1.0"
	// Commit is the git commit the binary was built from.
	Commit = "dev"
	// BuildTime is the UTC time of the build.
	BuildTime = "unknown"
)

// String returns a human readable version summary.
func String() string {
	return fmt.Sprintf("Irongrid DNS %s (commit %s, built %s, %s/%s)",
		Version, Commit, BuildTime, runtime.GOOS, runtime.GOARCH)
}
