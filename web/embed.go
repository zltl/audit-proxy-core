// Package web embeds the template and static-asset filesystems so they can
// be imported by other packages regardless of directory depth.
package web

import "embed"

// EmbeddedFS contains all files under web/ (templates + static assets).
//
//go:embed all:templates all:static
var EmbeddedFS embed.FS
