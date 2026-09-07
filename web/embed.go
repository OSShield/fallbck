package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static templates
var embeddedContent embed.FS

// Content defaults to embedded assets; development mode can use files on disk.
var Content fs.FS = embeddedContent

// StaticFS returns the sub-filesystem for static assets
func StaticFS() http.FileSystem {
	sub, err := fs.Sub(Content, "static")
	if err != nil {
		panic(err)
	}
	return http.FS(sub)
}
