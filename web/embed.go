package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static templates
var Content embed.FS

// StaticFS returns the sub-filesystem for static assets
func StaticFS() http.FileSystem {
	sub, err := fs.Sub(Content, "static")
	if err != nil {
		panic(err)
	}
	return http.FS(sub)
}
