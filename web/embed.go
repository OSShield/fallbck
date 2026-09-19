package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static templates
var Content embed.FS

func StaticFS() http.FileSystem {
	sub, err := fs.Sub(Content, "static")
	if err != nil {
		panic(err)
	}
	return http.FS(sub)
}
