// Package console serves the embedded admin console (a built React app) for
// every path the API does not claim. The build is copied into dist/ by
// `make console`; a placeholder page is embedded when no build exists so the
// binary always serves something honest at /.
package console

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var dist embed.FS

// Handler returns the SPA handler: static assets by path, index.html for
// anything else (client-side routing), never for /v1/.
func Handler() http.Handler {
	sub, _ := fs.Sub(dist, "dist")
	files := http.FS(sub)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/") {
			http.NotFound(w, r)
			return
		}
		p := path.Clean(r.URL.Path)
		if f, err := sub.Open(strings.TrimPrefix(p, "/")); err == nil {
			st, _ := f.Stat()
			f.Close()
			if st != nil && !st.IsDir() {
				if strings.HasPrefix(p, "/assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				http.FileServer(files).ServeHTTP(w, r)
				return
			}
		}
		w.Header().Set("Cache-Control", "no-cache")
		r.URL.Path = "/"
		http.FileServer(files).ServeHTTP(w, r)
	})
}
