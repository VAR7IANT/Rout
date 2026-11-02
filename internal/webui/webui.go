// Package webui embeds the compiled management panel (built from /web by Vite into
// internal/webui/dist) and serves it as a single-page application.
package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var dist embed.FS

// Built reports whether a compiled panel is embedded.
func Built() bool {
	_, e := fs.Stat(dist, "dist/index.html")
	return e == nil
}

const notBuilt = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Rout</title></head><body style="font:16px system-ui;margin:3rem auto;max-width:36rem;padding:0 1rem"><h1>Rout web panel</h1><p>This binary was built without the panel interface. The API is available; build the interface with <code>cd web &amp;&amp; npm ci &amp;&amp; npm run build</code> and rebuild Rout, or install an official release.</p></body></html>`

// Handler serves files from the embedded build. Unknown paths that are not assets fall back
// to index.html so client-side routes work after a reload. Hashed assets are cacheable for a
// year; everything else is revalidated.
func Handler() http.Handler {
	sub, e := fs.Sub(dist, "dist")
	if e != nil || !Built() {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(notBuilt))
		})
	}
	files := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := path.Clean("/" + r.URL.Path)
		name := strings.TrimPrefix(p, "/")
		if name == "" {
			name = "index.html"
		}
		info, err := fs.Stat(sub, name)
		if err != nil || info.IsDir() {
			if strings.HasPrefix(p, "/assets/") || path.Ext(p) != "" {
				http.NotFound(w, r)
				return
			}
			name = "index.html"
		}
		if strings.HasPrefix(name, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		if name == "index.html" {
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/"
			files.ServeHTTP(w, r2)
			return
		}
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/" + name
		files.ServeHTTP(w, r2)
	})
}
