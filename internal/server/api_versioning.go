package server

import (
	"net/http"
	"strings"
)

func (s *Server) handleAPIVersionAlias(fromPrefix, toPrefix string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, fromPrefix) {
			http.NotFound(w, r)
			return
		}

		cloned := r.Clone(r.Context())
		urlCopy := *r.URL
		urlCopy.Path = toPrefix + strings.TrimPrefix(r.URL.Path, fromPrefix)
		urlCopy.RawPath = toPrefix + strings.TrimPrefix(r.URL.EscapedPath(), fromPrefix)
		cloned.URL = &urlCopy
		cloned.RequestURI = cloned.URL.RequestURI()
		s.mux.ServeHTTP(w, cloned)
	})
}
