// Package server implements the InvMon server process. In Stage 0 it serves
// the embedded single-page application plus the health, readiness and version
// endpoints. Agent ingest, the web API and the database live in later stages.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/Aleck59/rmm/internal/buildinfo"
	"github.com/Aleck59/rmm/internal/webui"
)

// Server owns the HTTP listener and its dependencies.
type Server struct {
	cfg    Config
	log    *slog.Logger
	router http.Handler
}

// New builds a Server and its HTTP router.
func New(cfg Config, log *slog.Logger) (*Server, error) {
	spa, err := webui.FS()
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, log: log}
	s.router = securityHeaders(s.routes(spa))
	return s, nil
}

// Handler exposes the router for tests.
func (s *Server) Handler() http.Handler { return s.router }

func (s *Server) routes(spa fs.FS) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	mux.HandleFunc("GET /version", s.handleVersion)
	// The agent and web APIs are added in later stages; keep the namespace
	// reserved with an explicit "not implemented" so probes are unambiguous.
	mux.HandleFunc("/api/", s.handleAPIStub)
	mux.Handle("/", spaHandler(spa))
	return mux
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	// Stage 0 has no external dependencies to probe yet; readiness will check
	// the database and migrations once the store lands (Stage 1).
	writeJSON(w, r, http.StatusOK, map[string]any{
		"status":  "ready",
		"version": buildinfo.Version,
	})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, r, http.StatusOK, buildinfo.Get())
}

func (s *Server) handleAPIStub(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, r, http.StatusNotImplemented, map[string]any{
		"type":   "about:blank",
		"title":  "Not implemented",
		"status": http.StatusNotImplemented,
		"code":   "not_implemented",
		"detail": "API endpoints are introduced in a later development stage",
	})
}

// Run starts the HTTP server and shuts it down gracefully when ctx is done.
func (s *Server) Run(ctx context.Context) error {
	httpSrv := &http.Server{
		Addr:              s.cfg.WebAddr,
		Handler:           s.router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	tlsEnabled := s.cfg.TLSCert != "" && s.cfg.TLSKey != ""
	if tlsEnabled {
		httpSrv.TLSConfig = secureTLSConfig()
	} else {
		s.log.Warn("TLS certificate not configured; serving plain HTTP (development only)",
			"addr", s.cfg.WebAddr)
	}

	errc := make(chan error, 1)
	go func() {
		s.log.Info("web listener starting", "addr", s.cfg.WebAddr, "tls", tlsEnabled,
			"version", buildinfo.Version)
		if tlsEnabled {
			errc <- httpSrv.ListenAndServeTLS(s.cfg.TLSCert, s.cfg.TLSKey)
		} else {
			errc <- httpSrv.ListenAndServe()
		}
	}()

	select {
	case <-ctx.Done():
		s.log.Info("shutdown requested")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpSrv.Shutdown(shutdownCtx)
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func writeJSON(w http.ResponseWriter, _ *http.Request, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
