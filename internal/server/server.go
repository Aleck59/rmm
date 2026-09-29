// Package server implements the InvMon server process: the admin web
// listener (embedded SPA, health, readiness, version) and — when a database is
// configured — the agent API listener plus background partition maintenance.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/Aleck59/rmm/internal/agentapi"
	"github.com/Aleck59/rmm/internal/buildinfo"
	"github.com/Aleck59/rmm/internal/store"
	"github.com/Aleck59/rmm/internal/webui"
)

// maintenanceInterval is how often partitions are checked and pruned.
const maintenanceInterval = 6 * time.Hour

// Server owns the listeners and their dependencies.
type Server struct {
	cfg   Config
	log   *slog.Logger
	store *store.Store // nil when no database is configured (UI-only mode)

	router http.Handler // web listener
	agent  http.Handler // agent listener; nil without a store
}

// New builds a Server. st may be nil, in which case only the web listener
// runs and /readyz reports not ready.
func New(cfg Config, log *slog.Logger, st *store.Store) (*Server, error) {
	spa, err := webui.FS()
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, log: log, store: st}
	s.router = securityHeaders(s.routes(spa))
	if st != nil {
		s.agent = agentapi.New(st, log).Handler()
	}
	return s, nil
}

// Handler exposes the web router (tests).
func (s *Server) Handler() http.Handler { return s.router }

func (s *Server) routes(spa fs.FS) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	mux.HandleFunc("GET /version", s.handleVersion)
	// The web API arrives with the admin UI; keep the namespace reserved with
	// an explicit "not implemented" so probes are unambiguous.
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
	if s.store == nil {
		writeJSON(w, r, http.StatusServiceUnavailable, map[string]any{
			"status": "not_ready", "reason": "database not configured", "version": buildinfo.Version,
		})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		s.log.Warn("readiness check failed", "err", err)
		writeJSON(w, r, http.StatusServiceUnavailable, map[string]any{
			"status": "not_ready", "reason": "database unreachable", "version": buildinfo.Version,
		})
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]any{"status": "ready", "version": buildinfo.Version})
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
		"detail": "The web API is introduced together with the admin UI in a later stage",
	})
}

// Run starts the listeners (and maintenance, with a database) and shuts them
// down gracefully when ctx is done. The first listener failure stops all.
func (s *Server) Run(ctx context.Context) error {
	tlsEnabled := s.cfg.TLSCert != "" && s.cfg.TLSKey != ""
	if !tlsEnabled {
		s.log.Warn("TLS certificate not configured; serving plain HTTP (development only)")
	}

	type listener struct {
		name string
		srv  *http.Server
	}
	listeners := []listener{{"web", s.newHTTPServer(s.cfg.WebAddr, s.router, 120*time.Second, tlsEnabled)}}
	if s.agent != nil && s.cfg.AgentAddr != "" {
		// Idle timeout above the agents' send interval keeps one TLS
		// connection per agent instead of a handshake every minute.
		listeners = append(listeners, listener{"agent", s.newHTTPServer(s.cfg.AgentAddr, s.agent, 150*time.Second, tlsEnabled)})
	} else {
		s.log.Warn("agent API disabled: no database configured")
	}

	if s.store != nil {
		if err := s.store.MaintainPartitions(ctx, agentapi.RetentionDays); err != nil {
			return err
		}
		go s.maintain(ctx)
	}

	errc := make(chan error, len(listeners))
	for _, l := range listeners {
		go func() {
			s.log.Info("listener starting", "name", l.name, "addr", l.srv.Addr, "tls", tlsEnabled,
				"version", buildinfo.Version)
			var err error
			if tlsEnabled {
				err = l.srv.ListenAndServeTLS(s.cfg.TLSCert, s.cfg.TLSKey)
			} else {
				err = l.srv.ListenAndServe()
			}
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}
			errc <- err
		}()
	}

	var runErr error
	select {
	case <-ctx.Done():
		s.log.Info("shutdown requested")
	case runErr = <-errc:
		s.log.Error("listener stopped", "err", runErr)
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, l := range listeners {
		if err := l.srv.Shutdown(shutdownCtx); err != nil && runErr == nil {
			runErr = err
		}
	}
	return runErr
}

func (s *Server) newHTTPServer(addr string, h http.Handler, idle time.Duration, tlsEnabled bool) *http.Server {
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       idle,
		MaxHeaderBytes:    16 << 10,
	}
	if tlsEnabled {
		srv.TLSConfig = secureTLSConfig()
	}
	return srv
}

// maintain keeps metric and audit partitions ready until ctx is done.
func (s *Server) maintain(ctx context.Context) {
	t := time.NewTicker(maintenanceInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.store.MaintainPartitions(ctx, agentapi.RetentionDays); err != nil {
				s.log.Error("partition maintenance failed", "err", err)
			}
		}
	}
}

func writeJSON(w http.ResponseWriter, _ *http.Request, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
