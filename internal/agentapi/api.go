// Package agentapi implements the agent-facing HTTP API (/api/agent/v1):
// enrollment, metrics ingestion, configuration and token rotation. It is
// served on its own listener (default :8443) so that the admin UI can be
// firewalled separately from the workstation network.
package agentapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/Aleck59/rmm/internal/protocol"
	"github.com/Aleck59/rmm/internal/ratelimit"
	"github.com/Aleck59/rmm/internal/store"
	"github.com/Aleck59/rmm/internal/tokens"
)

// Tunables of the ingestion pipeline.
const (
	// RetentionDays bounds how old an accepted sample may be; it must match
	// the raw-metrics partition window maintained by the server.
	RetentionDays = 14
	// maxFutureSkew is how far past the server clock a (corrected) sample may be.
	maxFutureSkew = 5 * time.Minute
	// skewCorrectionThreshold: larger clock differences are corrected.
	skewCorrectionThreshold = 2 * time.Minute
	// tokenOverlap keeps the previous device token valid after rotation.
	tokenOverlap = 24 * time.Hour
)

// API serves the agent endpoints.
type API struct {
	store *store.Store
	log   *slog.Logger
	now   func() time.Time

	enrollLimit *ratelimit.Limiter // per client IP
	deviceLimit *ratelimit.Limiter // per device
}

// New returns an API backed by st.
func New(st *store.Store, log *slog.Logger) *API {
	return &API{
		store:       st,
		log:         log,
		now:         time.Now,
		enrollLimit: ratelimit.New(10, time.Minute),
		deviceLimit: ratelimit.New(60, time.Minute),
	}
}

// Handler returns the router for the agent listener.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	base := protocol.APIVersionPath
	routes := []struct {
		method, path string
		h            http.HandlerFunc
	}{
		{"POST", base + "/enroll", a.handleEnroll},
		{"POST", base + "/metrics", a.handleMetrics},
		{"GET", base + "/config", a.handleConfig},
		{"POST", base + "/token/rotate", a.handleRotate},
		{"GET", "/healthz", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("ok"))
		}},
	}
	allowed := map[string]string{}
	for _, rt := range routes {
		mux.HandleFunc(rt.method+" "+rt.path, rt.h)
		allowed[rt.path] = rt.method
	}
	// The catch-all shadows ServeMux's automatic 405, so tell "wrong method on
	// a known path" apart from "unknown path" here; both return problem+json.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if m, ok := allowed[r.URL.Path]; ok {
			w.Header().Set("Allow", m)
			writeProblem(w, http.StatusMethodNotAllowed, protocol.CodeMethodNotAllowed, "Method not allowed", "", nil)
			return
		}
		writeProblem(w, http.StatusNotFound, protocol.CodeNotFound, "Not found", "", nil)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r)
	})
}

func (a *API) internalError(w http.ResponseWriter, r *http.Request, err error) {
	a.log.Error("agent api error", "path", r.URL.Path, "err", err)
	writeProblem(w, http.StatusInternalServerError, protocol.CodeInternal, "Internal server error", "", nil)
}

// ---- enrollment -----------------------------------------------------------

func (a *API) handleEnroll(w http.ResponseWriter, r *http.Request) {
	ip := remoteIP(r)
	if ok, retry := a.enrollLimit.Allow(ip.String()); !ok {
		writeRateLimited(w, retry)
		return
	}
	enrollTok := bearerToken(r)
	if !tokens.Valid(enrollTok, tokens.EnrollPrefix) {
		writeProblem(w, http.StatusUnauthorized, protocol.CodeInvalidToken, "Invalid or expired token", "", nil)
		return
	}

	body, err := readBody(w, r, maxEnrollBody)
	if err != nil {
		a.bodyError(w, err)
		return
	}
	var req protocol.EnrollRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, protocol.CodeValidationFailed, "Malformed JSON", err.Error(), nil)
		return
	}
	if errs := validateEnroll(&req); len(errs) > 0 {
		writeProblem(w, http.StatusBadRequest, protocol.CodeValidationFailed, "Validation failed", "", errs)
		return
	}

	deviceTok, err := tokens.Generate(tokens.DevicePrefix)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	smbios := ""
	if req.HardwareIDs.SMBIOSUUID != nil {
		smbios = canonicalUUID(*req.HardwareIDs.SMBIOSUUID)
	}
	res, err := a.store.Enroll(r.Context(), store.EnrollParams{
		EnrollTokenHash:  tokens.Hash(enrollTok),
		DeviceTokenHash:  tokens.Hash(deviceTok),
		AgentUID:         canonicalUUID(req.AgentUID),
		AgentVersion:     req.AgentVersion,
		Hostname:         req.Hostname,
		Domain:           req.Domain,
		OSName:           req.OS.Name,
		OSVersion:        req.OS.Version,
		OSDisplayVersion: req.OS.DisplayVersion,
		OSArch:           req.OS.Arch,
		MachineGUID:      req.HardwareIDs.MachineGUID,
		SMBIOSUUID:       smbios,
		SerialNumber:     req.HardwareIDs.SerialNumber,
		RemoteIP:         ip,
	})
	switch {
	case errors.Is(err, store.ErrInvalidEnrollToken):
		if aerr := a.store.AuditEnrollFailure(r.Context(), req.Hostname, ip, "invalid_token"); aerr != nil {
			a.log.Error("audit enrollment failure", "err", aerr)
		}
		writeProblem(w, http.StatusUnauthorized, protocol.CodeInvalidToken, "Invalid or expired token", "", nil)
		return
	case errors.Is(err, store.ErrAlreadyEnrolled):
		writeProblem(w, http.StatusConflict, protocol.CodeAlreadyEnrolled, "Agent already enrolled",
			"this agent_uid has already reported data; reinstall the agent to enroll again", nil)
		return
	case errors.Is(err, store.ErrDeviceRevoked):
		writeProblem(w, http.StatusForbidden, protocol.CodeDeviceRevoked, "Device is revoked", "", nil)
		return
	case err != nil:
		a.internalError(w, r, err)
		return
	}

	cfg, err := a.store.AgentConfig(r.Context())
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	a.log.Info("agent enrolled", "device_id", res.DeviceID, "hostname", req.Hostname,
		"status", res.Status, "reenrolled", res.Reenrolled, "ip", ip.String())
	writeJSON(w, http.StatusCreated, protocol.EnrollResponse{
		DeviceID:    res.DeviceID,
		DeviceToken: deviceTok,
		Status:      res.Status,
		Config:      cfg,
	})
}

// ---- authenticated device endpoints ----------------------------------------

// authenticate resolves the calling device and enforces its lifecycle status
// and rate limit. On failure it writes the response and returns ok=false.
func (a *API) authenticate(w http.ResponseWriter, r *http.Request) (store.Device, bool) {
	tok := bearerToken(r)
	if !tokens.Valid(tok, tokens.DevicePrefix) {
		writeProblem(w, http.StatusUnauthorized, protocol.CodeInvalidToken, "Invalid or expired token", "", nil)
		return store.Device{}, false
	}
	dev, err := a.store.DeviceByToken(r.Context(), tokens.Hash(tok))
	if errors.Is(err, store.ErrNotFound) {
		a.log.Warn("agent authentication failed", "ip", remoteIP(r).String(), "path", r.URL.Path)
		writeProblem(w, http.StatusUnauthorized, protocol.CodeInvalidToken, "Invalid or expired token", "", nil)
		return store.Device{}, false
	}
	if err != nil {
		a.internalError(w, r, err)
		return store.Device{}, false
	}
	switch dev.Status {
	case "active":
	case "pending":
		writeProblem(w, http.StatusForbidden, protocol.CodePendingApproval, "Device is pending approval", "", nil)
		return dev, false
	default: // revoked | retired
		writeProblem(w, http.StatusForbidden, protocol.CodeDeviceRevoked, "Device is revoked", "", nil)
		return dev, false
	}
	if ok, retry := a.deviceLimit.Allow(strconv.FormatInt(dev.ID, 10)); !ok {
		writeRateLimited(w, retry)
		return dev, false
	}
	return dev, true
}

func (a *API) handleMetrics(w http.ResponseWriter, r *http.Request) {
	dev, ok := a.authenticate(w, r)
	if !ok {
		return
	}
	body, err := readBody(w, r, maxMetricsBody)
	if err != nil {
		a.bodyError(w, err)
		return
	}
	var batch protocol.MetricsBatch
	if err := json.Unmarshal(body, &batch); err != nil {
		writeProblem(w, http.StatusBadRequest, protocol.CodeValidationFailed, "Malformed JSON", err.Error(), nil)
		return
	}
	if errs := validateMetrics(&batch); len(errs) > 0 {
		writeProblem(w, http.StatusBadRequest, protocol.CodeValidationFailed, "Validation failed", "", errs)
		return
	}

	params, accepted := a.buildIngest(dev.ID, &batch, remoteIP(r))
	res, err := a.store.IngestMetrics(r.Context(), params)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, protocol.MetricsResponse{
		Accepted:           accepted,
		ConfigVersion:      res.ConfigVersion,
		InventoryRequested: res.InventoryRequested,
		RotateToken:        res.RotateToken,
	})
}

// buildIngest corrects the agent clock and drops samples outside the
// acceptance window [now-RetentionDays, now+maxFutureSkew].
func (a *API) buildIngest(deviceID int64, b *protocol.MetricsBatch, ip netip.Addr) (store.IngestParams, protocol.Accepted) {
	now := a.now()
	skew := now.Sub(b.SentAt)
	shift := time.Duration(0)
	if skew > skewCorrectionThreshold || skew < -skewCorrectionThreshold {
		shift = skew
	}
	oldest := now.Add(-RetentionDays * 24 * time.Hour)
	newest := now.Add(maxFutureSkew)
	inWindow := func(t time.Time) bool { return !t.Before(oldest) && !t.After(newest) }

	p := store.IngestParams{
		DeviceID:     deviceID,
		RemoteIP:     ip,
		LoggedOnUser: b.LoggedOnUser,
		ClockSkewS:   int(skew.Round(time.Second).Seconds()),
	}
	if b.BootTime != nil {
		bt := b.BootTime.Add(shift)
		p.BootTime = &bt
	}
	for _, h := range b.Host {
		ts := h.TS.Add(shift)
		if !inWindow(ts) {
			continue
		}
		p.Host = append(p.Host, store.HostSample{
			TS: ts, CPU: float32(h.CPUPct), CPUMax: float32(h.CPUMaxPct),
			MemUsed: h.MemUsedBytes, MemTotal: h.MemTotalBytes,
		})
	}
	for _, d := range b.Disks {
		ts := d.TS.Add(shift)
		if !inWindow(ts) {
			continue
		}
		p.Disks = append(p.Disks, store.DiskSample{TS: ts, Volume: d.Volume, Total: d.TotalBytes, Free: d.FreeBytes})
	}
	if b.Agent != nil {
		p.AgentVersion = b.Agent.Version
		if b.Agent.UptimeS > 0 {
			u := b.Agent.UptimeS
			p.AgentUptimeS = &u
		}
		if b.Agent.RSSBytes > 0 {
			rss := b.Agent.RSSBytes
			p.AgentRSSBytes = &rss
		}
		if len(b.Agent.Errors) > 0 {
			if enc, err := json.Marshal(b.Agent.Errors); err == nil {
				p.AgentErrors = enc
			}
		}
	}
	return p, protocol.Accepted{Host: len(p.Host), Disks: len(p.Disks)}
}

func (a *API) handleConfig(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.authenticate(w, r); !ok {
		return
	}
	cfg, err := a.store.AgentConfig(r.Context())
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	etag := fmt.Sprintf("%q", strconv.Itoa(cfg.ConfigVersion))
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (a *API) handleRotate(w http.ResponseWriter, r *http.Request) {
	dev, ok := a.authenticate(w, r)
	if !ok {
		return
	}
	newTok, err := tokens.Generate(tokens.DevicePrefix)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	until, err := a.store.RotateDeviceToken(r.Context(), dev.ID, tokens.Hash(newTok), tokenOverlap, remoteIP(r))
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, protocol.TokenRotateResponse{DeviceToken: newTok, PreviousValidUntil: until.UTC()})
}

func (a *API) bodyError(w http.ResponseWriter, err error) {
	if errors.Is(err, errBodyTooLarge) {
		writeProblem(w, http.StatusRequestEntityTooLarge, protocol.CodePayloadTooLarge, "Payload too large", "", nil)
		return
	}
	writeProblem(w, http.StatusBadRequest, protocol.CodeValidationFailed, "Unreadable request body", err.Error(), nil)
}
