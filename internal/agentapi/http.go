package agentapi

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/Aleck59/rmm/internal/protocol"
)

// writeJSON writes a JSON body with the given status.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// writeProblem writes an RFC 9457 problem document.
func writeProblem(w http.ResponseWriter, status int, code, title, detail string, fields []protocol.FieldError) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(protocol.Problem{
		Type:   "urn:invmon:problem:" + code,
		Title:  title,
		Status: status,
		Detail: detail,
		Code:   code,
		Errors: fields,
	})
}

func writeRateLimited(w http.ResponseWriter, retryAfter time.Duration) {
	secs := int(retryAfter.Round(time.Second).Seconds())
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeProblem(w, http.StatusTooManyRequests, protocol.CodeRateLimited, "Too many requests", "", nil)
}

var errBodyTooLarge = errors.New("request body too large")

// readBody reads at most limit bytes of (optionally gzip-compressed) request
// body. The limit applies to the decompressed size, so a small compressed
// payload cannot expand into an arbitrarily large one (gzip bomb).
func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	body := http.MaxBytesReader(w, r.Body, limit)
	var src io.Reader = body
	switch strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding"))) {
	case "", "identity":
	case "gzip":
		zr, err := gzip.NewReader(body)
		if err != nil {
			return nil, err
		}
		defer func() { _ = zr.Close() }()
		src = zr
	default:
		return nil, errors.New("unsupported Content-Encoding")
	}
	data, err := io.ReadAll(io.LimitReader(src, limit+1))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, errBodyTooLarge
		}
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errBodyTooLarge
	}
	return data, nil
}

// bearerToken extracts the token from "Authorization: Bearer <token>".
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

// remoteIP returns the TCP peer address. Forwarded headers are deliberately
// ignored until a trusted-proxy list exists.
func remoteIP(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}
