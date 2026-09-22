// Package api is the HTTP surface (spec §9: one API; admin CLI and devices
// are both clients of it). Errors are codes with parameters; human text is
// rendered from the catalog only when a caller asks for it.
package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"rostor.org/app/internal/audit"
	"rostor.org/app/internal/auth"
	"rostor.org/app/internal/authz"
	"rostor.org/app/internal/catalog"
	"rostor.org/app/internal/db"
	"rostor.org/app/internal/devices"
	"rostor.org/app/internal/directory"
	"rostor.org/app/internal/ids"
	"rostor.org/app/internal/pki"
)

type Server struct {
	DB       *db.Pool
	Auth     *auth.Service
	Authz    *authz.Engine
	Devices  *devices.Service
	Catalog  *catalog.Catalog
	CA       *pki.CA
	TenantID string // single-tenant self-hosted (D4): one tenant per process
	Log      *slog.Logger
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("POST /v1/devices/enroll", s.handleEnroll)
	mux.HandleFunc("POST /v1/verify", s.deviceAuth(s.handleVerify))
	mux.HandleFunc("POST /v1/devices/self/posture", s.deviceAuth(s.handlePosture))

	// Admin surface: bearer API token, authorised via the same engine
	// (§3.3: admin rights are roles on directory resources).
	mux.HandleFunc("POST /v1/admin/users", s.adminAuth("users.write", s.handleCreateUser))
	mux.HandleFunc("POST /v1/admin/users/{id}/state", s.adminAuth("users.write", s.handleUserState))
	mux.HandleFunc("POST /v1/admin/users/{id}/bindings", s.adminAuth("credentials.write", s.handleEnrollBinding))
	mux.HandleFunc("POST /v1/admin/groups", s.adminAuth("groups.write", s.handleCreateGroup))
	mux.HandleFunc("POST /v1/admin/groups/{name}/members", s.adminAuth("groups.write", s.handleAddMember))
	mux.HandleFunc("DELETE /v1/admin/groups/{name}/members", s.adminAuth("groups.write", s.handleRemoveMember))
	mux.HandleFunc("POST /v1/admin/resources", s.adminAuth("resources.write", s.handleCreateResource))
	mux.HandleFunc("POST /v1/admin/roles", s.adminAuth("roles.write", s.handleUpsertRole))
	mux.HandleFunc("POST /v1/admin/grants", s.adminAuth("grants.write", s.handleCreateGrant))
	mux.HandleFunc("DELETE /v1/admin/grants/{id}", s.adminAuth("grants.write", s.handleRevokeGrant))
	mux.HandleFunc("POST /v1/admin/enrollment-tokens", s.adminAuth("devices.write", s.handleEnrollmentToken))
	mux.HandleFunc("GET /v1/admin/why", s.adminAuth("authz.read", s.handleWhy))
	mux.HandleFunc("GET /v1/admin/audit", s.adminAuth("audit.read", s.handleAudit))
	mux.HandleFunc("GET /v1/admin/audit/verify", s.adminAuth("audit.read", s.handleAuditVerify))
	return s.logging(mux)
}

// TLSConfig serves the core certificate and *requests* client certificates
// without requiring them: enrollment and admin calls have none, device calls
// do. Device handlers then insist on one.
func (s *Server) TLSConfig(certPEM, keyPEM []byte) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(s.CA.Cert)
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// ---- plumbing ---------------------------------------------------------------

type ctxKey int

const (
	ctxActor ctxKey = iota
	ctxDevice
	ctxCorr
)

func (s *Server) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		corr := r.Header.Get("X-Correlation-Id")
		if corr == "" {
			corr = ids.New("corr")
		}
		w.Header().Set("X-Correlation-Id", corr)
		start := time.Now()
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxCorr, corr)))
		s.Log.Info("http", "method", r.Method, "path", r.URL.Path, "ms", time.Since(start).Milliseconds(), "corr", corr)
	})
}

func corrOf(r *http.Request) string { c, _ := r.Context().Value(ctxCorr).(string); return c }

type apiError struct {
	Code    string         `json:"code"`
	Params  map[string]any `json:"params"`
	Message string         `json:"message,omitempty"`
}

func (s *Server) writeErr(w http.ResponseWriter, r *http.Request, status int, code string, params map[string]any) {
	if params == nil {
		params = map[string]any{}
	}
	s.writeJSON(w, status, apiError{Code: code, Params: params, Message: s.Catalog.Render(locale(r), code, params)})
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	var e *directory.ErrCode
	if errors.As(err, &e) {
		status := map[string]int{
			"request.malformed": 400, "request.unauthorized": 401, "request.forbidden": 403,
			"request.not_found": 404, "principal.not_found": 404, "request.conflict": 409,
			"enrollment.token_invalid": 401, "auth.method_unavailable": 400,
		}[e.Code]
		if status == 0 {
			status = 400
		}
		s.writeErr(w, r, status, e.Code, e.Params)
		return
	}
	s.Log.Error("internal", "err", err, "corr", corrOf(r))
	s.writeErr(w, r, 500, "internal.error", nil)
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return directory.Err("request.malformed", "detail", err.Error())
	}
	return nil
}

func locale(r *http.Request) string {
	if l := r.URL.Query().Get("locale"); l != "" {
		return l
	}
	if al := r.Header.Get("Accept-Language"); al != "" {
		return strings.TrimSpace(strings.Split(strings.Split(al, ",")[0], ";")[0])
	}
	return "en"
}

// deviceAuth requires a client certificate issued by the tenant CA that maps
// to an enrolled device, and puts the device in context.
func (s *Server) deviceAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			s.writeErr(w, r, 401, "request.unauthorized", map[string]any{"reason": "client_certificate_required"})
			return
		}
		fp := pki.Fingerprint(r.TLS.PeerCertificates[0])
		tenantID, d, err := devices.ByFingerprint(r.Context(), s.DB, fp)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if d == nil || tenantID != s.TenantID {
			s.writeErr(w, r, 401, "device.unknown", nil)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxDevice, d)))
	}
}

// adminAuth resolves a bearer API token to a service-account principal and
// checks the named action on directory:root through the one engine.
func (s *Server) adminAuth(action string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if tok == "" || tok == r.Header.Get("Authorization") {
			s.writeErr(w, r, 401, "request.unauthorized", nil)
			return
		}
		tenantID, pid, err := auth.ResolveAPIToken(r.Context(), s.DB, tok)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if pid == "" || tenantID != s.TenantID {
			s.writeErr(w, r, 401, "request.unauthorized", nil)
			return
		}
		p, err := directory.GetPrincipal(r.Context(), s.DB, tenantID, pid)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		// A static API token is a single possession factor: AL1.
		d, err := s.Authz.Check(r.Context(), s.DB, tenantID, p, action, "directory", "root", authz.Presented{Assurance: "AL1", Properties: []string{"possession"}})
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if !d.Allow {
			s.writeErr(w, r, 403, "request.forbidden", map[string]any{"action": action, "reason": d.Reasons[0].Code})
			return
		}
		actor := directory.Actor{Kind: p.Kind, ID: p.ID, CorrelationID: corrOf(r)}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxActor, actor)))
	}
}

func actorOf(r *http.Request) directory.Actor { a, _ := r.Context().Value(ctxActor).(directory.Actor); return a }

func (s *Server) tx(r *http.Request, fn func(pgx.Tx) error) error { return s.DB.Tx(r.Context(), fn) }

// auditDenied records a failed or refused act. It runs in its own transaction
// because the caller's may have rolled back.
func (s *Server) auditEvent(ctx context.Context, e audit.Event) {
	err := s.DB.Tx(ctx, func(tx pgx.Tx) error {
		_, err := audit.Append(ctx, tx, s.TenantID, e)
		return err
	})
	if err != nil {
		s.Log.Error("audit append failed", "err", err)
	}
}
