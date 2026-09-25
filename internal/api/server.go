// Package api is the HTTP surface (spec §9: one API; admin CLI and devices
// are both clients of it). Errors are codes with parameters; human text is
// rendered from the catalog only when a caller asks for it.
package api

import (
	"context"
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
	"rostor.org/app/internal/update"
)

type Server struct {
	DB           *db.Pool
	Auth         *auth.Service
	Authz        *authz.Engine
	Devices      *devices.Service
	Catalog      *catalog.Catalog
	CA           *pki.CA
	TenantID     string // single-tenant self-hosted (D4): one tenant per process
	Log          *slog.Logger
	StateDir     string // where the updater leaves its state (update-state.json)
	Version      string
	Events       *Broadcaster
	Started      time.Time
	ReleaseKeyFP string
	Static       http.Handler   // the embedded console; nil to serve API only
	Channel      *update.Client // release channel client; nil when unconfigured
	trust        *trustState
	// OnTrustChange runs after the active CA set changes (rotate/retire) so
	// the serve command can reissue the server certificate.
	OnTrustChange func()
	// ReleaseRepo/ReleaseToken locate release assets (downloads); token only
	// for private repositories.
	ReleaseRepo  string
	ReleaseToken string
	// DeviceURL is the address devices enroll against (the mTLS listener),
	// shown beside the installer download.
	DeviceURL string
	// actions collects every permission the admin API checks, as routes are
	// registered; the grant form offers them when defining a directory role.
	actions map[string]struct{}
	// mux is the API router; the MCP endpoint dispatches tool calls through it.
	mux *http.ServeMux
}

// baseCtx is a context for work not tied to a request (trust reloads).
func (s *Server) baseCtx() context.Context { return context.Background() }

func (s *Server) Handler() http.Handler {
	// The badge method reads the tenant's number format from policy.
	if bm, ok := s.Auth.Method("badge"); ok {
		if badge, ok := bm.(*auth.BadgeMethod); ok {
			badge.Format = s.badgeFormat
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /v1/catalog", s.handleCatalog)
	mux.HandleFunc("GET /v1/brand", s.handleBrand)
	mux.HandleFunc("POST /v1/auth/login", s.handleLogin)
	mux.HandleFunc("GET /v1/auth/session", s.handleSession)
	mux.HandleFunc("POST /v1/auth/logout", s.handleLogout)
	mux.HandleFunc("GET /v1/auth/setup", s.handleSetupStatus)
	mux.HandleFunc("POST /v1/auth/setup", s.handleSetup)
	mux.HandleFunc("GET /v1/events/stream", s.anySession(s.handleEventStream))
	mux.HandleFunc("POST /v1/auth/passkeys/register/begin", s.handlePasskeyRegisterBegin)
	mux.HandleFunc("POST /v1/auth/passkeys/register/finish", s.handlePasskeyRegisterFinish)
	mux.HandleFunc("POST /v1/auth/login/passkey/begin", s.handlePasskeyLoginBegin)
	mux.HandleFunc("POST /v1/auth/login/passkey/finish", s.handlePasskeyLoginFinish)
	mux.HandleFunc("GET /v1/admin/settings/auth", s.adminAuth("system.read", s.handleGetAuthSettings))
	mux.HandleFunc("PUT /v1/admin/settings/auth", s.adminAuth("policies.write", s.handlePutAuthSettings))
	mux.HandleFunc("POST /v1/devices/enroll", s.handleEnroll)
	mux.HandleFunc("POST /v1/verify", s.deviceAuth(s.handleVerify))
	mux.HandleFunc("POST /v1/devices/self/posture", s.deviceAuth(s.handlePosture))
	mux.HandleFunc("GET /v1/devices/self/trust", s.deviceAuth(s.handleTrust))
	mux.HandleFunc("POST /v1/devices/self/renew", s.deviceAuth(s.handleRenew))
	mux.HandleFunc("GET /v1/admin/downloads", s.adminAuth("devices.read", s.handleDownloadStatus))
	mux.HandleFunc("GET /v1/admin/downloads/windows", s.adminAuth("devices.read", s.handleDownloadWindows))
	mux.HandleFunc("GET /v1/admin/ca", s.adminAuth("system.read", s.handleListCAs))
	mux.HandleFunc("POST /v1/admin/ca/rotate", s.adminAuth("system.write", s.handleRotateCA))
	mux.HandleFunc("POST /v1/admin/ca/{id}/retire", s.adminAuth("system.write", s.handleRetireCA))

	// Admin surface: bearer API token, authorised via the same engine
	// (§3.3: admin rights are roles on directory resources).
	mux.HandleFunc("POST /v1/admin/users", s.adminAuth("users.write", s.handleCreateUser))
	mux.HandleFunc("POST /v1/admin/users/{id}/state", s.adminAuth("users.write", s.handleUserState))
	mux.HandleFunc("POST /v1/admin/users/{id}/bindings", s.selfOrAdmin("credentials.write", s.handleEnrollBinding))
	mux.HandleFunc("POST /v1/admin/groups", s.adminAuth("groups.write", s.handleCreateGroup))
	mux.HandleFunc("POST /v1/admin/groups/{name}/members", s.adminAuth("groups.write", s.handleAddMember))
	mux.HandleFunc("DELETE /v1/admin/groups/{name}/members", s.adminAuth("groups.write", s.handleRemoveMember))
	mux.HandleFunc("POST /v1/admin/resources", s.adminAuth("resources.write", s.handleCreateResource))
	mux.HandleFunc("POST /v1/admin/roles", s.adminAuth("roles.write", s.handleUpsertRole))
	mux.HandleFunc("POST /v1/admin/grants", s.adminAuth("grants.write", s.handleCreateGrant))
	mux.HandleFunc("DELETE /v1/admin/grants/{id}", s.adminAuth("grants.write", s.handleRevokeGrant))
	mux.HandleFunc("POST /v1/admin/enrollment-tokens", s.adminAuth("devices.write", s.handleEnrollmentToken))
	mux.HandleFunc("GET /v1/admin/why", s.adminAuth("authz.read", s.handleWhy))
	mux.HandleFunc("GET /v1/admin/audit", s.adminAuth("audit.read", s.handleAuditList))
	mux.HandleFunc("GET /v1/admin/audit/verify", s.adminAuth("audit.read", s.handleAuditVerify))
	mux.HandleFunc("GET /v1/admin/summary", s.adminAuth("users.read", s.handleSummary))
	mux.HandleFunc("GET /v1/admin/users", s.adminAuth("users.read", s.handleListUsers))
	mux.HandleFunc("DELETE /v1/admin/users/{id}/bindings/{bid}", s.selfOrAdmin("credentials.write", s.handleRevokeBinding))
	mux.HandleFunc("GET /v1/admin/users/{id}", s.selfOrAdmin("users.read", s.handleGetUser))
	mux.HandleFunc("POST /v1/admin/users/{id}/password", s.selfOrAdmin("credentials.write", s.handleChangePassword))
	mux.HandleFunc("POST /v1/admin/users/{id}/bindings/{bid}/pin", s.selfOrAdmin("credentials.write", s.handleSetPIN))
	mux.HandleFunc("GET /v1/admin/groups", s.adminAuth("groups.read", s.handleListGroups))
	mux.HandleFunc("GET /v1/admin/groups/{name}", s.adminAuth("groups.read", s.handleGetGroup))
	mux.HandleFunc("GET /v1/admin/grants", s.adminAuth("grants.read", s.handleListGrants))
	mux.HandleFunc("GET /v1/admin/roles", s.adminAuth("grants.read", s.handleListRoles))
	mux.HandleFunc("GET /v1/admin/resources", s.adminAuth("grants.read", s.handleListResources))
	// SPEC-agents: owners manage their own agents; admins manage all.
	mux.HandleFunc("POST /v1/admin/agents", s.ownerOrAdmin("users.write", s.handleCreateAgent))
	mux.HandleFunc("GET /v1/admin/agents", s.ownerOrAdmin("users.read", s.handleListAgents))
	mux.HandleFunc("GET /v1/admin/agents/{id}", s.ownerOrAdmin("users.read", s.handleGetAgent))
	mux.HandleFunc("POST /v1/admin/agents/{id}/token", s.ownerOrAdmin("users.write", s.handleAgentToken))
	mux.HandleFunc("DELETE /v1/admin/agents/{id}/token", s.ownerOrAdmin("users.write", s.handleAgentTokenRevoke))
	mux.HandleFunc("POST /v1/admin/agents/{id}/state", s.ownerOrAdmin("users.write", s.handleAgentState))
	mux.HandleFunc("POST /v1/admin/agents/{id}/grants", s.ownerOrAdmin("grants.write", s.handleAgentGrant))
	mux.HandleFunc("DELETE /v1/admin/agents/{id}/grants/{gid}", s.ownerOrAdmin("grants.write", s.handleAgentGrantRevoke))
	mux.HandleFunc("GET /v1/admin/devices", s.adminAuth("devices.read", s.handleListDevices))
	mux.HandleFunc("GET /v1/admin/system", s.adminAuth("system.read", s.handleSystem))
	mux.HandleFunc("GET /v1/admin/plugins", s.adminAuth("plugins.read", s.handlePlugins))
	mux.HandleFunc("GET /v1/admin/updates", s.adminAuth("updates.read", s.handleUpdateStatus))
	mux.HandleFunc("POST /v1/admin/updates/apply", s.adminAuth("updates.write", s.handleUpdateApply))
	mux.HandleFunc("POST /v1/admin/updates/check", s.adminAuth("updates.read", s.handleUpdateCheck))
	mux.HandleFunc("POST /v1/admin/badges/read", s.handleBadgeRead)
	// SPEC-agents: MCP on the same listener, tools dispatched through this mux.
	mux.HandleFunc("/mcp", s.handleMCP)
	s.noteAction("agents.own") // checked in handlers, not a route; the role editor must still offer it
	if s.Static != nil {
		mux.Handle("/", s.Static)
	}
	s.mux = mux
	return s.logging(mux)
}

// ---- plumbing ---------------------------------------------------------------

type ctxKey int

const (
	ctxActor ctxKey = iota
	ctxDevice
	ctxCorr
	ctxFullStream
	ctxAgentAdmin // ownerOrAdmin: the caller passed the admin check (vs. owns the agent)
	ctxCaller     // ownerOrAdmin: the signed-in principal
	ctxPresented  // ownerOrAdmin: how the caller proved identity
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
	s.noteAction(action)
	return func(w http.ResponseWriter, r *http.Request) {
		var p *directory.Principal
		assurance, props := "AL1", []string{"possession"}
		if tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "); tok != "" && tok != r.Header.Get("Authorization") {
			// A static API token is a single possession factor: AL1.
			tenantID, pid, err := auth.ResolveAPIToken(r.Context(), s.DB, tok)
			if err != nil {
				s.fail(w, r, err)
				return
			}
			if pid == "" || tenantID != s.TenantID {
				s.writeErr(w, r, 401, "request.unauthorized", nil)
				return
			}
			p, err = directory.GetPrincipal(r.Context(), s.DB, tenantID, pid)
			if err != nil {
				s.fail(w, r, err)
				return
			}
			pres := authz.Presented{Assurance: assurance, Properties: props}
			s.capAgentAssurance(r.Context(), p, &pres)
			assurance = pres.Assurance
		} else {
			// Console session cookie. Mutations must carry the CSRF marker.
			sp, ses, err := s.sessionPrincipal(r.Context(), r)
			if err != nil {
				s.fail(w, r, err)
				return
			}
			if sp == nil {
				s.writeErr(w, r, 401, "request.unauthorized", nil)
				return
			}
			if r.Method != "GET" && r.Method != "HEAD" && !isConsoleMutation(r) {
				s.writeErr(w, r, 403, "request.forbidden", map[string]any{"reason": "csrf"})
				return
			}
			p, assurance, props = sp, ses.Assurance, ses.Properties
		}
		d, err := s.Authz.Check(r.Context(), s.DB, s.TenantID, p, action, "directory", "root", authz.Presented{Assurance: assurance, Properties: props})
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

func actorOf(r *http.Request) directory.Actor {
	a, _ := r.Context().Value(ctxActor).(directory.Actor)
	return a
}

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

// ProxiedHandler serves the same API over plain HTTP for a TLS-terminating
// reverse proxy. Only connections from trusted proxies are accepted, and the
// proxy's X-Forwarded-For is recorded as the client for logging. Device
// endpoints still demand a client certificate, which cannot arrive this way,
// so they fail closed with request.unauthorized.
func (s *Server) ProxiedHandler(trusted []string) http.Handler {
	h := s.Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := strings.Cut(r.RemoteAddr, ":")
		if len(trusted) > 0 && !contains(trusted, host) {
			http.Error(w, `{"code":"request.forbidden","params":{"reason":"untrusted_proxy"}}`, 403)
			return
		}
		if ff := r.Header.Get("X-Forwarded-For"); ff != "" {
			r.Header.Set("X-Rostor-Client", strings.TrimSpace(strings.Split(ff, ",")[0]))
		}
		h.ServeHTTP(w, r)
	})
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if strings.TrimSpace(v) == s {
			return true
		}
	}
	return false
}

// emitSystemEvent writes a typed event with no target so the live stream
// can carry system state (update checks) to open consoles.
func (s *Server) emitSystemEvent(ctx context.Context, typ string, payload map[string]any) {
	raw, _ := json.Marshal(payload)
	_, _ = s.DB.Exec(ctx, `INSERT INTO events (tenant_id, type, actor_id, payload, correlation_id) VALUES ($1,$2,'core',$3,$4)`,
		s.TenantID, typ, raw, ids.New("corr"))
}

// selfOrAdmin lets a signed-in person act on their own record (their own
// sign-in methods, their own detail) without holding the admin action;
// anyone else goes through adminAuth as usual. A person's own credentials
// are theirs to manage (spec §7.2: bindings are enumerable and revocable on
// the principal's record).
// noteAction records a permission the API checks (see Server.actions).
func (s *Server) noteAction(action string) {
	if s.actions == nil {
		s.actions = map[string]struct{}{}
	}
	s.actions[action] = struct{}{}
}

func (s *Server) selfOrAdmin(action string, next http.HandlerFunc) http.HandlerFunc {
	s.noteAction(action)
	admin := s.adminAuth(action, next)
	return func(w http.ResponseWriter, r *http.Request) {
		if tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "); tok != "" && tok != r.Header.Get("Authorization") {
			// A bearer principal (an agent, typically) may read and change its own record.
			if tenantID, pid, err := auth.ResolveAPIToken(r.Context(), s.DB, tok); err == nil && pid != "" && tenantID == s.TenantID {
				if p, err := directory.GetPrincipal(r.Context(), s.DB, tenantID, pid); err == nil {
					id := r.PathValue("id")
					if id == p.ID || strings.EqualFold(id, p.Username) {
						actor := directory.Actor{Kind: p.Kind, ID: p.ID, CorrelationID: corrOf(r)}
						next(w, r.WithContext(context.WithValue(r.Context(), ctxActor, actor)))
						return
					}
				}
			}
		}
		if r.Header.Get("Authorization") == "" {
			if p, ses, err := s.sessionPrincipal(r.Context(), r); err == nil && p != nil {
				id := r.PathValue("id")
				if id == p.ID || strings.EqualFold(id, p.Username) {
					if r.Method != "GET" && r.Method != "HEAD" && !isConsoleMutation(r) {
						s.writeErr(w, r, 403, "request.forbidden", map[string]any{"reason": "csrf"})
						return
					}
					actor := directory.Actor{Kind: p.Kind, ID: p.ID, CorrelationID: corrOf(r)}
					_ = ses
					next(w, r.WithContext(context.WithValue(r.Context(), ctxActor, actor)))
					return
				}
			}
		}
		admin(w, r)
	}
}

// anySession admits any signed-in principal (bearer or cookie) and records
// whether they may see everything (audit.read) or only their own events.
func (s *Server) anySession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var p *directory.Principal
		assurance := "AL1"
		if tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "); tok != "" && tok != r.Header.Get("Authorization") {
			tenantID, pid, err := auth.ResolveAPIToken(r.Context(), s.DB, tok)
			if err != nil {
				s.fail(w, r, err)
				return
			}
			if pid != "" && tenantID == s.TenantID {
				p, _ = directory.GetPrincipal(r.Context(), s.DB, tenantID, pid)
				if p != nil {
					pres := authz.Presented{Assurance: assurance}
					s.capAgentAssurance(r.Context(), p, &pres)
					assurance = pres.Assurance
				}
			}
		} else if sp, ses, err := s.sessionPrincipal(r.Context(), r); err == nil && sp != nil {
			p, assurance = sp, ses.Assurance
		}
		if p == nil {
			s.writeErr(w, r, 401, "request.unauthorized", nil)
			return
		}
		full := false
		if d, err := s.Authz.Check(r.Context(), s.DB, s.TenantID, p, "audit.read", "directory", "root", authz.Presented{Assurance: assurance}); err == nil && d.Allow {
			full = true
		}
		ctx := context.WithValue(r.Context(), ctxActor, directory.Actor{Kind: p.Kind, ID: p.ID, CorrelationID: corrOf(r)})
		ctx = context.WithValue(ctx, ctxFullStream, full)
		next(w, r.WithContext(ctx))
	}
}
