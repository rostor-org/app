package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"rostor.org/app/internal/api"
	"rostor.org/app/internal/auth"
	"rostor.org/app/internal/authz"
	"rostor.org/app/internal/catalog"
	"rostor.org/app/internal/config"
	"rostor.org/app/internal/console"
	"rostor.org/app/internal/crypto"
	"rostor.org/app/internal/db"
	"rostor.org/app/internal/devices"
	"rostor.org/app/internal/directory"
	"rostor.org/app/internal/ids"
	"rostor.org/app/internal/pki"
	"rostor.org/app/internal/update"
)

type core struct {
	cfg      config.Config
	db       *db.Pool
	provider crypto.Provider
	auth     *auth.Service
	authz    *authz.Engine
	devices  *devices.Service
	catalog  *catalog.Catalog
	tenantID string
	log      *slog.Logger
}

func open(ctx context.Context, createKey bool) (*core, error) {
	cfg := config.FromEnv()
	key, err := cfg.MasterKey(createKey)
	if err != nil {
		return nil, err
	}
	prov, err := crypto.NewDefault(key)
	if err != nil {
		return nil, err
	}
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	eng, err := authz.New()
	if err != nil {
		return nil, err
	}
	cat, err := catalog.Load()
	if err != nil {
		return nil, err
	}
	wa := &auth.WebAuthnMethod{}
	c := &core{cfg: cfg, db: pool, provider: prov, authz: eng, catalog: cat,
		auth:    auth.NewService(prov, &auth.PasswordMethod{Provider: prov}, &auth.BadgeMethod{Provider: prov}, wa),
		devices: &devices.Service{Provider: prov},
		log:     slog.New(slog.NewTextHandler(os.Stderr, nil)),
	}
	return c, nil
}

// loadTenant finds the process tenant. Single-tenant self-hosted (D4): the
// one tenant row is the tenant.
func (c *core) loadTenant(ctx context.Context) error {
	err := c.db.QueryRow(ctx, `SELECT id FROM tenants ORDER BY created_at LIMIT 1`).Scan(&c.tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	return err
}

func runMigrate(ctx context.Context) error {
	cfg := config.FromEnv()
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	applied, err := pool.Migrate(ctx)
	for _, a := range applied {
		fmt.Println("applied", a)
	}
	if len(applied) == 0 && err == nil {
		fmt.Println("up to date")
	}
	return err
}

func runServe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	fs.Parse(args)
	c, err := open(ctx, false)
	if err != nil {
		return err
	}
	defer c.db.Close()
	if err := c.loadTenant(ctx); err != nil {
		return err
	}
	if c.tenantID == "" {
		return errors.New("no tenant: run `rostor bootstrap` first")
	}
	var ca *pki.CA
	if err := c.db.Tx(ctx, func(tx pgx.Tx) error {
		var err error
		ca, err = c.devices.EnsureCA(ctx, tx, c.tenantID, "rostor")
		if err != nil {
			return err
		}
		return directory.EnsureBuiltins(ctx, tx, c.tenantID, c.authz)
	}); err != nil {
		return err
	}
	certPEM, keyPEM, err := serverCert(c, ca)
	if err != nil {
		return err
	}
	// The CLI on this machine trusts the core through this file.
	_ = os.WriteFile(filepath.Join(c.cfg.DataDir, "ca.crt"), ca.CertPEM(), 0o644)
	var channel *update.Client
	if url := os.Getenv("ROSTOR_CHANNEL_URL"); url != "" {
		if pub, err := update.LoadPublicKey(c.cfg.ReleasePubKey); err == nil {
			channel = &update.Client{ManifestURL: url, PublicKey: pub, Token: os.Getenv("ROSTOR_CHANNEL_TOKEN")}
		} else {
			c.log.Warn("release channel configured but public key unreadable", "err", err)
		}
	}
	srv := &api.Server{DB: c.db, Auth: c.auth, Authz: c.authz, Devices: c.devices, Catalog: c.catalog, CA: ca, TenantID: c.tenantID, Log: c.log, Channel: channel,
		StateDir: c.cfg.StateDir, Version: version, Events: api.NewBroadcaster(), Started: time.Now(), ReleaseKeyFP: releaseKeyFP(c.cfg.ReleasePubKey), Static: console.Handler()}
	go srv.Listen(ctx)
	// Passkey relying-party settings come from tenant policy at call time.
	if m, ok := c.auth.Method("webauthn"); ok {
		m.(*auth.WebAuthnMethod).Settings = srv.RelyingParty
	}
	tlsCfg, err := srv.TLSConfig(certPEM, keyPEM)
	if err != nil {
		return err
	}
	hs := &http.Server{Addr: c.cfg.Listen, Handler: srv.Handler(), TLSConfig: tlsCfg,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second}
	c.log.Info("rostor core listening", "addr", c.cfg.Listen, "tenant", c.tenantID, "provider", c.provider.Name(), "version", version)
	errc := make(chan error, 2)
	go func() { errc <- hs.ListenAndServeTLS("", "") }()
	if c.cfg.AdminListen != "" {
		// Plain HTTP for the reverse proxy. Same handler, so there is exactly
		// one API; only the transport differs (spec §9).
		ah := &http.Server{Addr: c.cfg.AdminListen, Handler: srv.ProxiedHandler(c.cfg.TrustedProxies),
			ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second}
		c.log.Info("rostor admin listener (behind proxy)", "addr", c.cfg.AdminListen, "trusted_proxies", c.cfg.TrustedProxies)
		go func() { errc <- ah.ListenAndServe() }()
	}
	return <-errc
}

// serverCert issues (or reuses) the core's own TLS certificate from the CA.
// It is re-issued whenever the configured SANs change.
func serverCert(c *core, ca *pki.CA) ([]byte, []byte, error) {
	hosts := c.cfg.TLSHosts
	if len(hosts) == 0 {
		hosts = []string{"localhost", "127.0.0.1"}
		if h, err := os.Hostname(); err == nil {
			hosts = append(hosts, h)
		}
		if addrs, err := net.InterfaceAddrs(); err == nil {
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() && ipn.IP.To4() != nil {
					hosts = append(hosts, ipn.IP.String())
				}
			}
		}
	}
	certPath := filepath.Join(c.cfg.DataDir, "server.crt")
	keyPath := filepath.Join(c.cfg.DataDir, "server.key")
	sanPath := filepath.Join(c.cfg.DataDir, "server.sans")
	// Keyed by SANs and by issuing CA, so a re-bootstrapped CA re-issues.
	want := fmt.Sprintf("%x %v", pki.Fingerprint(ca.Cert), hosts)
	if prev, err := os.ReadFile(sanPath); err == nil && string(prev) == want {
		cert, err1 := os.ReadFile(certPath)
		key, err2 := os.ReadFile(keyPath)
		if err1 == nil && err2 == nil {
			return cert, key, nil
		}
	}
	cert, key, err := ca.IssueServer(hosts, 2*365*24*time.Hour)
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(c.cfg.DataDir, 0o700); err != nil {
		return nil, nil, err
	}
	_ = os.WriteFile(certPath, cert, 0o600)
	_ = os.WriteFile(keyPath, key, 0o600)
	_ = os.WriteFile(sanPath, []byte(want), 0o600)
	c.log.Info("issued server certificate", "sans", hosts)
	return cert, key, nil
}

// runBootstrap creates the tenant, the CA, the built-in directory admin role,
// an admin service account, and prints its API token once.
func runBootstrap(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("bootstrap", flag.ExitOnError)
	name := fs.String("tenant", "rostor", "tenant name")
	fs.Parse(args)
	c, err := open(ctx, true)
	if err != nil {
		return err
	}
	defer c.db.Close()
	if _, err := c.db.Migrate(ctx); err != nil {
		return err
	}
	if err := c.loadTenant(ctx); err != nil {
		return err
	}
	if c.tenantID != "" {
		return fmt.Errorf("tenant %s already exists; bootstrap is one-shot", c.tenantID)
	}
	tenantID := ids.New("tnt")
	var token string
	err = c.db.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1,$2)`, tenantID, *name); err != nil {
			return err
		}
		if _, err := c.devices.EnsureCA(ctx, tx, tenantID, *name); err != nil {
			return err
		}
		sys := directory.Actor{Kind: "system", ID: "bootstrap", CorrelationID: ids.New("corr")}
		// Built-in resources, roles and the directory-admins group (§2.4,
		// §3.3). The same call runs on every start for existing installs.
		if err := directory.EnsureBuiltins(ctx, tx, tenantID, c.authz); err != nil {
			return err
		}
		admin, err := directory.CreatePrincipal(ctx, tx, tenantID, sys, directory.Principal{Kind: "service", Username: "admin-cli",
			DisplayName: map[string]string{"en": "Admin CLI"}})
		if err != nil {
			return err
		}
		if _, err := directory.CreateGrant(ctx, tx, tenantID, sys, directory.Grant{SubjectKind: "principal", SubjectID: admin.ID,
			Role: "admin", ResourceType: "directory", ResourceID: "root"}, c.authz); err != nil {
			return err
		}
		token, err = c.auth.MintAPIToken(ctx, tx, tenantID, sys, admin.ID, "bootstrap admin", 0)
		return err
	})
	if err != nil {
		return err
	}
	fmt.Printf("tenant:      %s\n", tenantID)
	fmt.Printf("admin token: %s\n", token)
	fmt.Println("Store the token now; it is not shown again. Export it as ROSTOR_TOKEN for `rostor admin`.")
	return nil
}

// releaseKeyFP shows which release key this appliance trusts.
func releaseKeyFP(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}
