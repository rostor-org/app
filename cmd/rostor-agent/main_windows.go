//go:build windows

// rostor-agent is the Rostor device agent for Windows (contract: docs/contracts/
// windows-logon.md). It runs as the RostorAgent service and brokers logon
// between the credential provider (named pipe) and core (mTLS).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"rostor.org/app/cmd/rostor-agent/internal/broker"
	"rostor.org/app/cmd/rostor-agent/internal/core"
	"rostor.org/app/cmd/rostor-agent/internal/enroll"
	"rostor.org/app/cmd/rostor-agent/internal/ledger"
	"rostor.org/app/cmd/rostor-agent/internal/localuser"
	"rostor.org/app/cmd/rostor-agent/internal/paths"
	"rostor.org/app/cmd/rostor-agent/internal/pipe"
	"rostor.org/app/cmd/rostor-agent/internal/pipeproto"
	"rostor.org/app/cmd/rostor-agent/internal/trust"
)

const version = "0.1.0"

const usage = `usage: rostor-agent <command> [flags]

commands:
  run               run the agent (as a service when started by SCM, else in the foreground)
                    flags: --mock-core   no core: identifier "testuser" (any secret) and badge
                                       1234567890 ALLOW; badge 5555555555 needs PIN 2468
  enroll            enroll this device with core
                    flags: --core-url URL --token TOKEN [--ca-file PATH] [--insecure]
  install-service   register and start the RostorAgent service
                    flags: [--mock-core]
  uninstall-service stop and remove the RostorAgent service
  pipe-test         send one request to the agent pipe and print the reply
                    flags: --op ui|logon [--identifier ID --secret S | --badge N [--pin P]] [--locale L]
  trust             print the pinned CA fingerprints, the device certificate's issuer
                    and expiry, and the last trust bundle version (no network)
  renew             renew the device certificate; flags: --now (required)
  version           print the agent version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = cmdRun(os.Args[2:])
	case "enroll":
		err = cmdEnroll(os.Args[2:])
	case "install-service":
		err = cmdInstallService(os.Args[2:])
	case "uninstall-service":
		err = cmdUninstallService()
	case "pipe-test":
		err = cmdPipeTest(os.Args[2:])
	case "trust":
		err = cmdTrust()
	case "renew":
		err = cmdRenew(os.Args[2:])
	case "version":
		fmt.Println(version)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "rostor-agent:", err)
		os.Exit(1)
	}
}

// ---- run -------------------------------------------------------------------

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	mock := fs.Bool("mock-core", false, "use the in-process mock core")
	if err := fs.Parse(args); err != nil {
		return err
	}
	isService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	logger, closeLog, err := openLog(!isService)
	if err != nil {
		return err
	}
	defer closeLog()

	b, err := buildBroker(logger, *mock)
	if err != nil {
		logger.Printf("startup failed: %v", err)
		return err
	}
	srv := &pipe.Server{Path: paths.PipeName, Handler: b, Logger: logger}
	if err := srv.Listen(); err != nil {
		logger.Printf("listen %s: %v", paths.PipeName, err)
		return err
	}
	logger.Printf("rostor-agent %s listening on %s (mock-core=%v, enrolled=%v)", version, paths.PipeName, *mock, b.Verifier != nil && !*mock)

	if isService {
		return svc.Run(paths.ServiceName, &service{srv: srv, logger: logger})
	}
	fmt.Println("running in the foreground; Ctrl+C to stop")
	return srv.Serve()
}

// buildBroker wires the verifier and account manager. A missing enrollment
// is not fatal: the service must still answer `ui` and report
// agent.not_enrolled on logon rather than leave the pipe dead.
func buildBroker(logger *log.Logger, mock bool) (*broker.Broker, error) {
	led, err := ledger.Open(paths.Ledger)
	if err != nil {
		return nil, fmt.Errorf("ledger: %w", err)
	}
	hostname, _ := os.Hostname()
	b := &broker.Broker{
		Accounts: &localuser.NetAPI{Ledger: led, Logger: logger},
		Resource: core.Resource{Type: "workstation", ID: hostname},
		Logger:   logger,
	}
	if mock {
		b.Verifier = core.Mock{AllowIdentifier: "testuser"}
		return b, nil
	}
	cfg, err := enroll.LoadConfig(paths.AgentJSON)
	if errors.Is(err, os.ErrNotExist) {
		logger.Printf("not enrolled (%s missing); logon will answer agent.not_enrolled", paths.AgentJSON)
		return b, nil
	}
	if err != nil {
		return nil, err
	}
	if cfg.Resource.ID != "" {
		b.Resource = cfg.Resource
	}
	mgr, err := newTrustManager(cfg, b.Resource, logger)
	if err != nil {
		return nil, err
	}
	b.Verifier = mgr
	go heartbeat(mgr, logger)
	return b, nil
}

func agentFiles() trust.Files {
	return trust.Files{AgentJSON: paths.AgentJSON, DeviceKey: paths.DeviceKey, DeviceCert: paths.DeviceCert, CACert: paths.CACert}
}

// newTrustManager builds the mTLS client and the trust manager around it.
// A renewal interrupted between its two renames is repaired first, because
// the client cannot load a key that no longer matches its certificate.
func newTrustManager(cfg *enroll.Config, res core.Resource, logger *log.Logger) (*trust.Manager, error) {
	files := agentFiles()
	if _, err := trust.Recover(files); err != nil {
		logger.Printf("recover certificate files: %v", err)
	}
	client, err := core.NewClient(cfg.CoreURL, paths.DeviceCert, paths.DeviceKey, paths.CACert, res, version)
	if err != nil {
		return nil, err
	}
	return &trust.Manager{
		Client:    client,
		Files:     files,
		Config:    cfg,
		SecureKey: enroll.SecureKeyFile,
		Logger:    logger,
	}, nil
}

// heartbeat runs the trust check (bundle update, renewal) and posts posture
// (§1.3) at start and every ten minutes; failures are only logged.
func heartbeat(mgr *trust.Manager, logger *log.Logger) {
	osVersion := windowsVersion()
	first := true
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 4*core.Timeout)
		var err error
		if first {
			err = mgr.Start(ctx)
			first = false
		} else {
			err = mgr.Check(ctx)
		}
		if err != nil {
			logger.Printf("trust check: %v", err)
		}
		cancel()
		ctx, cancel = context.WithTimeout(context.Background(), core.Timeout)
		if err := mgr.Client.Posture(ctx, osVersion); err != nil {
			logger.Printf("posture: %v", err)
		}
		cancel()
		time.Sleep(10 * time.Minute)
	}
}

type service struct {
	srv    *pipe.Server
	logger *log.Logger
}

func (s *service) Execute(_ []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	go func() {
		if err := s.srv.Serve(); err != nil {
			s.logger.Printf("serve: %v", err)
		}
	}()
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			_ = s.srv.Close()
			s.logger.Printf("service stopping")
			return false, 0
		}
	}
	return false, 0
}

func openLog(alsoStderr bool) (*log.Logger, func(), error) {
	if err := os.MkdirAll(paths.LogDir, 0o755); err != nil {
		return nil, nil, err
	}
	f, err := os.OpenFile(paths.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, nil, err
	}
	var w io.Writer = f
	if alsoStderr {
		w = io.MultiWriter(f, os.Stderr)
	}
	return log.New(w, "", log.LstdFlags|log.LUTC), func() { _ = f.Close() }, nil
}

// ---- enroll ----------------------------------------------------------------

func cmdEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	coreURL := fs.String("core-url", "", "core base URL, e.g. https://core.example:8443")
	token := fs.String("token", "", "single-use enrollment token")
	caFile := fs.String("ca-file", "", "PEM CA to trust for the enrollment call")
	insecure := fs.Bool("insecure", false, "skip TLS verification for the enrollment call (PoC only)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	hostname, _ := os.Hostname()
	cfg, err := enroll.Run(context.Background(), enroll.Options{
		CoreURL:  *coreURL,
		Token:    *token,
		CAFile:   *caFile,
		Insecure: *insecure,
		Posture:  enroll.Posture{OS: "windows", OSVersion: windowsVersion(), Hostname: hostname},
		Files: enroll.Files{
			AgentJSON: paths.AgentJSON, DeviceKey: paths.DeviceKey,
			DeviceCert: paths.DeviceCert, CACert: paths.CACert,
		},
		SecureKey: enroll.SecureKeyFile,
	})
	if err != nil {
		return err
	}
	fmt.Printf("enrolled as %s (%s %s); files written to %s\n", cfg.DeviceID, cfg.Resource.Type, cfg.Resource.ID, paths.ProgramData)
	fmt.Println("restart the RostorAgent service to pick up the enrollment")
	return nil
}

func windowsVersion() string {
	major, minor, build := windows.RtlGetNtVersionNumbers()
	return fmt.Sprintf("%d.%d.%d", major, minor, build)
}

// ---- service install / uninstall ------------------------------------------

func cmdInstallService(args []string) error {
	fs := flag.NewFlagSet("install-service", flag.ContinueOnError)
	mock := fs.Bool("mock-core", false, "run the service with --mock-core")
	if err := fs.Parse(args); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, _ = filepath.Abs(exe)
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if s, err := m.OpenService(paths.ServiceName); err == nil {
		s.Close()
		return fmt.Errorf("service %s already exists", paths.ServiceName)
	}
	svcArgs := []string{"run"}
	if *mock {
		svcArgs = append(svcArgs, "--mock-core")
	}
	s, err := m.CreateService(paths.ServiceName, exe, mgr.Config{
		DisplayName:  paths.ServiceDisplayName,
		Description:  "Brokers Windows logon between the Rostor credential provider and the Rostor core.",
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
	}, svcArgs...)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()
	if err := s.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	fmt.Printf("installed and started %s (%s %v)\n", paths.ServiceName, exe, svcArgs)
	return nil
}

func cmdUninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(paths.ServiceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", paths.ServiceName)
	}
	defer s.Close()
	if status, err := s.Control(svc.Stop); err == nil {
		deadline := time.Now().Add(15 * time.Second)
		for status.State != svc.Stopped && time.Now().Before(deadline) {
			time.Sleep(300 * time.Millisecond)
			status, err = s.Query()
			if err != nil {
				break
			}
		}
	}
	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}
	fmt.Printf("removed %s\n", paths.ServiceName)
	return nil
}

// ---- trust / renew -----------------------------------------------------------

func cmdTrust() error {
	trust.Inspect(agentFiles()).Write(os.Stdout, time.Now())
	return nil
}

// cmdRenew renews from the command line. The running service notices the
// new device.crt at its next check (within ten minutes) and reloads; until
// then it keeps using the old certificate, which core accepts for 24 h.
func cmdRenew(args []string) error {
	fs := flag.NewFlagSet("renew", flag.ContinueOnError)
	now := fs.Bool("now", false, "renew immediately regardless of expiry")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*now {
		return errors.New("renew: pass --now to renew the certificate immediately")
	}
	cfg, err := enroll.LoadConfig(paths.AgentJSON)
	if err != nil {
		return fmt.Errorf("not enrolled: %w", err)
	}
	res := cfg.Resource
	if res.ID == "" {
		hostname, _ := os.Hostname()
		res = core.Resource{Type: "workstation", ID: hostname}
	}
	mgr, err := newTrustManager(cfg, res, log.New(os.Stderr, "", 0))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*core.Timeout)
	defer cancel()
	if err := mgr.Renew(ctx); err != nil {
		return err
	}
	leaf := mgr.Client.Certificate()
	fmt.Printf("renewed: issuer %s, expires %s\n", leaf.Issuer.CommonName, leaf.NotAfter.UTC().Format(time.RFC3339))
	fmt.Println("the RostorAgent service picks the new certificate up at its next trust check (within 10 minutes) or on restart")
	return nil
}

// ---- pipe-test ---------------------------------------------------------------

func cmdPipeTest(args []string) error {
	fs := flag.NewFlagSet("pipe-test", flag.ContinueOnError)
	op := fs.String("op", "ui", "ui or logon")
	identifier := fs.String("identifier", "", "identifier for logon")
	secret := fs.String("secret", "", "secret for logon")
	badge := fs.String("badge", "", "badge number for a badge logon (instead of identifier/secret)")
	pin := fs.String("pin", "", "PIN to send with --badge")
	locale := fs.String("locale", "en-US", "locale")
	if err := fs.Parse(args); err != nil {
		return err
	}
	req := pipeproto.Request{Op: *op, Locale: *locale, Identifier: *identifier, Secret: *secret}
	if *badge != "" {
		req.Badge = &pipeproto.Badge{Number: *badge, PIN: *pin}
	}
	started := time.Now()
	rep, err := pipe.Call(paths.PipeName, req, 10*time.Second)
	if err != nil {
		return fmt.Errorf("pipe %s: %w", paths.PipeName, err)
	}
	out, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(out))
	fmt.Fprintf(os.Stderr, "(%s)\n", time.Since(started).Round(time.Millisecond))
	return nil
}
