package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"rostor.org/app/internal/config"
	"rostor.org/app/internal/update"
)

// runUpdate is the privileged half of the update path. `check` is run by a
// systemd timer and only records state; `apply` is run by a systemd path
// unit when the core has dropped a request file (or by an operator), and
// swaps the binary and restarts the service. The core process itself never
// needs the privilege to replace its own executable.
func runUpdate(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return errors.New("usage: rostor update check|apply [--channel-url URL] [--pubkey FILE] [--target PATH] [--service NAME]")
	}
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	cfg := config.FromEnv()
	channelURL := fs.String("channel-url", os.Getenv("ROSTOR_CHANNEL_URL"), "signed manifest URL")
	pubkey := fs.String("pubkey", cfg.ReleasePubKey, "pinned release public key")
	target := fs.String("target", defaultTarget(), "binary to replace")
	service := fs.String("service", os.Getenv("ROSTOR_SERVICE"), "systemd unit to restart after apply (empty: none)")
	token := fs.String("token", os.Getenv("ROSTOR_CHANNEL_TOKEN"), "bearer token for a private release host")
	fs.Parse(args[1:])
	if *channelURL == "" {
		return errors.New("ROSTOR_CHANNEL_URL is not set")
	}
	pub, err := update.LoadPublicKey(*pubkey)
	if err != nil {
		return err
	}
	c := &update.Client{ManifestURL: *channelURL, PublicKey: pub, Token: *token}
	st := update.LoadState(cfg.StateDir)
	st.Current = version
	now := time.Now().UTC()

	m, err := c.Fetch(ctx)
	st.CheckedAt = &now
	if err != nil {
		st.LastError = err.Error()
		_ = update.SaveState(cfg.StateDir, st)
		return err
	}
	st.Channel = m.Channel
	st.LastError = ""
	st.Notes = m.Notes
	if update.NewerThan(m.Version, version) {
		st.Available = m.Version
	} else {
		st.Available = ""
	}

	switch args[0] {
	case "check":
		if err := update.SaveState(cfg.StateDir, st); err != nil {
			return err
		}
		if st.Available != "" {
			fmt.Printf("update available: %s (running %s)\n", st.Available, version)
		} else {
			fmt.Printf("up to date: %s\n", version)
		}
		return nil
	case "apply":
		defer os.Remove(update.RequestPath(cfg.StateDir))
		if st.Available == "" {
			_ = update.SaveState(cfg.StateDir, st)
			fmt.Printf("nothing to apply: running %s, channel has %s\n", version, m.Version)
			return nil
		}
		path, err := c.Download(ctx, m, filepath.Dir(*target))
		if err != nil {
			st.LastError = err.Error()
			_ = update.SaveState(cfg.StateDir, st)
			return err
		}
		if err := update.Swap(path, *target); err != nil {
			st.LastError = err.Error()
			_ = update.SaveState(cfg.StateDir, st)
			return err
		}
		st.AppliedAt = &now
		st.Current = m.Version
		st.Available = ""
		if err := update.SaveState(cfg.StateDir, st); err != nil {
			return err
		}
		fmt.Printf("installed %s at %s (previous kept as %s.previous)\n", m.Version, *target, *target)
		if *service != "" {
			// The new binary migrates the database on start (embedded migrations).
			out, err := exec.CommandContext(ctx, "systemctl", "restart", *service).CombinedOutput()
			if err != nil {
				return fmt.Errorf("restart %s: %v: %s", *service, err, out)
			}
			fmt.Printf("restarted %s\n", *service)
		}
		return nil
	default:
		return fmt.Errorf("unknown update verb %q", args[0])
	}
}

func defaultTarget() string {
	if p, err := os.Executable(); err == nil {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return r
		}
		return p
	}
	return "/usr/local/bin/rostor"
}
