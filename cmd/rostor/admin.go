package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The admin CLI is a plain HTTP client. It knows nothing the API does not
// expose, by design (spec principle 6).

type client struct {
	base  string
	token string
	http  *http.Client
}

func newClient() (*client, error) {
	base := os.Getenv("ROSTOR_URL")
	if base == "" {
		base = "https://localhost:8443"
	}
	tok := os.Getenv("ROSTOR_TOKEN")
	if tok == "" {
		return nil, errors.New("ROSTOR_TOKEN is not set")
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	// Trust the core's own CA when it is on this machine; otherwise the
	// operator points ROSTOR_CA at the ca.crt they were given.
	caPath := os.Getenv("ROSTOR_CA")
	if caPath == "" {
		home, _ := os.UserHomeDir()
		caPath = filepath.Join(getenvDefault("ROSTOR_DATA_DIR", filepath.Join(home, ".rostor")), "ca.crt")
	}
	// System roots (a proxy with a public certificate) plus the core's own CA
	// (talking to it directly).
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if pem, err := os.ReadFile(caPath); err == nil {
		pool.AppendCertsFromPEM(pem)
	}
	tlsCfg.RootCAs = pool
	return &client{base: strings.TrimRight(base, "/"), token: tok,
		http: &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}}, nil
}

func getenvDefault(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func (c *client) do(ctx context.Context, method, path string, body any) (map[string]any, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(raw)))
		}
	}
	if resp.StatusCode >= 400 {
		msg, _ := out["message"].(string)
		code, _ := out["code"].(string)
		return out, fmt.Errorf("%s (%s) %v", msg, code, out["params"])
	}
	return out, nil
}

func printJSON(v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}

func runAdmin(ctx context.Context, args []string) error {
	if len(args) < 2 {
		return errors.New(`usage: rostor admin <object> <verb> [flags]
  setup-admin --username U --display "Name" --password P   (first human administrator; uses ROSTOR_TOKEN as the bootstrap token)
  user create --username U --display "Name"
  user password --user U --password P
  user suspend --user U | user activate --user U
  group create --name G
  group add --group G --user U | group remove --group G --user U
  grant create --group G|--user U --role R --resource-type T --resource-id ID [--condition CEL] [--expires RFC3339]
  grant revoke --id GRANT_ID
  agent create --username U --display "Name" [--user OWNER]   (owner defaults to the caller)
  agent list | agent token --user AGENT | agent revoke-token --user AGENT
  agent grant --user AGENT --role R --resource-type T --resource-id ID [--condition CEL]
  agent suspend --user AGENT | agent activate --user AGENT
  device token [--resource-type workstation] [--ttl 3600]
  why --user U --action A --resource-type T --resource-id ID
  audit [--limit N] | audit verify
  update status | update apply`)
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	obj, verb, rest := args[0], args[1], args[2:]
	if obj == "why" || obj == "setup-admin" {
		verb, rest = "", args[1:]
	}
	fs := flag.NewFlagSet(obj+" "+verb, flag.ExitOnError)
	username := fs.String("username", "", "")
	display := fs.String("display", "", "")
	user := fs.String("user", "", "")
	group := fs.String("group", "", "")
	name := fs.String("name", "", "")
	password := fs.String("password", "", "")
	role := fs.String("role", "", "")
	rtype := fs.String("resource-type", "workstation", "")
	rid := fs.String("resource-id", "", "")
	cond := fs.String("condition", "", "")
	expires := fs.String("expires", "", "")
	id := fs.String("id", "", "")
	action := fs.String("action", "logon", "")
	ttl := fs.Int("ttl", 3600, "")
	limit := fs.Int("limit", 50, "")
	if obj == "update" {
		rest = nil
	}
	if obj == "audit" && verb == "verify" {
		rest = nil
	}
	if obj == "audit" && verb != "verify" {
		rest = append([]string{verb}, rest...)
		verb = "list"
	}
	fs.Parse(rest)

	var out map[string]any
	switch obj + " " + verb {
	case "user create":
		out, err = c.do(ctx, "POST", "/v1/admin/users", map[string]any{"username": *username, "display_name": map[string]string{"en": *display}})
	case "user password":
		out, err = c.do(ctx, "POST", "/v1/admin/users/"+url.PathEscape(*user)+"/bindings",
			map[string]any{"method": "password", "fields": map[string]string{"password": *password}})
	case "user suspend", "user activate":
		state := map[string]string{"suspend": "suspended", "activate": "active"}[verb]
		out, err = c.do(ctx, "POST", "/v1/admin/users/"+url.PathEscape(*user)+"/state", map[string]any{"state": state})
	case "group create":
		out, err = c.do(ctx, "POST", "/v1/admin/groups", map[string]any{"name": *name})
	case "group add":
		out, err = c.do(ctx, "POST", "/v1/admin/groups/"+url.PathEscape(*group)+"/members", map[string]any{"member_kind": "principal", "member": *user})
	case "group remove":
		out, err = c.do(ctx, "DELETE", "/v1/admin/groups/"+url.PathEscape(*group)+"/members", map[string]any{"member_kind": "principal", "member": *user})
	case "grant create":
		body := map[string]any{"role": *role, "resource_type": *rtype, "resource_id": *rid, "condition": *cond}
		if *group != "" {
			body["subject_kind"], body["subject"] = "group", *group
		} else {
			body["subject_kind"], body["subject"] = "principal", *user
		}
		if *expires != "" {
			body["expires_at"] = *expires
		}
		out, err = c.do(ctx, "POST", "/v1/admin/grants", body)
	case "grant revoke":
		out, err = c.do(ctx, "DELETE", "/v1/admin/grants/"+url.PathEscape(*id), nil)
	case "agent create":
		body := map[string]any{"username": *username, "display_name": map[string]string{"en": *display}}
		if *user != "" {
			body["owner"] = *user
		}
		out, err = c.do(ctx, "POST", "/v1/admin/agents", body)
	case "agent list":
		out, err = c.do(ctx, "GET", "/v1/admin/agents", nil)
	case "agent token":
		out, err = c.do(ctx, "POST", "/v1/admin/agents/"+url.PathEscape(*user)+"/token", nil)
	case "agent revoke-token":
		out, err = c.do(ctx, "DELETE", "/v1/admin/agents/"+url.PathEscape(*user)+"/token", nil)
	case "agent grant":
		out, err = c.do(ctx, "POST", "/v1/admin/agents/"+url.PathEscape(*user)+"/grants", map[string]any{"role": *role, "resource_type": *rtype, "resource_id": *rid, "condition": *cond})
	case "agent suspend", "agent activate":
		state := map[string]string{"suspend": "suspended", "activate": "active"}[verb]
		out, err = c.do(ctx, "POST", "/v1/admin/agents/"+url.PathEscape(*user)+"/state", map[string]any{"state": state})
	case "device token":
		out, err = c.do(ctx, "POST", "/v1/admin/enrollment-tokens", map[string]any{"resource_type": *rtype, "ttl_seconds": *ttl})
	case "setup-admin ":
		out, err = c.do(ctx, "POST", "/v1/auth/setup", map[string]any{"bootstrap_token": c.token, "username": *username, "display_name": *display, "password": *password})
	case "why ":
		q := url.Values{"principal": {*user}, "action": {*action}, "resource_type": {*rtype}, "resource_id": {*rid}}
		out, err = c.do(ctx, "GET", "/v1/admin/why?"+q.Encode(), nil)
	case "audit list":
		out, err = c.do(ctx, "GET", fmt.Sprintf("/v1/admin/audit?limit=%d", *limit), nil)
	case "audit verify":
		out, err = c.do(ctx, "GET", "/v1/admin/audit/verify", nil)
	case "update status":
		out, err = c.do(ctx, "GET", "/v1/admin/updates", nil)
	case "update apply":
		out, err = c.do(ctx, "POST", "/v1/admin/updates/apply", nil)
	default:
		return fmt.Errorf("unknown command %q", obj+" "+verb)
	}
	if err != nil {
		return err
	}
	printJSON(out)
	return nil
}
