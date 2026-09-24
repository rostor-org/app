// Package broker implements the agent side of the pipe protocol: it turns a
// `ui` or `logon` request (password or badge) into a reply by consulting core
// and the local account manager. It holds all the decision-to-action mapping from contract
// §1.2 and §3 and is fully testable with fakes.
package broker

import (
	"context"
	"errors"
	"log"
	"time"

	"rostor.org/app/cmd/rostor-agent/internal/catalog"
	"rostor.org/app/cmd/rostor-agent/internal/core"
	"rostor.org/app/cmd/rostor-agent/internal/localuser"
	"rostor.org/app/cmd/rostor-agent/internal/pipeproto"
)

// Broker answers pipe requests.
type Broker struct {
	// Verifier is nil when the agent is not enrolled; every logon then
	// answers agent.not_enrolled rather than crashing the lock screen path.
	Verifier core.Verifier
	Accounts localuser.Manager
	Resource core.Resource
	Logger   *log.Logger
}

// Handle dispatches one request. It never returns an error to the transport:
// every failure becomes an ok:false reply with a code the credprov can show.
func (b *Broker) Handle(ctx context.Context, req pipeproto.Request) pipeproto.Reply {
	locale := req.Locale
	if locale == "" {
		locale = catalog.DefaultLocale
	}
	switch req.Op {
	case "ui":
		return b.ui(locale)
	case "logon":
		return b.logon(ctx, locale, req)
	default:
		return b.fail(locale, "agent.bad_request", "")
	}
}

func (b *Broker) ui(locale string) pipeproto.Reply {
	m, err := catalog.UI(locale)
	if err != nil {
		b.logf("ui: catalog error: %v", err)
		return pipeproto.Reply{OK: false, Code: "agent.bad_request"}
	}
	return pipeproto.Reply{OK: true, Strings: &pipeproto.UIStrings{
		TileLabel:     m["tile_label"],
		UsernameLabel: m["username_label"],
		PasswordLabel: m["password_label"],
		SubmitLabel:   m["submit_label"],
		Connecting:    m["connecting"],
		PinLabel:      m["pin_label"],
		BadgeHint:     m["badge_hint"],
	}}
}

func (b *Broker) logon(ctx context.Context, locale string, req pipeproto.Request) pipeproto.Reply {
	// Which presentation this is (§2.2 password, §2.3 badge). The log label
	// never carries a whole badge number: it is a credential.
	var cred core.Credential
	var who string
	switch {
	case req.Badge != nil:
		if req.Badge.Number == "" {
			return b.fail(locale, "auth.failed", "")
		}
		cred = core.Credential{Type: "badge", Number: req.Badge.Number, PIN: req.Badge.PIN}
		who = "badge ..." + tail(req.Badge.Number, 4)
	case req.Identifier != "":
		cred = core.Credential{Type: "password", Identifier: req.Identifier, Secret: req.Secret}
		who = req.Identifier
	default:
		return b.fail(locale, "auth.failed", "")
	}
	if b.Verifier == nil {
		return b.fail(locale, "agent.not_enrolled", "")
	}
	started := time.Now()
	resp, err := b.Verifier.Verify(ctx, core.VerifyRequest{
		Credential: cred,
		Action:     "logon",
		Resource:   b.Resource,
		Locale:     locale,
	})
	if err != nil {
		b.logf("logon %q: core error after %s: %v", who, time.Since(started).Round(time.Millisecond), err)
		if errors.Is(err, context.DeadlineExceeded) {
			return b.fail(locale, "agent.timeout", "")
		}
		return b.fail(locale, "agent.core_unreachable", "")
	}

	switch resp.Decision {
	case core.DecisionAllow:
		return b.allow(locale, who, resp)
	case core.DecisionContinue:
		// The card matched but core needs a PIN before it decides. Nothing
		// is allowed or denied yet, so no local account is touched; the
		// credprov collects the PIN and resends the same badge with it.
		need := resp.Need()
		b.logf("logon %q: CONTINUE (need %s)", who, need)
		rep := b.fail(locale, core.CodeContinue, resp.Message)
		rep.Need = need
		return rep
	}

	code := resp.FirstCode()
	if code == "" {
		code = "auth.failed"
	}
	b.logf("logon %q: DENY %s", who, code)
	// Suspension and lifecycle denials also close the door locally so a
	// cached Windows credential cannot outlive the directory decision. Only
	// the password path names the account; a badge denial carries no
	// username the agent could act on.
	if (code == "principal.suspended" || code == "principal.not_active") && cred.Type == "password" {
		if u, ok := localuser.NormalizeUsername(req.Identifier); ok {
			if err := b.Accounts.Disable(u); err != nil && !errors.Is(err, localuser.ErrNotManaged) {
				b.logf("logon %q: disable local account: %v", u, err)
			}
		}
	}
	return b.fail(locale, code, resp.Message)
}

// tail returns the last n characters of s (all of s when shorter).
func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

func (b *Broker) allow(locale, identifier string, resp *core.VerifyResponse) pipeproto.Reply {
	if resp.Principal == nil || resp.Principal.Username == "" {
		b.logf("logon %q: ALLOW without principal", identifier)
		return b.fail(locale, "agent.local_account_failed", "")
	}
	username, ok := localuser.NormalizeUsername(resp.Principal.Username)
	if !ok {
		b.logf("logon %q: principal username %q not usable locally", identifier, resp.Principal.Username)
		return b.fail(locale, "agent.local_account_failed", "")
	}
	secret, err := b.Accounts.EnsureEnabled(username, resp.Principal.DisplayName)
	if err != nil {
		b.logf("logon %q: local account %q: %v", identifier, username, err)
		return b.fail(locale, "agent.local_account_failed", "")
	}
	b.logf("logon %q: ALLOW as local %q (assurance %s)", identifier, username, resp.Assurance)
	return pipeproto.Reply{OK: true, LocalUser: username, LocalSecret: secret}
}

// fail builds a denial. Core-rendered text wins; agent-local and unrendered
// codes fall back to the bundled catalog.
func (b *Broker) fail(locale, code, message string) pipeproto.Reply {
	if message == "" {
		message = catalog.Message(locale, code)
	}
	return pipeproto.Reply{OK: false, Code: code, Message: message}
}

func (b *Broker) logf(format string, args ...any) {
	if b.Logger != nil {
		b.Logger.Printf(format, args...)
	}
}
