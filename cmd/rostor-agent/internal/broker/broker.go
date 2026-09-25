// Package broker implements the agent side of the pipe protocol: it turns a
// `ui` or `logon` request (password or badge) into a reply by consulting core
// and the local account manager. It holds all the decision-to-action mapping from contract
// §1.2 and §3 and is fully testable with fakes.
package broker

import (
	"context"
	"errors"
	"log"
	"sync/atomic"
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
	// OnLogon, when set, is called in its own goroutine after an ALLOW
	// reply has been built, with the identifier the person presented (the
	// principal's username for a badge, which carries none), the principal
	// id and the local account. It never delays the reply: sign-in scripts
	// (SPEC-scripts) run behind the lock screen, not in front of it.
	OnLogon func(identifier, principalID, localAccount string)

	// policy is the last effective auth policy the heartbeat fetched
	// (§1.5), stored as a core.PolicyResponse value. It is read on every
	// `ui` request from the pipe goroutines and written from the heartbeat,
	// hence the atomic; nil until the first successful fetch.
	policy atomic.Value
}

// SetPolicy records the effective auth policy for this device. The
// heartbeat calls it after every successful fetch; a failed fetch leaves
// the previous value in place, so the lock screen keeps the last known
// policy rather than falling back to password on a network blip.
func (b *Broker) SetPolicy(p core.PolicyResponse) {
	b.policy.Store(p)
}

// DefaultMethod is the sign-in method the current policy puts first. Before
// any policy is known it is password (§1.5), and an unrecognised value from
// core is treated as password too: the credprov must never be handed a
// method it cannot render.
func (b *Broker) DefaultMethod() string {
	p, ok := b.policy.Load().(core.PolicyResponse)
	if !ok {
		return core.DefaultMethodPassword
	}
	switch p.Login.DefaultMethod {
	case core.DefaultMethodPasskey, core.DefaultMethodBadge:
		return p.Login.DefaultMethod
	}
	return core.DefaultMethodPassword
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

// ui builds the §2.1 reply. When the effective policy puts badges first the
// tile and identifier labels switch to their badge-first catalog entries;
// the credprov renders whatever it is given, so a policy change shows at
// the next lock without a credprov update.
func (b *Broker) ui(locale string) pipeproto.Reply {
	m, err := catalog.UI(locale)
	if err != nil {
		b.logf("ui: catalog error: %v", err)
		return pipeproto.Reply{OK: false, Code: "agent.bad_request"}
	}
	method := b.DefaultMethod()
	tileKey, userKey := "tile_label", "username_label"
	if method == core.DefaultMethodBadge {
		tileKey, userKey = "tile_label_badge", "username_label_badge"
	}
	return pipeproto.Reply{OK: true, DefaultMethod: method, Strings: &pipeproto.UIStrings{
		TileLabel:     m[tileKey],
		UsernameLabel: m[userKey],
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
		return b.allow(locale, who, req.Identifier, resp)
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

// allow builds the ALLOW reply. who is the log label; presented is the
// identifier as typed, empty for a badge.
func (b *Broker) allow(locale, who, presented string, resp *core.VerifyResponse) pipeproto.Reply {
	if resp.Principal == nil || resp.Principal.Username == "" {
		b.logf("logon %q: ALLOW without principal", who)
		return b.fail(locale, "agent.local_account_failed", "")
	}
	username, ok := localuser.NormalizeUsername(resp.Principal.Username)
	if !ok {
		b.logf("logon %q: principal username %q not usable locally", who, resp.Principal.Username)
		return b.fail(locale, "agent.local_account_failed", "")
	}
	secret, err := b.Accounts.EnsureEnabled(username, resp.Principal.DisplayName)
	if err != nil {
		b.logf("logon %q: local account %q: %v", who, username, err)
		return b.fail(locale, "agent.local_account_failed", "")
	}
	b.logf("logon %q: ALLOW as local %q (assurance %s)", who, username, resp.Assurance)
	if hook := b.OnLogon; hook != nil {
		identifier := presented
		if identifier == "" {
			identifier = resp.Principal.Username
		}
		go hook(identifier, resp.Principal.ID, username)
	}
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
