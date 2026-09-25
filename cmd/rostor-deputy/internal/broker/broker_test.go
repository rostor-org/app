package broker

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"rostor.org/app/cmd/rostor-deputy/internal/core"
	"rostor.org/app/cmd/rostor-deputy/internal/localuser"
	"rostor.org/app/cmd/rostor-deputy/internal/pipeproto"
)

type fakeAccounts struct {
	enabled  []string
	names    []string // display name passed with each EnsureEnabled
	disabled []string
	failWith error
}

func (f *fakeAccounts) EnsureEnabled(u, displayName string) (string, error) {
	if f.failWith != nil {
		return "", f.failWith
	}
	f.enabled = append(f.enabled, u)
	f.names = append(f.names, displayName)
	return "SECRETSECRETSECRETSECRETSECRET12", nil
}

func (f *fakeAccounts) Disable(u string) error {
	f.disabled = append(f.disabled, u)
	return nil
}

type fakeVerifier struct {
	resp *core.VerifyResponse
	err  error
	got  core.VerifyRequest
}

func (f *fakeVerifier) Verify(_ context.Context, req core.VerifyRequest) (*core.VerifyResponse, error) {
	f.got = req
	return f.resp, f.err
}

func TestUI(t *testing.T) {
	b := &Broker{}
	rep := b.Handle(context.Background(), pipeproto.Request{Op: "ui", Locale: "en-US"})
	if !rep.OK || rep.Strings == nil || rep.Strings.TileLabel == "" || rep.Strings.SubmitLabel == "" {
		t.Fatalf("bad ui reply: %+v", rep)
	}
	// The badge path has no literals in the credprov either: both of its
	// strings must come from the catalog.
	if rep.Strings.PinLabel == "" || rep.Strings.BadgeHint == "" {
		t.Fatalf("badge strings missing: %+v", rep.Strings)
	}
}

func TestUIFollowsPolicy(t *testing.T) {
	b := &Broker{}
	ui := func() pipeproto.Reply {
		t.Helper()
		rep := b.Handle(context.Background(), pipeproto.Request{Op: "ui", Locale: "en-US"})
		if !rep.OK || rep.Strings == nil {
			t.Fatalf("bad ui reply: %+v", rep)
		}
		return rep
	}
	// Before any policy is known the deputy behaves as password (§1.5).
	rep := ui()
	if rep.DefaultMethod != "password" || rep.Strings.TileLabel != "Rostor" || rep.Strings.UsernameLabel != "Username" {
		t.Fatalf("no policy: %+v %+v", rep.DefaultMethod, rep.Strings)
	}
	password := *rep.Strings

	var pol core.PolicyResponse
	pol.Login.DefaultMethod = core.DefaultMethodBadge
	pol.Badge.Format = "wiegand26"
	b.SetPolicy(pol)
	rep = ui()
	if rep.DefaultMethod != "badge" || rep.Strings.TileLabel != "Tap your badge" || rep.Strings.UsernameLabel != "Badge, or username" {
		t.Fatalf("badge policy: %+v %+v", rep.DefaultMethod, rep.Strings)
	}
	// Only the tile and identifier labels and the heading change; the rest
	// of the strings (including badge_hint, which the tile shows on both)
	// are untouched.
	badge := *rep.Strings
	badge.TileLabel, badge.UsernameLabel, badge.Heading = password.TileLabel, password.UsernameLabel, password.Heading
	if badge != password {
		t.Fatalf("badge policy changed more than the two labels and the heading: %+v vs %+v", rep.Strings, password)
	}

	// Passkey is reported as such but rendered with the password strings:
	// the tile still collects a username and a secret.
	pol.Login.DefaultMethod = core.DefaultMethodPasskey
	b.SetPolicy(pol)
	rep = ui()
	if rep.DefaultMethod != "passkey" || *rep.Strings != password {
		t.Fatalf("passkey policy: %+v %+v", rep.DefaultMethod, rep.Strings)
	}

	// Switching back to password restores the original labels.
	pol.Login.DefaultMethod = core.DefaultMethodPassword
	b.SetPolicy(pol)
	rep = ui()
	if rep.DefaultMethod != "password" || *rep.Strings != password {
		t.Fatalf("password policy: %+v %+v", rep.DefaultMethod, rep.Strings)
	}

	// A method this deputy does not know is never forwarded to the credprov.
	pol.Login.DefaultMethod = "sms"
	b.SetPolicy(pol)
	rep = ui()
	if rep.DefaultMethod != "password" || *rep.Strings != password {
		t.Fatalf("unknown method: %+v %+v", rep.DefaultMethod, rep.Strings)
	}
	pol.Login.DefaultMethod = ""
	b.SetPolicy(pol)
	if rep = ui(); rep.DefaultMethod != "password" {
		t.Fatalf("empty method: %+v", rep)
	}
}

func TestUIWithMockPolicy(t *testing.T) {
	// --mock-core hands the broker the mock's policy: password, no badges,
	// tenant "Mock Lab".
	b := &Broker{Verifier: core.Mock{AllowIdentifier: "testuser"}, Accounts: &fakeAccounts{}}
	pol, err := core.Mock{}.Policy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b.SetPolicy(*pol)
	rep := b.Handle(context.Background(), pipeproto.Request{Op: "ui"})
	if rep.DefaultMethod != "password" || rep.Strings.TileLabel != "Rostor" || rep.Strings.Heading != "Sign in to Mock Lab" {
		t.Fatalf("got %+v %+v", rep.DefaultMethod, rep.Strings)
	}
}

func TestUIHeadingAndSwitchStrings(t *testing.T) {
	// v0.13.0 "Badge-first tile and the organisation name": the heading
	// names the tenant and follows the default method; the two command-link
	// texts are always present so the credprov can offer the other method.
	b := &Broker{}
	ui := func() pipeproto.UIStrings {
		t.Helper()
		rep := b.Handle(context.Background(), pipeproto.Request{Op: "ui", Locale: "en-US"})
		if !rep.OK || rep.Strings == nil {
			t.Fatalf("bad ui reply: %+v", rep)
		}
		return *rep.Strings
	}
	// No policy at all: password, no tenant, nothing dangling.
	s := ui()
	if s.Heading != "Sign in" || s.SwitchToUsername != "Use username" || s.SwitchToBadge != "Use badge" {
		t.Fatalf("no policy: %+v", s)
	}

	var pol core.PolicyResponse
	pol.Login.DefaultMethod = core.DefaultMethodPassword
	pol.TenantName = "ChattLab"
	b.SetPolicy(pol)
	if s = ui(); s.Heading != "Sign in to ChattLab" || s.SwitchToUsername != "Use username" || s.SwitchToBadge != "Use badge" {
		t.Fatalf("password+tenant: %+v", s)
	}

	pol.Login.DefaultMethod = core.DefaultMethodBadge
	b.SetPolicy(pol)
	if s = ui(); s.Heading != "Tap your badge · ChattLab" || s.TileLabel != "Tap your badge" || s.SwitchToUsername != "Use username" || s.SwitchToBadge != "Use badge" {
		t.Fatalf("badge+tenant: %+v", s)
	}

	// Passkey renders like password (the tile still collects a username).
	pol.Login.DefaultMethod = core.DefaultMethodPasskey
	b.SetPolicy(pol)
	if s = ui(); s.Heading != "Sign in to ChattLab" {
		t.Fatalf("passkey+tenant: %+v", s)
	}

	// A core that sends no tenant name (older than §1.5a, or an unnamed
	// tenant): the " to …" / " · …" tail is dropped, not left half-empty.
	pol.TenantName = ""
	pol.Login.DefaultMethod = core.DefaultMethodPassword
	b.SetPolicy(pol)
	if s = ui(); s.Heading != "Sign in" {
		t.Fatalf("password, no tenant: %+v", s)
	}
	pol.Login.DefaultMethod = core.DefaultMethodBadge
	b.SetPolicy(pol)
	if s = ui(); s.Heading != "Tap your badge" || s.TileLabel != "Tap your badge" {
		t.Fatalf("badge, no tenant: %+v", s)
	}
	if b.TenantName() != "" {
		t.Fatalf("TenantName: %q", b.TenantName())
	}
	pol.TenantName = "ChattLab"
	b.SetPolicy(pol)
	if b.TenantName() != "ChattLab" {
		t.Fatalf("TenantName: %q", b.TenantName())
	}
}

func TestSetPolicyConcurrentWithUI(t *testing.T) {
	// The heartbeat writes while pipe goroutines read; run under -race.
	b := &Broker{}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				var pol core.PolicyResponse
				pol.Login.DefaultMethod = []string{core.DefaultMethodPassword, core.DefaultMethodBadge}[j%2]
				b.SetPolicy(pol)
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				rep := b.Handle(context.Background(), pipeproto.Request{Op: "ui"})
				if !rep.OK || (rep.DefaultMethod != "password" && rep.DefaultMethod != "badge") {
					t.Errorf("got %+v", rep)
					return
				}
				// The labels always match the method in the same reply.
				wantTile := "Rostor"
				if rep.DefaultMethod == "badge" {
					wantTile = "Tap your badge"
				}
				if rep.Strings.TileLabel != wantTile {
					t.Errorf("method %s with tile %q", rep.DefaultMethod, rep.Strings.TileLabel)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestUnknownOp(t *testing.T) {
	rep := (&Broker{}).Handle(context.Background(), pipeproto.Request{Op: "nope"})
	if rep.OK || rep.Code != "deputy.bad_request" || rep.Message == "" {
		t.Fatalf("got %+v", rep)
	}
}

func TestLogonMockAllow(t *testing.T) {
	acc := &fakeAccounts{}
	b := &Broker{Verifier: core.Mock{AllowIdentifier: "testuser"}, Accounts: acc, Resource: core.Resource{Type: "workstation", ID: "PC"}}
	rep := b.Handle(context.Background(), pipeproto.Request{Op: "logon", Identifier: "testuser", Secret: "x"})
	if !rep.OK || rep.LocalUser != "testuser" || len(rep.LocalSecret) != 32 || rep.Code != "" {
		t.Fatalf("got %+v", rep)
	}
	if len(acc.enabled) != 1 || acc.enabled[0] != "testuser" {
		t.Fatalf("accounts touched: %+v", acc)
	}
}

func TestLogonMockDeny(t *testing.T) {
	acc := &fakeAccounts{}
	b := &Broker{Verifier: core.Mock{AllowIdentifier: "testuser"}, Accounts: acc}
	rep := b.Handle(context.Background(), pipeproto.Request{Op: "logon", Identifier: "nobody", Secret: "x", Locale: "en-US"})
	if rep.OK || rep.Code != "auth.failed" || rep.Message == "" || rep.LocalSecret != "" {
		t.Fatalf("got %+v", rep)
	}
	if len(acc.enabled)+len(acc.disabled) != 0 {
		t.Fatal("deny must not touch accounts")
	}
}

func TestLogonNotEnrolled(t *testing.T) {
	rep := (&Broker{Accounts: &fakeAccounts{}}).Handle(context.Background(), pipeproto.Request{Op: "logon", Identifier: "dan"})
	if rep.OK || rep.Code != "deputy.not_enrolled" {
		t.Fatalf("got %+v", rep)
	}
}

func TestLogonCoreUnreachable(t *testing.T) {
	v := &fakeVerifier{err: core.ErrUnreachable}
	rep := (&Broker{Verifier: v, Accounts: &fakeAccounts{}}).Handle(context.Background(), pipeproto.Request{Op: "logon", Identifier: "dan", Secret: "p"})
	if rep.OK || rep.Code != "deputy.core_unreachable" || rep.Message == "" {
		t.Fatalf("got %+v", rep)
	}
	if v.got.Credential.Type != "password" || v.got.Action != "logon" || v.got.Locale != "en-US" {
		t.Fatalf("request shape: %+v", v.got)
	}
}

func TestLogonTimeout(t *testing.T) {
	v := &fakeVerifier{err: context.DeadlineExceeded}
	rep := (&Broker{Verifier: v, Accounts: &fakeAccounts{}}).Handle(context.Background(), pipeproto.Request{Op: "logon", Identifier: "dan"})
	if rep.Code != "deputy.timeout" {
		t.Fatalf("got %+v", rep)
	}
}

func TestSuspendedDisablesLocalAccount(t *testing.T) {
	acc := &fakeAccounts{}
	v := &fakeVerifier{resp: &core.VerifyResponse{Decision: "DENY", Reason: []core.Reason{{Code: "principal.suspended"}}, Message: "Your account is suspended."}}
	rep := (&Broker{Verifier: v, Accounts: acc}).Handle(context.Background(), pipeproto.Request{Op: "logon", Identifier: "Dan"})
	if rep.OK || rep.Code != "principal.suspended" || rep.Message != "Your account is suspended." {
		t.Fatalf("got %+v", rep)
	}
	if len(acc.disabled) != 1 || acc.disabled[0] != "dan" {
		t.Fatalf("expected disable of dan, got %+v", acc)
	}
}

func TestGrantNoneDoesNotTouchAccount(t *testing.T) {
	acc := &fakeAccounts{}
	v := &fakeVerifier{resp: &core.VerifyResponse{Decision: "DENY", Reason: []core.Reason{{Code: "grant.none"}}, Message: "No access here."}}
	rep := (&Broker{Verifier: v, Accounts: acc}).Handle(context.Background(), pipeproto.Request{Op: "logon", Identifier: "dan"})
	if rep.Code != "grant.none" || len(acc.disabled) != 0 {
		t.Fatalf("got %+v %+v", rep, acc)
	}
}

func TestAllowWithBadUsername(t *testing.T) {
	acc := &fakeAccounts{}
	v := &fakeVerifier{resp: &core.VerifyResponse{Decision: "ALLOW", Principal: &core.Principal{Username: "dan evans"}}}
	rep := (&Broker{Verifier: v, Accounts: acc}).Handle(context.Background(), pipeproto.Request{Op: "logon", Identifier: "dan"})
	if rep.OK || rep.Code != "deputy.local_account_failed" || len(acc.enabled) != 0 {
		t.Fatalf("got %+v", rep)
	}
}

func TestAllowUsesPrincipalUsernameNotIdentifier(t *testing.T) {
	acc := &fakeAccounts{}
	v := &fakeVerifier{resp: &core.VerifyResponse{Decision: "ALLOW", Principal: &core.Principal{Username: "Dan.Evans", DisplayName: "Dan Evans"}}}
	rep := (&Broker{Verifier: v, Accounts: acc}).Handle(context.Background(), pipeproto.Request{Op: "logon", Identifier: "dan@rostor.org"})
	if !rep.OK || rep.LocalUser != "dan.evans" {
		t.Fatalf("got %+v", rep)
	}
}

func TestLocalAccountFailure(t *testing.T) {
	acc := &fakeAccounts{failWith: errors.New("NetUserAdd: boom")}
	b := &Broker{Verifier: core.Mock{AllowIdentifier: "testuser"}, Accounts: acc}
	rep := b.Handle(context.Background(), pipeproto.Request{Op: "logon", Identifier: "testuser"})
	if rep.OK || rep.Code != "deputy.local_account_failed" {
		t.Fatalf("got %+v", rep)
	}
}

// ---- badge (§2.3) ----------------------------------------------------------

func TestBadgeMockAllow(t *testing.T) {
	acc := &fakeAccounts{}
	b := &Broker{Verifier: core.Mock{AllowIdentifier: "testuser"}, Accounts: acc}
	rep := b.Handle(context.Background(), pipeproto.Request{Op: "logon", Badge: &pipeproto.Badge{Number: core.MockBadgePlain}})
	if !rep.OK || rep.LocalUser != "testuser" || len(rep.LocalSecret) != 32 || rep.Need != "" {
		t.Fatalf("got %+v", rep)
	}
	if len(acc.enabled) != 1 || acc.enabled[0] != "testuser" {
		t.Fatalf("accounts touched: %+v", acc)
	}
}

func TestBadgeMockContinueThenAllow(t *testing.T) {
	acc := &fakeAccounts{}
	b := &Broker{Verifier: core.Mock{AllowIdentifier: "testuser"}, Accounts: acc}
	rep := b.Handle(context.Background(), pipeproto.Request{Op: "logon", Locale: "en-US", Badge: &pipeproto.Badge{Number: core.MockBadgePIN}})
	if rep.OK || rep.Code != "auth.continue" || rep.Need != "pin" || rep.Message == "" || rep.LocalSecret != "" {
		t.Fatalf("tap without PIN: got %+v", rep)
	}
	if len(acc.enabled)+len(acc.disabled) != 0 {
		t.Fatal("continue must not touch accounts")
	}
	rep = b.Handle(context.Background(), pipeproto.Request{Op: "logon", Badge: &pipeproto.Badge{Number: core.MockBadgePIN, PIN: "0000"}})
	if rep.OK || rep.Code != "auth.failed" || rep.Need != "" {
		t.Fatalf("wrong PIN: got %+v", rep)
	}
	rep = b.Handle(context.Background(), pipeproto.Request{Op: "logon", Badge: &pipeproto.Badge{Number: core.MockBadgePIN, PIN: core.MockPIN}})
	if !rep.OK || rep.LocalUser != "testuser" || len(rep.LocalSecret) != 32 {
		t.Fatalf("right PIN: got %+v", rep)
	}
}

func TestBadgeMockUnknownDenies(t *testing.T) {
	b := &Broker{Verifier: core.Mock{AllowIdentifier: "testuser"}, Accounts: &fakeAccounts{}}
	rep := b.Handle(context.Background(), pipeproto.Request{Op: "logon", Badge: &pipeproto.Badge{Number: "0000001"}})
	if rep.OK || rep.Code != "auth.failed" || rep.Message == "" {
		t.Fatalf("got %+v", rep)
	}
	rep = b.Handle(context.Background(), pipeproto.Request{Op: "logon", Badge: &pipeproto.Badge{}})
	if rep.OK || rep.Code != "auth.failed" {
		t.Fatalf("empty badge: got %+v", rep)
	}
}

func TestBadgeRequestShape(t *testing.T) {
	v := &fakeVerifier{resp: &core.VerifyResponse{Decision: core.DecisionContinue,
		Reason:  []core.Reason{{Code: core.CodeContinue, Params: map[string]any{"need": "pin"}}},
		Message: "Enter your PIN."}}
	acc := &fakeAccounts{}
	rep := (&Broker{Verifier: v, Accounts: acc, Resource: core.Resource{Type: "workstation", ID: "PC"}}).Handle(
		context.Background(), pipeproto.Request{Op: "logon", Locale: "en-US", Badge: &pipeproto.Badge{Number: "4857726", PIN: "1234"}})
	if v.got.Credential.Type != "badge" || v.got.Credential.Number != "4857726" || v.got.Credential.PIN != "1234" ||
		v.got.Credential.Identifier != "" || v.got.Credential.Secret != "" || v.got.Action != "logon" || v.got.Resource.ID != "PC" {
		t.Fatalf("request shape: %+v", v.got)
	}
	// Core-rendered text wins over the catalog; need comes from the params.
	if rep.OK || rep.Code != "auth.continue" || rep.Need != "pin" || rep.Message != "Enter your PIN." {
		t.Fatalf("got %+v", rep)
	}
	if len(acc.enabled)+len(acc.disabled) != 0 {
		t.Fatal("continue must not touch accounts")
	}
}

func TestBadgeContinueWithoutParamsDefaultsToPin(t *testing.T) {
	v := &fakeVerifier{resp: &core.VerifyResponse{Decision: core.DecisionContinue, Reason: []core.Reason{{Code: core.CodeContinue}}}}
	rep := (&Broker{Verifier: v, Accounts: &fakeAccounts{}}).Handle(context.Background(), pipeproto.Request{Op: "logon", Badge: &pipeproto.Badge{Number: "123456"}})
	if rep.Code != "auth.continue" || rep.Need != "pin" || rep.Message == "" {
		t.Fatalf("got %+v", rep)
	}
}

func TestBadgeSuspendedDoesNotGuessAnAccount(t *testing.T) {
	acc := &fakeAccounts{}
	v := &fakeVerifier{resp: &core.VerifyResponse{Decision: "DENY", Reason: []core.Reason{{Code: "principal.suspended"}}, Message: "Suspended."}}
	rep := (&Broker{Verifier: v, Accounts: acc}).Handle(context.Background(), pipeproto.Request{Op: "logon", Badge: &pipeproto.Badge{Number: "123456"}})
	if rep.Code != "principal.suspended" || rep.Message != "Suspended." || len(acc.disabled) != 0 {
		t.Fatalf("got %+v %+v", rep, acc)
	}
}

var _ localuser.Manager = (*fakeAccounts)(nil)

// ---- sign-in hook (SPEC-scripts) --------------------------------------------

type hookCalls struct {
	mu    sync.Mutex
	calls [][3]string
	done  chan struct{}
}

func (h *hookCalls) fn(identifier, principalID, localAccount string) {
	h.mu.Lock()
	h.calls = append(h.calls, [3]string{identifier, principalID, localAccount})
	h.mu.Unlock()
	h.done <- struct{}{}
}

func (h *hookCalls) wait(t *testing.T) [3]string {
	t.Helper()
	select {
	case <-h.done:
	case <-time.After(2 * time.Second):
		t.Fatal("hook not called")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls[len(h.calls)-1]
}

func TestOnLogonHookAfterAllow(t *testing.T) {
	h := &hookCalls{done: make(chan struct{}, 1)}
	v := &fakeVerifier{resp: &core.VerifyResponse{Decision: "ALLOW", Principal: &core.Principal{ID: "usr_9", Username: "Dan.Evans"}}}
	b := &Broker{Verifier: v, Accounts: &fakeAccounts{}, OnLogon: h.fn}
	rep := b.Handle(context.Background(), pipeproto.Request{Op: "logon", Identifier: "dan@rostor.org", Secret: "p"})
	if !rep.OK || rep.LocalUser != "dan.evans" {
		t.Fatalf("got %+v", rep)
	}
	if got := h.wait(t); got != [3]string{"dan@rostor.org", "usr_9", "dan.evans"} {
		t.Fatalf("hook args: %v", got)
	}
	// A badge presents no identifier: the principal's username stands in.
	rep = b.Handle(context.Background(), pipeproto.Request{Op: "logon", Badge: &pipeproto.Badge{Number: "123456"}})
	if !rep.OK {
		t.Fatalf("got %+v", rep)
	}
	if got := h.wait(t); got != [3]string{"Dan.Evans", "usr_9", "dan.evans"} {
		t.Fatalf("badge hook args: %v", got)
	}
}

func TestOnLogonHookNotCalledOnDenyOrFailure(t *testing.T) {
	h := &hookCalls{done: make(chan struct{}, 8)}
	deny := &fakeVerifier{resp: &core.VerifyResponse{Decision: "DENY", Reason: []core.Reason{{Code: "auth.failed"}}}}
	(&Broker{Verifier: deny, Accounts: &fakeAccounts{}, OnLogon: h.fn}).Handle(context.Background(), pipeproto.Request{Op: "logon", Identifier: "dan"})
	cont := &fakeVerifier{resp: &core.VerifyResponse{Decision: core.DecisionContinue, Reason: []core.Reason{{Code: core.CodeContinue}}}}
	(&Broker{Verifier: cont, Accounts: &fakeAccounts{}, OnLogon: h.fn}).Handle(context.Background(), pipeproto.Request{Op: "logon", Badge: &pipeproto.Badge{Number: "123456"}})
	allow := &fakeVerifier{resp: &core.VerifyResponse{Decision: "ALLOW", Principal: &core.Principal{ID: "u", Username: "dan"}}}
	(&Broker{Verifier: allow, Accounts: &fakeAccounts{failWith: errors.New("boom")}, OnLogon: h.fn}).Handle(context.Background(), pipeproto.Request{Op: "logon", Identifier: "dan"})
	// The hook is asynchronous; give a wrongly scheduled call time to land.
	select {
	case <-h.done:
		t.Fatalf("hook called: %v", h.calls)
	case <-time.After(50 * time.Millisecond):
	}
	// No hook set: ALLOW still works.
	rep := (&Broker{Verifier: allow, Accounts: &fakeAccounts{}}).Handle(context.Background(), pipeproto.Request{Op: "logon", Identifier: "dan"})
	if !rep.OK {
		t.Fatalf("nil hook: %+v", rep)
	}
}

// ---- lock-screen default tile (v0.13.0) -------------------------------------

func TestUIDefaultProvider(t *testing.T) {
	b := &Broker{}
	ui := func() pipeproto.Reply {
		t.Helper()
		rep := b.Handle(context.Background(), pipeproto.Request{Op: "ui"})
		if !rep.OK {
			t.Fatalf("bad ui reply: %+v", rep)
		}
		return rep
	}
	// No policy yet: the Rostor tile is the default.
	if rep := ui(); rep.DefaultProvider != "rostor" {
		t.Fatalf("no policy: %+v", rep)
	}
	var pol core.PolicyResponse
	pol.Login.DefaultMethod = core.DefaultMethodPassword
	b.SetPolicy(pol) // core sent no logon block: still rostor
	if rep := ui(); rep.DefaultProvider != "rostor" {
		t.Fatalf("empty: %+v", rep)
	}
	pol.Logon.DefaultProvider = core.DefaultProviderWindows
	b.SetPolicy(pol)
	if rep := ui(); rep.DefaultProvider != "windows" {
		t.Fatalf("windows: %+v", rep)
	}
	pol.Logon.DefaultProvider = core.DefaultProviderRostor
	b.SetPolicy(pol)
	if rep := ui(); rep.DefaultProvider != "rostor" {
		t.Fatalf("rostor: %+v", rep)
	}
	// A value this deputy does not know is never forwarded to the credprov.
	pol.Logon.DefaultProvider = "macos"
	b.SetPolicy(pol)
	if rep := ui(); rep.DefaultProvider != "rostor" {
		t.Fatalf("unknown: %+v", rep)
	}
	// It never appears on a logon reply.
	rep := (&Broker{Verifier: core.Mock{AllowIdentifier: "testuser"}, Accounts: &fakeAccounts{}}).Handle(
		context.Background(), pipeproto.Request{Op: "logon", Identifier: "testuser", Secret: "x"})
	if !rep.OK || rep.DefaultProvider != "" {
		t.Fatalf("logon reply: %+v", rep)
	}
}

// ---- shared session account (v0.13.0) ---------------------------------------

func TestSharedSessionAccountUsedWhenPresent(t *testing.T) {
	acc := &fakeAccounts{}
	h := &hookCalls{done: make(chan struct{}, 1)}
	v := &fakeVerifier{resp: &core.VerifyResponse{Decision: "ALLOW", SessionAccount: "ChattLab",
		Principal: &core.Principal{ID: "usr_9", Username: "Dan.Evans", DisplayName: "Dan Evans"}}}
	b := &Broker{Verifier: v, Accounts: acc, OnLogon: h.fn}
	rep := b.Handle(context.Background(), pipeproto.Request{Op: "logon", Identifier: "dan", Secret: "p"})
	if !rep.OK || rep.LocalUser != "chattlab" || len(rep.LocalSecret) != 32 {
		t.Fatalf("got %+v", rep)
	}
	// Only the shared account is touched, never the person's derived one,
	// and its display name is its own name.
	if len(acc.enabled) != 1 || acc.enabled[0] != "chattlab" || acc.names[0] != "chattlab" {
		t.Fatalf("accounts: %+v", acc)
	}
	// The sign-in hook still names the person, with the shared account as the local one.
	if got := h.wait(t); got != [3]string{"dan", "usr_9", "chattlab"} {
		t.Fatalf("hook args: %v", got)
	}
	// Same on the badge path.
	rep = b.Handle(context.Background(), pipeproto.Request{Op: "logon", Badge: &pipeproto.Badge{Number: "123456"}})
	if !rep.OK || rep.LocalUser != "chattlab" {
		t.Fatalf("badge: got %+v", rep)
	}
	if got := h.wait(t); got != [3]string{"Dan.Evans", "usr_9", "chattlab"} {
		t.Fatalf("badge hook args: %v", got)
	}
}

func TestDerivedAccountWhenNoSessionAccount(t *testing.T) {
	acc := &fakeAccounts{}
	v := &fakeVerifier{resp: &core.VerifyResponse{Decision: "ALLOW",
		Principal: &core.Principal{ID: "usr_9", Username: "Dan.Evans", DisplayName: "Dan Evans"}}}
	rep := (&Broker{Verifier: v, Accounts: acc}).Handle(context.Background(), pipeproto.Request{Op: "logon", Identifier: "dan", Secret: "p"})
	if !rep.OK || rep.LocalUser != "dan.evans" {
		t.Fatalf("got %+v", rep)
	}
	if len(acc.enabled) != 1 || acc.enabled[0] != "dan.evans" || acc.names[0] != "Dan Evans" {
		t.Fatalf("accounts: %+v", acc)
	}
}

func TestUnusableSessionAccountFailsCleanly(t *testing.T) {
	for _, bad := range []string{"chatt lab", "a-name-that-is-far-too-long-for-sam", "kiosk/1"} {
		acc := &fakeAccounts{}
		v := &fakeVerifier{resp: &core.VerifyResponse{Decision: "ALLOW", SessionAccount: bad,
			Principal: &core.Principal{ID: "usr_9", Username: "dan"}}}
		rep := (&Broker{Verifier: v, Accounts: acc}).Handle(context.Background(), pipeproto.Request{Op: "logon", Identifier: "dan", Secret: "p"})
		if rep.OK || rep.Code != "deputy.local_account_failed" || rep.Message == "" || rep.LocalSecret != "" {
			t.Fatalf("%q: got %+v", bad, rep)
		}
		// Neither the shared name nor the person's derived account is touched.
		if len(acc.enabled)+len(acc.disabled) != 0 {
			t.Fatalf("%q: accounts touched: %+v", bad, acc)
		}
	}
}

// blockingVerifier holds every Verify until release is closed, so a test
// can observe a logon that is in flight.
type blockingVerifier struct {
	entered chan struct{}
	release chan struct{}
}

func (v *blockingVerifier) Verify(_ context.Context, _ core.VerifyRequest) (*core.VerifyResponse, error) {
	v.entered <- struct{}{}
	<-v.release
	return &core.VerifyResponse{Decision: core.DecisionDeny, Reason: []core.Reason{{Code: "auth.failed"}}}, nil
}

func TestInFlightCountsLogons(t *testing.T) {
	v := &blockingVerifier{entered: make(chan struct{}), release: make(chan struct{})}
	b := &Broker{Verifier: v, Accounts: &fakeAccounts{}}
	if b.InFlight() != 0 {
		t.Fatalf("idle: %d", b.InFlight())
	}
	// ui requests are not logons and are not counted.
	b.Handle(context.Background(), pipeproto.Request{Op: "ui"})
	if b.InFlight() != 0 {
		t.Fatalf("after ui: %d", b.InFlight())
	}
	const n = 3
	done := make(chan pipeproto.Reply, n)
	for i := 0; i < n; i++ {
		go func() {
			done <- b.Handle(context.Background(), pipeproto.Request{Op: "logon", Identifier: "dan", Secret: "x"})
		}()
	}
	for i := 0; i < n; i++ {
		<-v.entered
	}
	if got := b.InFlight(); got != n {
		t.Fatalf("with %d logons blocked in core: InFlight %d", n, got)
	}
	close(v.release)
	for i := 0; i < n; i++ {
		if rep := <-done; rep.OK {
			t.Fatalf("unexpected ALLOW: %+v", rep)
		}
	}
	if got := b.InFlight(); got != 0 {
		t.Fatalf("after the replies: %d", got)
	}
}
