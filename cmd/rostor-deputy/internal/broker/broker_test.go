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
	disabled []string
	failWith error
}

func (f *fakeAccounts) EnsureEnabled(u, _ string) (string, error) {
	if f.failWith != nil {
		return "", f.failWith
	}
	f.enabled = append(f.enabled, u)
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
	// Only the tile and identifier labels change; the rest of the strings
	// (including badge_hint, which the tile shows on both) are untouched.
	badge := *rep.Strings
	badge.TileLabel, badge.UsernameLabel = password.TileLabel, password.UsernameLabel
	if badge != password {
		t.Fatalf("badge policy changed more than the two labels: %+v vs %+v", rep.Strings, password)
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
	// --mock-core hands the broker the mock's policy: password, no badges.
	b := &Broker{Verifier: core.Mock{AllowIdentifier: "testuser"}, Accounts: &fakeAccounts{}}
	pol, err := core.Mock{}.Policy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b.SetPolicy(*pol)
	rep := b.Handle(context.Background(), pipeproto.Request{Op: "ui"})
	if rep.DefaultMethod != "password" || rep.Strings.TileLabel != "Rostor" {
		t.Fatalf("got %+v %+v", rep.DefaultMethod, rep.Strings)
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
