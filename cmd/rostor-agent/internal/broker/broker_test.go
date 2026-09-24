package broker

import (
	"context"
	"errors"
	"testing"

	"rostor.org/app/cmd/rostor-agent/internal/core"
	"rostor.org/app/cmd/rostor-agent/internal/localuser"
	"rostor.org/app/cmd/rostor-agent/internal/pipeproto"
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

func TestUnknownOp(t *testing.T) {
	rep := (&Broker{}).Handle(context.Background(), pipeproto.Request{Op: "nope"})
	if rep.OK || rep.Code != "agent.bad_request" || rep.Message == "" {
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
	if rep.OK || rep.Code != "agent.not_enrolled" {
		t.Fatalf("got %+v", rep)
	}
}

func TestLogonCoreUnreachable(t *testing.T) {
	v := &fakeVerifier{err: core.ErrUnreachable}
	rep := (&Broker{Verifier: v, Accounts: &fakeAccounts{}}).Handle(context.Background(), pipeproto.Request{Op: "logon", Identifier: "dan", Secret: "p"})
	if rep.OK || rep.Code != "agent.core_unreachable" || rep.Message == "" {
		t.Fatalf("got %+v", rep)
	}
	if v.got.Credential.Type != "password" || v.got.Action != "logon" || v.got.Locale != "en-US" {
		t.Fatalf("request shape: %+v", v.got)
	}
}

func TestLogonTimeout(t *testing.T) {
	v := &fakeVerifier{err: context.DeadlineExceeded}
	rep := (&Broker{Verifier: v, Accounts: &fakeAccounts{}}).Handle(context.Background(), pipeproto.Request{Op: "logon", Identifier: "dan"})
	if rep.Code != "agent.timeout" {
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
	if rep.OK || rep.Code != "agent.local_account_failed" || len(acc.enabled) != 0 {
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
	if rep.OK || rep.Code != "agent.local_account_failed" {
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
