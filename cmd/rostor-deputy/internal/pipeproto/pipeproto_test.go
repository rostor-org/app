package pipeproto

import (
	"bufio"
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestRoundTripRequest(t *testing.T) {
	var buf bytes.Buffer
	in := Request{Op: "logon", Identifier: "dan", Secret: "s3cret\nwith newline", Locale: "en-US"}
	if err := Write(&buf, in); err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(buf.Bytes(), []byte("\n")); n != 1 {
		t.Fatalf("frame has %d newlines, want 1", n)
	}
	out, err := ReadRequest(bufio.NewReader(&buf))
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("got %+v want %+v", out, in)
	}
}

func TestReplyWireShape(t *testing.T) {
	var buf bytes.Buffer
	_ = Write(&buf, Reply{OK: true, LocalUser: "dan", LocalSecret: "x"})
	if got, want := strings.TrimSpace(buf.String()), `{"ok":true,"local_user":"dan","local_secret":"x"}`; got != want {
		t.Fatalf("got %s want %s", got, want)
	}
	buf.Reset()
	_ = Write(&buf, Reply{OK: false, Code: "auth.failed", Message: "Sign-in failed."})
	if got, want := strings.TrimSpace(buf.String()), `{"ok":false,"code":"auth.failed","message":"Sign-in failed."}`; got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestBadgeRequestWireShape(t *testing.T) {
	var buf bytes.Buffer
	_ = Write(&buf, Request{Op: "logon", Badge: &Badge{Number: "1234567890"}, Locale: "en-US"})
	if got, want := strings.TrimSpace(buf.String()), `{"op":"logon","locale":"en-US","badge":{"number":"1234567890"}}`; got != want {
		t.Fatalf("got %s want %s", got, want)
	}
	// Exactly what the credprov sends in PIN mode.
	req, err := ReadRequest(bufio.NewReader(strings.NewReader(`{"op":"logon","badge":{"number":"5555555555","pin":"2468"},"locale":"en-US"}` + "\n")))
	if err != nil {
		t.Fatal(err)
	}
	if req.Badge == nil || req.Badge.Number != "5555555555" || req.Badge.PIN != "2468" || req.Identifier != "" {
		t.Fatalf("got %+v", req)
	}
	buf.Reset()
	_ = Write(&buf, Reply{OK: false, Code: "auth.continue", Message: "Enter your PIN.", Need: "pin"})
	if got, want := strings.TrimSpace(buf.String()), `{"ok":false,"code":"auth.continue","message":"Enter your PIN.","need":"pin"}`; got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestReadRequestRejectsMissingOp(t *testing.T) {
	_, err := ReadRequest(bufio.NewReader(strings.NewReader(`{"locale":"en"}` + "\n")))
	if err == nil {
		t.Fatal("expected error for missing op")
	}
}

func TestReadRequestTooLong(t *testing.T) {
	long := `{"op":"ui","locale":"` + strings.Repeat("a", MaxLine+10) + `"}` + "\n"
	_, err := ReadRequest(bufio.NewReader(strings.NewReader(long)))
	if !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("got %v want ErrLineTooLong", err)
	}
}

func TestUIReplyDefaultMethod(t *testing.T) {
	// A `ui` reply carries default_method beside strings (§2.1, v0.11.0).
	var buf bytes.Buffer
	in := Reply{OK: true, DefaultMethod: "badge", Strings: &UIStrings{TileLabel: "Tap your badge", UsernameLabel: "Badge, or username",
		PasswordLabel: "Password", SubmitLabel: "Sign in", Connecting: "Contacting Rostor…", PinLabel: "PIN", BadgeHint: "Tap your badge or type your username"}}
	if err := Write(&buf, in); err != nil {
		t.Fatal(err)
	}
	wire := strings.TrimSpace(buf.String())
	if !strings.Contains(wire, `"default_method":"badge"`) || !strings.Contains(wire, `"strings":{"tile_label":"Tap your badge","username_label":"Badge, or username"`) {
		t.Fatalf("wire: %s", wire)
	}
	out, err := ReadReply(bufio.NewReader(&buf))
	if err != nil {
		t.Fatal(err)
	}
	if out.DefaultMethod != "badge" || out.Strings == nil || *out.Strings != *in.Strings || !out.OK {
		t.Fatalf("got %+v", out)
	}
	// Every other reply shape stays exactly as before: no default_method key.
	for _, rep := range []Reply{
		{OK: true, LocalUser: "dan", LocalSecret: "x"},
		{OK: false, Code: "auth.failed", Message: "Sign-in failed."},
		{OK: false, Code: "auth.continue", Message: "Enter your PIN.", Need: "pin"},
	} {
		buf.Reset()
		_ = Write(&buf, rep)
		if strings.Contains(buf.String(), "default_method") {
			t.Fatalf("default_method leaked into %s", buf.String())
		}
	}
	// A pre-v0.11.0 deputy's reply (no default_method) still parses.
	old, err := ReadReply(bufio.NewReader(strings.NewReader(`{"ok":true,"strings":{"tile_label":"Rostor"}}` + "\n")))
	if err != nil || old.DefaultMethod != "" || old.Strings == nil || old.Strings.TileLabel != "Rostor" {
		t.Fatalf("got %+v %v", old, err)
	}
}

func TestUIReplyBadgeFirstStrings(t *testing.T) {
	// v0.13.0: heading, switch_to_username and switch_to_badge ride in
	// `strings`, after the seven original keys, and round-trip intact.
	var buf bytes.Buffer
	in := Reply{OK: true, DefaultMethod: "badge", Strings: &UIStrings{TileLabel: "Tap your badge", UsernameLabel: "Badge, or username",
		PasswordLabel: "Password", SubmitLabel: "Sign in", Connecting: "Contacting Rostor…", PinLabel: "PIN", BadgeHint: "Tap your badge or type your username",
		Heading: "Tap your badge · ChattLab", SwitchToUsername: "Use username", SwitchToBadge: "Use badge"}}
	if err := Write(&buf, in); err != nil {
		t.Fatal(err)
	}
	wire := strings.TrimSpace(buf.String())
	if !strings.Contains(wire, `"badge_hint":"Tap your badge or type your username","heading":"Tap your badge · ChattLab","switch_to_username":"Use username","switch_to_badge":"Use badge"}`) {
		t.Fatalf("wire: %s", wire)
	}
	out, err := ReadReply(bufio.NewReader(&buf))
	if err != nil {
		t.Fatal(err)
	}
	if out.Strings == nil || *out.Strings != *in.Strings {
		t.Fatalf("got %+v", out.Strings)
	}

	// Empty new strings are omitted, so a reply that does not carry them is
	// byte-for-byte the pre-v0.13.0 shape.
	buf.Reset()
	_ = Write(&buf, Reply{OK: true, DefaultMethod: "password", Strings: &UIStrings{TileLabel: "Rostor", UsernameLabel: "Username",
		PasswordLabel: "Password", SubmitLabel: "Sign in", Connecting: "Contacting Rostor…", PinLabel: "PIN", BadgeHint: "Tap your badge or type your username"}})
	if got, want := strings.TrimSpace(buf.String()), `{"ok":true,"strings":{"tile_label":"Rostor","username_label":"Username","password_label":"Password","submit_label":"Sign in","connecting":"Contacting Rostor…","pin_label":"PIN","badge_hint":"Tap your badge or type your username"},"default_method":"password"}`; got != want {
		t.Fatalf("got %s\nwant %s", got, want)
	}
	for _, k := range []string{"heading", "switch_to_username", "switch_to_badge"} {
		if strings.Contains(buf.String(), k) {
			t.Fatalf("%s leaked into %s", k, buf.String())
		}
	}

	// An older deputy's reply (no new strings) parses with them empty, which
	// is what tells the credential provider to keep its previous labels.
	old, err := ReadReply(bufio.NewReader(strings.NewReader(`{"ok":true,"strings":{"tile_label":"Rostor"},"default_method":"badge"}` + "\n")))
	if err != nil || old.Strings == nil || old.Strings.Heading != "" || old.Strings.SwitchToUsername != "" || old.Strings.SwitchToBadge != "" {
		t.Fatalf("got %+v %v", old, err)
	}
}

func TestUIReplyDefaultProvider(t *testing.T) {
	// "Which tile is the default" (v0.13.0): default_provider rides on the
	// `ui` reply beside default_method and nowhere else.
	var buf bytes.Buffer
	_ = Write(&buf, Reply{OK: true, DefaultMethod: "password", DefaultProvider: "windows", Strings: &UIStrings{TileLabel: "Rostor"}})
	if got, want := strings.TrimSpace(buf.String()), `{"ok":true,"strings":{"tile_label":"Rostor","username_label":"","password_label":"","submit_label":"","connecting":"","pin_label":"","badge_hint":""},"default_method":"password","default_provider":"windows"}`; got != want {
		t.Fatalf("got %s\nwant %s", got, want)
	}
	out, err := ReadReply(bufio.NewReader(&buf))
	if err != nil || out.DefaultProvider != "windows" {
		t.Fatalf("got %+v %v", out, err)
	}
	for _, rep := range []Reply{
		{OK: true, LocalUser: "dan", LocalSecret: "x"},
		{OK: false, Code: "auth.failed", Message: "Sign-in failed."},
		{OK: true, DefaultMethod: "password", Strings: &UIStrings{TileLabel: "Rostor"}},
	} {
		buf.Reset()
		_ = Write(&buf, rep)
		if strings.Contains(buf.String(), "default_provider") {
			t.Fatalf("default_provider leaked into %s", buf.String())
		}
	}
	// A pre-v0.13.0 reply parses with it empty; the credprov treats that as rostor.
	old, err := ReadReply(bufio.NewReader(strings.NewReader(`{"ok":true,"strings":{"tile_label":"Rostor"},"default_method":"badge"}` + "\n")))
	if err != nil || old.DefaultProvider != "" {
		t.Fatalf("got %+v %v", old, err)
	}
}
