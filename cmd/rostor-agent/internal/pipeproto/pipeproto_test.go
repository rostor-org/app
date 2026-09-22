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
