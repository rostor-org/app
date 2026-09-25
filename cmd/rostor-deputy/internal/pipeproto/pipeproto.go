// Package pipeproto defines the newline-framed JSON messages exchanged over
// \\.\pipe\rostor-deputy (contract §2). It is shared by the server and the
// pipe-test client and has no Windows dependencies so it can be tested anywhere.
package pipeproto

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MaxLine bounds a single framed message. Requests carry a username and a
// secret; nothing legitimate approaches this size, so anything larger is a
// misbehaving client rather than a real request.
const MaxLine = 64 * 1024

// Request is the client→deputy message. Fields not relevant to an op are empty.
// A logon carries either identifier+secret (password path) or badge (§2.3).
type Request struct {
	Op         string `json:"op"`
	Locale     string `json:"locale,omitempty"`
	Identifier string `json:"identifier,omitempty"`
	Secret     string `json:"secret,omitempty"`
	Badge      *Badge `json:"badge,omitempty"`
}

// Badge is a keyboard-wedge reader burst (the digits as typed) plus the PIN
// the person adds when the deputy answered auth.continue.
type Badge struct {
	Number string `json:"number"`
	PIN    string `json:"pin,omitempty"`
}

// UIStrings are the display strings the credential provider renders (§2.1).
type UIStrings struct {
	TileLabel     string `json:"tile_label"`
	UsernameLabel string `json:"username_label"`
	PasswordLabel string `json:"password_label"`
	SubmitLabel   string `json:"submit_label"`
	Connecting    string `json:"connecting"`
	PinLabel      string `json:"pin_label"`
	BadgeHint     string `json:"badge_hint"`
}

// Reply is the deputy→client message. Exactly one of the shapes in the
// contract is populated; the omitempty tags keep the wire shape identical to
// the contract examples. Need is set only with code auth.continue and names
// what the credential provider must collect next ("pin"). DefaultMethod
// accompanies Strings on a `ui` reply (§2.1, v0.11.0) and names the sign-in
// method the effective policy puts first ("password", "passkey", "badge").
type Reply struct {
	OK            bool       `json:"ok"`
	Strings       *UIStrings `json:"strings,omitempty"`
	DefaultMethod string     `json:"default_method,omitempty"`
	LocalUser     string     `json:"local_user,omitempty"`
	LocalSecret   string     `json:"local_secret,omitempty"`
	Code          string     `json:"code,omitempty"`
	Message       string     `json:"message,omitempty"`
	Need          string     `json:"need,omitempty"`
}

// ErrLineTooLong is returned when a frame exceeds MaxLine.
var ErrLineTooLong = errors.New("pipeproto: line too long")

// ReadRequest reads one newline-terminated JSON request.
func ReadRequest(r *bufio.Reader) (Request, error) {
	var req Request
	line, err := readLine(r)
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(line, &req); err != nil {
		return req, fmt.Errorf("pipeproto: bad request: %w", err)
	}
	if req.Op == "" {
		return req, errors.New("pipeproto: missing op")
	}
	return req, nil
}

// ReadReply reads one newline-terminated JSON reply.
func ReadReply(r *bufio.Reader) (Reply, error) {
	var rep Reply
	line, err := readLine(r)
	if err != nil {
		return rep, err
	}
	if err := json.Unmarshal(line, &rep); err != nil {
		return rep, fmt.Errorf("pipeproto: bad reply: %w", err)
	}
	return rep, nil
}

// Write marshals v as a single line. json.Marshal never emits a raw newline
// inside a string, so the frame boundary is unambiguous.
func Write(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}

func readLine(r *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		chunk, isPrefix, err := r.ReadLine()
		if err != nil {
			return nil, err
		}
		buf = append(buf, chunk...)
		if len(buf) > MaxLine {
			return nil, ErrLineTooLong
		}
		if !isPrefix {
			return buf, nil
		}
	}
}
