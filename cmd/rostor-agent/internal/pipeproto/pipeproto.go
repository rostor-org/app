// Package pipeproto defines the newline-framed JSON messages exchanged over
// \\.\pipe\rostor-agent (contract §2). It is shared by the server and the
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

// Request is the client→agent message. Fields not relevant to an op are empty.
type Request struct {
	Op         string `json:"op"`
	Locale     string `json:"locale,omitempty"`
	Identifier string `json:"identifier,omitempty"`
	Secret     string `json:"secret,omitempty"`
}

// UIStrings are the display strings the credential provider renders (§2.1).
type UIStrings struct {
	TileLabel     string `json:"tile_label"`
	UsernameLabel string `json:"username_label"`
	PasswordLabel string `json:"password_label"`
	SubmitLabel   string `json:"submit_label"`
	Connecting    string `json:"connecting"`
}

// Reply is the agent→client message. Exactly one of the three shapes in the
// contract is populated; the omitempty tags keep the wire shape identical to
// the contract examples.
type Reply struct {
	OK          bool       `json:"ok"`
	Strings     *UIStrings `json:"strings,omitempty"`
	LocalUser   string     `json:"local_user,omitempty"`
	LocalSecret string     `json:"local_secret,omitempty"`
	Code        string     `json:"code,omitempty"`
	Message     string     `json:"message,omitempty"`
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
