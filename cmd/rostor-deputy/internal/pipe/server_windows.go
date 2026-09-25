//go:build windows

// Package pipe is the named-pipe transport for contract §2. The server accepts
// one request per connection, answers it and closes, which matches the
// credential provider's CreateFile/WriteFile/ReadFile/CloseHandle cycle.
package pipe

import (
	"bufio"
	"context"
	"errors"
	"log"
	"net"
	"time"

	"github.com/Microsoft/go-winio"

	"rostor.org/app/cmd/rostor-deputy/internal/pipeproto"
)

// SDDL: full access for SYSTEM and Administrators, nothing for anyone else.
// LogonUI (the credprov host) runs as SYSTEM; pipe-test runs as an elevated
// administrator. The P flag stops inherited ACEs from widening it.
const sddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"

// Handler is what the broker exposes.
type Handler interface {
	Handle(ctx context.Context, req pipeproto.Request) pipeproto.Reply
}

// Server owns the listener.
type Server struct {
	Path    string
	Handler Handler
	Logger  *log.Logger

	// PerRequest bounds a whole exchange. Must stay under the credprov's
	// 10 s so the deputy, not the credprov, produces the timeout text.
	PerRequest time.Duration

	ln net.Listener
}

// Listen creates the pipe. It fails if another deputy already owns it.
func (s *Server) Listen() error {
	if s.PerRequest == 0 {
		s.PerRequest = 9 * time.Second
	}
	ln, err := winio.ListenPipe(s.Path, &winio.PipeConfig{SecurityDescriptor: sddl})
	if err != nil {
		return err
	}
	s.ln = ln
	return nil
}

// Serve accepts until Close.
func (s *Server) Serve() error {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if errors.Is(err, winio.ErrPipeListenerClosed) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.logf("accept: %v", err)
			continue
		}
		go s.serveConn(conn)
	}
}

// Close stops accepting.
func (s *Server) Close() error {
	if s.ln == nil {
		return nil
	}
	return s.ln.Close()
}

func (s *Server) serveConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(s.PerRequest))
	ctx, cancel := context.WithTimeout(context.Background(), s.PerRequest)
	defer cancel()

	req, err := pipeproto.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		s.logf("bad request: %v", err)
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_ = pipeproto.Write(conn, pipeproto.Reply{OK: false, Code: "deputy.bad_request"})
		return
	}
	started := time.Now()
	rep := s.Handler.Handle(ctx, req)
	if took := time.Since(started); took > 2*time.Second {
		s.logf("%s took %s", req.Op, took.Round(time.Millisecond))
	}
	// The write gets its own short deadline: local account calls are not
	// cancellable, and if they ran long the client may still be waiting.
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if err := pipeproto.Write(conn, rep); err != nil {
		s.logf("write reply for %s: %v", req.Op, err)
	}
}

func (s *Server) logf(format string, args ...any) {
	if s.Logger != nil {
		s.Logger.Printf(format, args...)
	}
}
