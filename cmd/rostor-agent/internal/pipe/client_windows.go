//go:build windows

package pipe

import (
	"bufio"
	"time"

	"github.com/Microsoft/go-winio"

	"rostor.org/app/cmd/rostor-agent/internal/pipeproto"
)

// Call performs one request/reply exchange the way the credential provider
// does, so `pipe-test` exercises the same path.
func Call(path string, req pipeproto.Request, timeout time.Duration) (pipeproto.Reply, error) {
	conn, err := winio.DialPipe(path, &timeout)
	if err != nil {
		return pipeproto.Reply{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := pipeproto.Write(conn, req); err != nil {
		return pipeproto.Reply{}, err
	}
	return pipeproto.ReadReply(bufio.NewReader(conn))
}
