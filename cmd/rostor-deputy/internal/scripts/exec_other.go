//go:build !windows

package scripts

import (
	"context"
	"fmt"
	"io"
)

// platformExecutor on non-Windows hosts never runs anything: the deputy is a
// Windows service and tests inject their own executor.
func platformExecutor(_ context.Context, _ string, _ []string, _ io.Writer) (int, error) {
	return -1, fmt.Errorf("%w: powershell is only run on windows", ErrStart)
}
