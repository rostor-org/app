//go:build !windows

package update

import (
	"context"
	"errors"
)

// platformInstaller on non-Windows hosts never runs anything: the deputy is
// a Windows service and tests inject their own installer.
func platformInstaller(_ context.Context, _ string) error {
	return errors.New("the update installer only runs on windows")
}

func platformCleanup() {}
