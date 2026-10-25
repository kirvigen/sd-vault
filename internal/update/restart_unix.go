//go:build !windows

package update

import (
	"os"
	"syscall"
)

// Restart replaces the running process with the freshly installed program,
// keeping its arguments and terminal.
func Restart(exe string) error {
	return syscall.Exec(exe, os.Args, os.Environ())
}
