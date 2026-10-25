package update

import (
	"errors"
	"os"
	"os/exec"
	"os/signal"
)

// Restart runs the freshly installed program in the same console and exits
// with its code. Windows has no exec, so this process waits; Ctrl+C reaches
// both, and only the child acts on it.
func Restart(exe string) error {
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	signal.Ignore(os.Interrupt)
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		os.Exit(exit.ExitCode())
	}
	if err != nil {
		return err
	}
	os.Exit(0)
	return nil
}
