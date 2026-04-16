package main

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// sudoPassStore holds the validated local system password for each user (userID → password).
// It is never persisted to disk; the user must supply it at registration and login.
var sudoPassStore sync.Map // int → string

// SetSudoPassword stores the plaintext sudo password for a user in memory.
func SetSudoPassword(userID int, password string) {
	sudoPassStore.Store(userID, password)
}

// GetSudoPassword retrieves the stored sudo password for a user.
// Returns ("", false) if no password has been set for this session.
func GetSudoPassword(userID int) (string, bool) {
	v, ok := sudoPassStore.Load(userID)
	if !ok {
		return "", false
	}
	return v.(string), true
}

// ValidateSudoPassword tests whether the supplied password can authenticate sudo
// on the local system by running `sudo -S -v` (update timestamp, don't run anything).
func ValidateSudoPassword(password string) error {
	cmd := exec.Command("sudo", "-S", "-v")
	cmd.Stdin = strings.NewReader(password + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("sudo authentication failed: %s", msg)
	}
	return nil
}

// sudoRun executes a command via `sudo -S`, piping the stored password for userID.
// name is the executable (e.g. "airmon-ng") and args are its arguments.
// Returns combined stdout+stderr output and any error.
func sudoRun(userID int, name string, args ...string) ([]byte, error) {
	pass, ok := GetSudoPassword(userID)
	if !ok {
		return nil, fmt.Errorf("no sudo password stored — please log in again")
	}
	fullArgs := append([]string{"-S", name}, args...)
	cmd := exec.Command("sudo", fullArgs...)
	cmd.Stdin = strings.NewReader(pass + "\n")
	return cmd.CombinedOutput()
}

// sudoCmd returns a pre-configured *exec.Cmd for `sudo -S <name> <args...>` with
// the stored password wired to Stdin.  The caller must not set Stdin after this.
// Returns nil and an error if no password is stored.
func sudoCmd(userID int, name string, args ...string) (*exec.Cmd, error) {
	pass, ok := GetSudoPassword(userID)
	if !ok {
		return nil, fmt.Errorf("no sudo password stored — please log in again")
	}
	fullArgs := append([]string{"-S", name}, args...)
	cmd := exec.Command("sudo", fullArgs...)
	cmd.Stdin = strings.NewReader(pass + "\n")
	return cmd, nil
}
