package main

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// authenticateLinuxUser verifies username+password against the system PAM stack.
// Uses python3-pam when available; falls back to sudo -S -v otherwise.
func authenticateLinuxUser(username, password string) error {
	if err := exec.Command("id", username).Run(); err != nil {
		return fmt.Errorf("user '%s' not found on this system", username)
	}

	// Try PAM via python3-pam. Exit codes: 0=ok, 2=wrong password, 99=module absent.
	const pamScript = `import sys
try:
    import pam
    p = pam.pam()
    sys.exit(0 if p.authenticate(sys.argv[1], sys.argv[2]) else 2)
except ImportError:
    sys.exit(99)
`
	cmd := exec.Command("python3", "-c", pamScript, username, password)
	err := cmd.Run()
	if err == nil {
		return nil
	}

	if exitErr, ok := err.(*exec.ExitError); ok {
		if exitErr.ExitCode() != 99 {
			// Exit code 2 (or any non-99): wrong password
			return fmt.Errorf("authentication failed: invalid credentials")
		}
		// Exit code 99: python3-pam not installed — fall through to sudo fallback
	}
	// python3 not found or python3-pam absent: fall back to sudo -S -v
	return ValidateSudoPassword(password)
}

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
