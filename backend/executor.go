package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// SessionExecutor manages a running msfconsole instance for a session.
// The outputChan, done, and conn map are allocated once and live for the
// lifetime of the executor.  When msfconsole crashes, spawnProcess is called
// again: new pipes and goroutines are wired up to the SAME channels so every
// WebSocket subscriber and the broadcaster stay connected transparently.
type SessionExecutor struct {
	SessionID    int
	TargetHost   string
	sudoPassword string // empty means launch without sudo

	// Process state — replaced on each restart; guarded by mutex.
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	stderr io.ReadCloser
	mutex  sync.RWMutex

	running   bool
	restartMu sync.Mutex // ensures only one restart runs at a time

	// Lifetime channels — never closed except by Close().
	outputChan chan string
	done       chan bool

	// Ready signal for the initial startup wait.
	readyChan chan struct{}
	readyOnce sync.Once

	// Fan-out: each connected WebSocket gets its own subscriber channel.
	connMu     sync.RWMutex
	conns      map[int]chan string
	nextConnID int

	// Last credentials set via "set USERNAME/PASSWORD" — captured for loot on session open.
	credMu       sync.Mutex
	lastUsername string
	lastPassword string
}

// GlobalExecutors maps session IDs to their executors.
var (
	executors   = make(map[int]*SessionExecutor)
	execMutex   sync.RWMutex
	startingMap sync.Map // key: sessionID (int) → chan struct{}, signals startup complete
)

// StartSession allocates a new executor and starts msfconsole for the first time.
func StartSession(sessionID int, targetHost string, sudoPassword string) (*SessionExecutor, error) {
	executor := &SessionExecutor{
		SessionID:    sessionID,
		TargetHost:   targetHost,
		sudoPassword: sudoPassword,
		outputChan: make(chan string, 200),
		done:       make(chan bool, 1),
		readyChan:  make(chan struct{}),
		conns:      make(map[int]chan string),
	}

	// Start broadcaster before the first process so no output is lost.
	go executor.broadcast()

	if err := executor.spawnProcess(true); err != nil {
		close(executor.outputChan) // shut broadcaster down
		return nil, err
	}

	return executor, nil
}

// msfEnv returns the filtered environment for msfconsole.
func msfEnv() []string {
	var env []string
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "DATABASE_URL=") {
			env = append(env, e)
		}
	}
	return append(env, "RUBYOPT=-W0")
}

// spawnProcess starts a new msfconsole process and wires it to the executor.
// If initial is true it also waits for the ready signal and records the pid.
func (e *SessionExecutor) spawnProcess(initial bool) error {
	msfPath := os.Getenv("MSFCONSOLE_PATH")
	if msfPath == "" {
		msfPath = "msfconsole"
	}

	var cmd *exec.Cmd
	if e.sudoPassword != "" {
		fmt.Printf("[Executor] Session %d: launching msfconsole as root (%s)\n", e.SessionID, msfPath)
		cmd = exec.Command("sudo", "-S", msfPath, "-q")
	} else {
		fmt.Printf("[Executor] Session %d: launching msfconsole (%s)\n", e.SessionID, msfPath)
		cmd = exec.Command(msfPath, "-q")
	}
	cmd.Env = msfEnv()

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start: %w", err)
	}

	// Feed the sudo password as the very first stdin line so sudo -S can consume it.
	// After sudo validates, remaining stdin reads go directly to msfconsole.
	if e.sudoPassword != "" {
		io.WriteString(stdin, e.sudoPassword+"\n")
	}

	fmt.Printf("[Executor] Session %d: msfconsole PID %d\n", e.SessionID, cmd.Process.Pid)

	e.mutex.Lock()
	e.cmd = cmd
	e.stdin = stdin
	e.stdout = stdout
	e.stderr = stderr
	e.running = true
	if !initial {
		// Reset ready signal for the restart path.
		e.readyChan = make(chan struct{})
		e.readyOnce = sync.Once{}
	}
	e.mutex.Unlock()

	// Wire up readers to the shared outputChan.
	go e.readOutput(stdout, false)
	go e.readOutput(stderr, true)

	// Watch for process exit; restart transparently on unexpected exit.
	go func(c *exec.Cmd) {
		exitErr := c.Wait()

		e.mutex.Lock()
		stillThis := e.cmd == c // guard against a concurrent restart already in progress
		if stillThis {
			e.running = false
		}
		e.mutex.Unlock()

		if !stillThis {
			return
		}

		fmt.Printf("[Executor] Session %d: msfconsole exited (%v) — attempting restart\n", e.SessionID, exitErr)
		e.outputChan <- "[!] msfconsole crashed — restarting automatically…"

		// Restart with a small back-off; give up after 3 attempts.
		restarted := false
		for attempt := 1; attempt <= 3; attempt++ {
			time.Sleep(time.Duration(attempt) * 2 * time.Second)

			e.restartMu.Lock()
			err := e.spawnProcess(false)
			e.restartMu.Unlock()

			if err == nil {
				e.outputChan <- "[*] msfconsole restarted — you may re-run your commands"
				restarted = true
				break
			}
			fmt.Printf("[Executor] Session %d: restart attempt %d failed: %v\n", e.SessionID, attempt, err)
			e.outputChan <- fmt.Sprintf("[!] Restart attempt %d failed: %v", attempt, err)
		}

		if !restarted {
			// All restarts failed — shut down cleanly so WebSocket reconnects to a fresh session.
			e.outputChan <- "[!] Could not restart msfconsole. Reload the page to start a new session."
			close(e.outputChan)
			e.done <- true
			execMutex.Lock()
			delete(executors, e.SessionID)
			execMutex.Unlock()
		}
	}(cmd)

	// On initial startup: wait for first output activity, then settle.
	if initial {
		select {
		case <-e.readyChan:
			fmt.Printf("[Executor] Session %d: activity detected, settling 300 ms\n", e.SessionID)
			time.Sleep(300 * time.Millisecond)
		case <-time.After(30 * time.Second):
			fmt.Printf("[Executor] Session %d: timed out waiting for activity\n", e.SessionID)
		}

		if !e.running {
			return fmt.Errorf("msfconsole exited prematurely")
		}
		fmt.Printf("[Executor] Session %d: ready for commands\n", e.SessionID)
	}

	return nil
}

// readOutput reads from stdout/stderr and sends lines to outputChan.
func (e *SessionExecutor) readOutput(reader io.ReadCloser, isStderr bool) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()

		// Signal ready on first line from either stream.
		e.readyOnce.Do(func() { close(e.readyChan) })

		if isStderr {
			if shouldSkipError(line) {
				continue
			}
			e.outputChan <- fmt.Sprintf("[ERROR] %s", line)
		} else {
			if strings.TrimSpace(line) != "" {
				e.outputChan <- line
			}
		}
	}
	if err := scanner.Err(); err != nil {
		// Don't log EOF — that's normal on process exit.
		if !strings.Contains(err.Error(), "file already closed") {
			e.outputChan <- fmt.Sprintf("[!] Read error: %v", err)
		}
	}
}

// shouldSkipError returns true for known non-fatal stderr noise.
func shouldSkipError(line string) bool {
	skipPatterns := []string{
		"stty: 'standard input': Inappropriate ioctl for device",
		"stty:",
		"URI::InvalidURIError",
		"from /usr/share/metasploit-framework",
		"vendor/bundle/ruby",
		"gems/uri-",
		"Invalid argument",
		"bundled_gems.rb",
		"in `require'",
		"in `block",
		"in `replace_require'",
		"/usr/lib/ruby/",
		"/usr/bin/msfconsole",
		"<main>",
		"from /",
		"warning",
		"Warning",
		"deprecated",
	}
	for _, p := range skipPatterns {
		if strings.Contains(line, p) {
			return true
		}
	}
	return false
}

// ExecuteCommand sends a command to msfconsole's stdin.
// It also tracks the last USERNAME/PASSWORD set so they can be saved to loot
// when a new MSF session is opened.
func (e *SessionExecutor) ExecuteCommand(cmd string) error {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	if !e.running {
		return fmt.Errorf("session not running")
	}

	// Track credentials set via "set <key> <value>" (case-insensitive key).
	trimmed := strings.TrimSpace(cmd)
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "set ") {
		parts := strings.Fields(trimmed)
		if len(parts) >= 3 {
			key := strings.ToLower(parts[1])
			val := parts[2]
			e.credMu.Lock()
			switch key {
			case "username", "user", "smbuser", "ftpuser", "db_user", "username_file":
				e.lastUsername = val
			case "password", "pass", "smbpass", "ftppass", "db_pass", "password_file":
				e.lastPassword = val
			}
			e.credMu.Unlock()
		}
	}

	if !strings.HasSuffix(cmd, "\n") {
		cmd += "\n"
	}
	_, err := io.WriteString(e.stdin, cmd)
	if err != nil {
		return fmt.Errorf("failed to write command: %w", err)
	}
	return nil
}

// LastCredentials returns the most recently set username and password.
func (e *SessionExecutor) LastCredentials() (username, password string) {
	e.credMu.Lock()
	defer e.credMu.Unlock()
	return e.lastUsername, e.lastPassword
}

// broadcast fans out outputChan to every registered subscriber channel.
// Runs for the lifetime of the executor; exits only when outputChan is closed.
func (e *SessionExecutor) broadcast() {
	for output := range e.outputChan {
		e.connMu.RLock()
		for _, ch := range e.conns {
			select {
			case ch <- output:
			default: // slow consumer — drop rather than block
			}
		}
		e.connMu.RUnlock()
	}
	// outputChan closed (terminal failure) — close all subscriber channels.
	e.connMu.Lock()
	for id, ch := range e.conns {
		close(ch)
		delete(e.conns, id)
	}
	e.connMu.Unlock()
}

// Subscribe registers a new WebSocket connection.
func (e *SessionExecutor) Subscribe() (int, <-chan string) {
	e.connMu.Lock()
	defer e.connMu.Unlock()

	id := e.nextConnID
	e.nextConnID++
	ch := make(chan string, 100)

	e.mutex.RLock()
	running := e.running
	e.mutex.RUnlock()

	if !running {
		close(ch)
		return id, ch
	}

	e.conns[id] = ch
	return id, ch
}

// Unsubscribe removes a subscriber and closes its channel.
func (e *SessionExecutor) Unsubscribe(id int) {
	e.connMu.Lock()
	defer e.connMu.Unlock()
	if ch, ok := e.conns[id]; ok {
		close(ch)
		delete(e.conns, id)
	}
}

// Close terminates the msfconsole session permanently.
func (e *SessionExecutor) Close() error {
	e.mutex.Lock()
	if !e.running {
		e.mutex.Unlock()
		return nil
	}
	e.running = false
	stdin := e.stdin
	cmd := e.cmd
	e.mutex.Unlock()

	io.WriteString(stdin, "exit\n")
	stdin.Close()
	time.Sleep(500 * time.Millisecond)
	if cmd.ProcessState == nil {
		cmd.Process.Kill()
	}

	execMutex.Lock()
	delete(executors, e.SessionID)
	execMutex.Unlock()

	return nil
}

// GetExecutor retrieves an executor for a session ID.
func GetExecutor(sessionID int) *SessionExecutor {
	execMutex.RLock()
	defer execMutex.RUnlock()
	return executors[sessionID]
}

// CloseExecutor closes and removes an executor.
func CloseExecutor(sessionID int) error {
	execMutex.Lock()
	executor, exists := executors[sessionID]
	execMutex.Unlock()
	if !exists {
		return nil
	}
	return executor.Close()
}
