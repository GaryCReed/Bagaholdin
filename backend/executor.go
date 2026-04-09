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

// SessionExecutor manages a running msfconsole instance for a session
type SessionExecutor struct {
	SessionID  int
	TargetHost string
	cmd        *exec.Cmd
	stdin      io.WriteCloser
	stdout     io.ReadCloser
	stderr     io.ReadCloser
	mutex      sync.RWMutex
	running    bool
	outputChan chan string
	done       chan bool
	readyChan  chan struct{}
	readyOnce  sync.Once

	// Fan-out: each connected WebSocket gets its own subscriber channel
	connMu     sync.RWMutex
	conns      map[int]chan string
	nextConnID int
}

// GlobalExecutors maps session IDs to their executors
var (
	executors    = make(map[int]*SessionExecutor)
	execMutex    sync.RWMutex
	startingMap  sync.Map // key: sessionID (int) → chan struct{}, signals startup complete
)

// StartSession initializes a new msfconsole session
func StartSession(sessionID int, targetHost string) (*SessionExecutor, error) {
	msfPath := os.Getenv("MSFCONSOLE_PATH")
	if msfPath == "" {
		msfPath = "msfconsole"
	}

	fmt.Printf("[Executor] Starting msfconsole from: %s\n", msfPath)

	cmd := exec.Command(msfPath, "-q")

	// Strip DATABASE_URL from the environment so it doesn't override
	// msfconsole's own ~/.msf4/database.yml connection settings.
	filteredEnv := []string{}
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "DATABASE_URL=") {
			filteredEnv = append(filteredEnv, e)
		}
	}
	// Suppress Ruby warnings
	cmd.Env = append(filteredEnv, "RUBYOPT=-W0")

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr: %w", err)
	}

	executor := &SessionExecutor{
		SessionID:  sessionID,
		TargetHost: targetHost,
		cmd:        cmd,
		stdin:      stdin,
		stdout:     stdout,
		stderr:     stderr,
		running:    false,
		outputChan: make(chan string, 100),
		done:       make(chan bool, 1),
		readyChan:  make(chan struct{}),
		conns:      make(map[int]chan string),
	}

	// Start the process
	if err := cmd.Start(); err != nil {
		fmt.Printf("[Executor] Failed to start msfconsole: %v\n", err)
		return nil, fmt.Errorf("failed to start msfconsole: %w", err)
	}

	fmt.Printf("[Executor] Session %d: msfconsole process started (PID: %d)\n", sessionID, cmd.Process.Pid)

	// Start output readers IMMEDIATELY before any delays
	go executor.readOutput(stdout, false)
	go executor.readOutput(stderr, true)

	executor.running = true

	// Monitor process exit
	go func() {
		err := cmd.Wait()
		executor.mutex.Lock()
		executor.running = false
		executor.mutex.Unlock()
		fmt.Printf("[Executor] Session %d process exited with status: %v\n", sessionID, err)
		if err != nil {
			executor.outputChan <- fmt.Sprintf("[!] Process exited with error: %v", err)
		} else {
			executor.outputChan <- "[*] Process exited successfully"
		}
		close(executor.outputChan)
		executor.done <- true
		// Remove from global map so the next WebSocket reconnect can spawn a fresh msfconsole.
		execMutex.Lock()
		delete(executors, sessionID)
		execMutex.Unlock()
	}()

	// Wait for the first output activity (msfconsole emits stderr Ruby init lines quickly),
	// then give it a short settle period. Falls back to a 30s timeout for slow machines.
	fmt.Printf("[Executor] Session %d: Waiting for msfconsole to become ready...\n", sessionID)
	select {
	case <-executor.readyChan:
		fmt.Printf("[Executor] Session %d: Activity detected, giving process 300ms to settle\n", sessionID)
		time.Sleep(300 * time.Millisecond)
	case <-time.After(30 * time.Second):
		fmt.Printf("[Executor] Session %d: Timed out waiting for activity\n", sessionID)
	}

	// Check if process is still running
	if !executor.running {
		fmt.Printf("[Executor] Session %d: Process exited prematurely!\n", sessionID)
		return nil, fmt.Errorf("msfconsole process exited prematurely")
	}

	fmt.Printf("[Executor] Session %d: Process ready for commands\n", sessionID)

	// Start broadcaster: fan out outputChan to all registered subscriber channels
	go executor.broadcast()

	return executor, nil
}

// readOutput reads from stdout/stderr and sends to output channel
func (e *SessionExecutor) readOutput(reader io.ReadCloser, isStderr bool) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()

		// Signal ready on first line from either stream (stderr Ruby init lines arrive fast)
		e.readyOnce.Do(func() { close(e.readyChan) })

		// Filter out non-fatal initialization errors from msfconsole
		if isStderr {
			// Skip known non-fatal errors
			if shouldSkipError(line) {
				continue
			}
			e.outputChan <- fmt.Sprintf("[ERROR] %s", line)
		} else {
			// Only send non-empty lines
			if strings.TrimSpace(line) != "" {
				e.outputChan <- line
			}
		}
	}
	if err := scanner.Err(); err != nil {
		e.outputChan <- fmt.Sprintf("[!] Read error: %v", err)
	}
}

// shouldSkipError determines if an stderr line is a non-fatal initialization error
func shouldSkipError(line string) bool {
	// Filter known non-fatal errors and Ruby initialization warnings
	skipPatterns := []string{
		// Terminal control errors (non-fatal, happens with pipes)
		"stty: 'standard input': Inappropriate ioctl for device",
		"stty:",
		
		// URI parsing errors
		"URI::InvalidURIError",
		"from /usr/share/metasploit-framework",
		"vendor/bundle/ruby",
		"gems/uri-",
		"Invalid argument",

		// Ruby gem loading / bundled_gems errors (non-fatal)
		"bundled_gems.rb",
		"in `require'",
		"in `block",
		"in `replace_require'",
		"/usr/lib/ruby/",
		"/usr/bin/msfconsole",
		"<main>",
		"from /",

		// Other known safe warnings
		"warning",
		"Warning",
		"deprecated",
	}

	for _, pattern := range skipPatterns {
		if strings.Contains(line, pattern) {
			return true
		}
	}

	return false
}

// ExecuteCommand sends a command to msfconsole
func (e *SessionExecutor) ExecuteCommand(cmd string) error {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	if !e.running {
		return fmt.Errorf("session not running")
	}

	// Add newline if not present
	if !strings.HasSuffix(cmd, "\n") {
		cmd += "\n"
	}

	_, err := io.WriteString(e.stdin, cmd)
	if err != nil {
		return fmt.Errorf("failed to write command: %w", err)
	}

	return nil
}

// broadcast reads from outputChan and fans out to all registered subscriber channels.
// When outputChan is closed (msfconsole exited) it closes every subscriber channel.
func (e *SessionExecutor) broadcast() {
	for output := range e.outputChan {
		e.connMu.RLock()
		for _, ch := range e.conns {
			select {
			case ch <- output:
			default:
				// slow consumer: drop rather than block the broadcaster
			}
		}
		e.connMu.RUnlock()
	}
	// outputChan drained — close all subscriber channels so WebSocket handlers exit cleanly
	e.connMu.Lock()
	for id, ch := range e.conns {
		close(ch)
		delete(e.conns, id)
	}
	e.connMu.Unlock()
}

// Subscribe registers a new WebSocket connection and returns its ID and a receive-only
// channel. If the process has already exited the returned channel is pre-closed.
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
// Safe to call after the broadcaster has already closed the channel.
func (e *SessionExecutor) Unsubscribe(id int) {
	e.connMu.Lock()
	defer e.connMu.Unlock()
	if ch, ok := e.conns[id]; ok {
		close(ch)
		delete(e.conns, id)
	}
}

// Close terminates the msfconsole session
func (e *SessionExecutor) Close() error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if !e.running {
		return nil
	}

	e.running = false

	// Send exit command
	io.WriteString(e.stdin, "exit\n")
	e.stdin.Close()

	// Give process time to exit gracefully
	time.Sleep(500 * time.Millisecond)

	// Force kill if still running
	if e.cmd.ProcessState == nil {
		e.cmd.Process.Kill()
	}

	// Remove from global map
	execMutex.Lock()
	delete(executors, e.SessionID)
	execMutex.Unlock()

	return nil
}

// GetExecutor retrieves an executor for a session ID
func GetExecutor(sessionID int) *SessionExecutor {
	execMutex.RLock()
	defer execMutex.RUnlock()
	return executors[sessionID]
}

// CloseExecutor closes and removes an executor
func CloseExecutor(sessionID int) error {
	execMutex.Lock()
	executor, exists := executors[sessionID]
	execMutex.Unlock()

	if !exists {
		return nil
	}

	return executor.Close()
}
