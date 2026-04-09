package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gorilla/websocket"
)

// isSessionOpenedLine returns true when a msfconsole output line announces a
// newly opened session, e.g. "[*] Meterpreter session 2 opened (…)".
func isSessionOpenedLine(line string) bool {
	lower := strings.ToLower(line)
	return strings.Contains(lower, "session") && strings.Contains(lower, "opened")
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true // non-browser client (curl, API tests)
		}
		allowed := os.Getenv("ALLOWED_ORIGIN")
		if allowed == "" {
			// Default: allow localhost on any port in development
			return strings.HasPrefix(origin, "http://localhost") ||
				strings.HasPrefix(origin, "http://127.0.0.1")
		}
		// Production: comma-separated list of exact origins
		for _, o := range strings.Split(allowed, ",") {
			if strings.TrimSpace(o) == origin {
				return true
			}
		}
		return false
	},
}

type CommandMessage struct {
	SessionID int    `json:"session_id"`
	Command   string `json:"command"`
}

type OutputMessage struct {
	Type    string      `json:"type"`
	Output  string      `json:"output"`
	Status  string      `json:"status"`
	Payload interface{} `json:"payload,omitempty"`
}

func handleCommandWebSocket(w http.ResponseWriter, r *http.Request, db *DB) {
	// Extract session ID from query params
	sessionIDStr := r.URL.Query().Get("session")
	if sessionIDStr == "" {
		fmt.Printf("[WS] Missing session parameter\n")
		http.Error(w, "session parameter required", http.StatusBadRequest)
		return
	}

	sessionID, err := strconv.Atoi(sessionIDStr)
	if err != nil {
		fmt.Printf("[WS] Invalid session ID: %s\n", sessionIDStr)
		http.Error(w, "invalid session ID", http.StatusBadRequest)
		return
	}

	// Authenticate: cookie first (httpOnly), fall back to query param for non-browser clients
	token := extractToken(r)
	if token == "" {
		token = r.URL.Query().Get("token")
	}
	if token == "" {
		fmt.Printf("[WS] Missing token for session %d\n", sessionID)
		http.Error(w, "token required", http.StatusUnauthorized)
		return
	}

	claims, err := validateToken(token)
	if err != nil {
		fmt.Printf("[WS] Token validation failed for session %d: %v\n", sessionID, err)
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	fmt.Printf("[WS] Authenticated user %s for session %d\n", claims.Username, sessionID)

	// Upgrade connection FIRST - before spawning msfconsole
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Printf("[WS] WebSocket upgrade error for session %d: %v\n", sessionID, err)
		return
	}
	defer conn.Close()

	fmt.Printf("[WS] WebSocket upgraded for session %d\n", sessionID)

	// Get or create executor for this session.
	// Use a per-session startup lock so only one goroutine calls StartSession
	// at a time; concurrent reconnects wait for the first one to finish.
	executor := GetExecutor(sessionID)
	if executor == nil {
		readyCh := make(chan struct{})
		actual, loaded := startingMap.LoadOrStore(sessionID, readyCh)
		if loaded {
			// Another goroutine is already starting this session — wait for it.
			fmt.Printf("[WS] Session %d: waiting for concurrent startup\n", sessionID)
			<-actual.(chan struct{})
			executor = GetExecutor(sessionID)
			if executor == nil {
				conn.WriteJSON(OutputMessage{Type: "error", Status: "executor_start_failed", Output: "Failed to start msfconsole"})
				return
			}
		} else {
			// We are responsible for starting the executor.
			defer func() {
				startingMap.Delete(sessionID)
				close(readyCh) // unblock any waiters
			}()

			fmt.Printf("[WS] Creating new executor for session %d\n", sessionID)
			session, err := db.GetSession(sessionID, claims.UserID)
			if err != nil {
				fmt.Printf("[WS] Session %d not found for user %s\n", sessionID, claims.Username)
				conn.WriteJSON(OutputMessage{Type: "error", Status: "session_not_found", Output: "Session not found"})
				return
			}
			newExecutor, err := StartSession(sessionID, session.TargetHost)
			if err != nil {
				fmt.Printf("[WS] Failed to start executor for session %d: %v\n", sessionID, err)
				conn.WriteJSON(OutputMessage{Type: "error", Status: "executor_start_failed", Output: fmt.Sprintf("Failed to start msfconsole: %v", err)})
				return
			}
			// Store in global map now so concurrent connections and HTTP handlers
			// can find it immediately.
			execMutex.Lock()
			executors[sessionID] = newExecutor
			execMutex.Unlock()
			executor = newExecutor
		}
	}

	fmt.Printf("[WS] Executor ready for session %d\n", sessionID)

	// Register this connection with the executor's fan-out broadcaster
	connID, subChan := executor.Subscribe()
	defer executor.Unsubscribe(connID)

	// Send welcome message
	welcomeMsg := OutputMessage{
		Type:   "welcome",
		Status: "connected",
		Output: fmt.Sprintf("[*] Connected to MSF Console (Session %d, User: %s)", sessionID, claims.Username),
	}
	conn.WriteJSON(welcomeMsg)

	// Stream output from this connection's subscriber channel to the WebSocket
	go func() {
		for output := range subChan {
			if output != "" {
				conn.WriteJSON(OutputMessage{
					Type:   "output",
					Output: output,
					Status: "streaming",
				})
				// Notify the client whenever msfconsole opens a new session so
				// the Shells panel can auto-refresh without polling.
				if isSessionOpenedLine(output) {
					conn.WriteJSON(OutputMessage{
						Type:   "session_opened",
						Status: "new_session",
						Output: output,
					})
				}
			}
		}
		// subChan closed means msfconsole exited — notify client then close
		// so ws.onclose fires and the browser's reconnect loop takes over.
		conn.WriteJSON(OutputMessage{
			Type:   "status",
			Status: "disconnected",
			Output: "[!] MSF Console disconnected — reconnecting…",
		})
		conn.Close()
	}()

	// Read commands from WebSocket and send to executor
	for {
		var msg CommandMessage
		err := conn.ReadJSON(&msg)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				fmt.Printf("WebSocket error: %v\n", err)
			}
			break
		}

		// Allow commands without explicit session_id (default to current session)
		if msg.SessionID == 0 {
			msg.SessionID = sessionID
		}

		if msg.SessionID != sessionID {
			errorMsg := OutputMessage{
				Type:   "error",
				Status: "session_mismatch",
				Output: fmt.Sprintf("[!] Session ID mismatch: URL session=%d, command session=%d", sessionID, msg.SessionID),
			}
			conn.WriteJSON(errorMsg)
			continue
		}

		// Send command to executor
		if msg.Command != "" {
			if err := executor.ExecuteCommand(msg.Command); err != nil {
				errorMsg := OutputMessage{
					Type:   "error",
					Status: "command_failed",
					Output: fmt.Sprintf("Failed to execute command: %v", err),
				}
				conn.WriteJSON(errorMsg)
			} else {
				confirmMsg := OutputMessage{
					Type:   "confirmation",
					Status: "sent",
					Payload: map[string]interface{}{
						"session_id": msg.SessionID,
						"command":    msg.Command,
					},
				}
				conn.WriteJSON(confirmMsg)
			}
		}
	}
}

