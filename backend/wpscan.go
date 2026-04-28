package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/go-chi/chi/v5"
)

// ── Job management ────────────────────────────────────────────────────────────

type WpscanJob struct {
	mu     sync.Mutex
	cmd    *exec.Cmd
	output []string
	found  []WpscanFinding
	done   bool
	err    string
}

type WpscanFinding struct {
	Type  string `json:"type"`  // "user"|"plugin"|"theme"|"vulnerability"|"password"|"interesting"
	Value string `json:"value"`
}

var wpscanJobs sync.Map // sessionID → *WpscanJob

func getWpscanJob(sessionID int) *WpscanJob {
	v, _ := wpscanJobs.Load(sessionID)
	if v == nil {
		return nil
	}
	return v.(*WpscanJob)
}

// ── Request struct ─────────────────────────────────────────────────────────────

type WpscanRequest struct {
	URL            string `json:"url"`
	Enumerate      string `json:"enumerate"`
	Usernames      string `json:"usernames"`
	Passwords      string `json:"passwords"`
	PasswordAttack string `json:"password_attack"`
	ApiToken       string `json:"api_token"`
	Stealthy       bool   `json:"stealthy"`
	Force          bool   `json:"force"`
	DisableTLS     bool   `json:"disable_tls_checks"`
	MaxThreads     int    `json:"max_threads"`
	Throttle       int    `json:"throttle"`
	CookieString   string `json:"cookie_string"`
	HttpAuth       string `json:"http_auth"`
	CustomArgs     string `json:"custom_args"`
}

// ── Arg builder ───────────────────────────────────────────────────────────────

func buildWpscanArgs(req WpscanRequest) ([]string, error) {
	if req.URL == "" {
		return nil, fmt.Errorf("target URL required")
	}

	args := []string{"--url", req.URL, "--no-banner", "--format", "cli-no-colour"}

	enumerate := req.Enumerate
	if enumerate == "" {
		enumerate = "u,vp,vt,tt,cb"
	}
	args = append(args, "-e", enumerate)

	if req.Usernames != "" {
		args = append(args, "-U", req.Usernames)
	}
	if req.Passwords != "" {
		args = append(args, "-P", req.Passwords)
	}
	if req.PasswordAttack != "" {
		args = append(args, "--password-attack", req.PasswordAttack)
	}
	apiToken := req.ApiToken
	if apiToken == "" {
		apiToken = os.Getenv("WPSCAN_API_TOKEN")
	}
	if apiToken != "" {
		args = append(args, "--api-token", apiToken)
	}
	if req.Stealthy {
		args = append(args, "--stealthy")
	}
	if req.Force {
		args = append(args, "--force")
	}
	if req.DisableTLS {
		args = append(args, "--disable-tls-checks")
	}

	threads := req.MaxThreads
	if threads <= 0 {
		threads = 5
	}
	args = append(args, "-t", strconv.Itoa(threads))

	if req.Throttle > 0 {
		args = append(args, "--throttle", strconv.Itoa(req.Throttle))
	}
	if req.CookieString != "" {
		args = append(args, "--cookie-string", req.CookieString)
	}
	if req.HttpAuth != "" {
		args = append(args, "--http-auth", req.HttpAuth)
	}
	if req.CustomArgs != "" {
		args = append(args, strings.Fields(req.CustomArgs)...)
	}

	return args, nil
}

// ── Output parsing ────────────────────────────────────────────────────────────

var (
	reWPUser     = regexp.MustCompile(`(?i)^\s*\|\s+([^\|]+?)\s+\|`)
	reWPPassword = regexp.MustCompile(`(?i)login:\s+'([^']+)'.*password:\s+'([^']+)'`)
	reWPVersion  = regexp.MustCompile(`(?i)WordPress version`)
	reWPPlugin   = regexp.MustCompile(`(?i)\[\+\].*[Pp]lugin`)
	reWPTheme    = regexp.MustCompile(`(?i)\[\+\].*[Tt]heme`)
	reWPVuln     = regexp.MustCompile(`(?i)(\[!\]|vulnerability|CVE-\d{4}-\d+)`)
)

func parseWpscanLine(line string, inUserBlock bool) (*WpscanFinding, bool) {
	trim := strings.TrimSpace(line)

	// Password found
	if m := reWPPassword.FindStringSubmatch(trim); len(m) > 2 {
		return &WpscanFinding{Type: "password", Value: m[1] + ":" + m[2]}, false
	}

	// User block header
	if strings.Contains(trim, "User(s) Identified") || strings.Contains(trim, "Users Identified") {
		return nil, true
	}

	// User row within user block (table rows: | username |)
	if inUserBlock && reWPUser.MatchString(trim) {
		m := reWPUser.FindStringSubmatch(trim)
		if len(m) > 1 {
			val := strings.TrimSpace(m[1])
			if val != "" && !strings.EqualFold(val, "name") && !strings.HasPrefix(val, "-") {
				return &WpscanFinding{Type: "user", Value: val}, true
			}
		}
		return nil, true
	}

	// Exit user block on blank line or non-table line
	if inUserBlock && !strings.HasPrefix(trim, "|") && trim != "" {
		// fall through to check other patterns
	}

	// Vulnerability / warning
	if reWPVuln.MatchString(trim) {
		return &WpscanFinding{Type: "vulnerability", Value: trim}, false
	}

	// WordPress version
	if reWPVersion.MatchString(trim) {
		return &WpscanFinding{Type: "interesting", Value: trim}, false
	}

	// Plugin
	if reWPPlugin.MatchString(trim) {
		return &WpscanFinding{Type: "plugin", Value: trim}, false
	}

	// Theme
	if reWPTheme.MatchString(trim) {
		return &WpscanFinding{Type: "theme", Value: trim}, false
	}

	// Generic interesting [+] line (not already handled above)
	if strings.HasPrefix(trim, "[+]") {
		return &WpscanFinding{Type: "interesting", Value: trim}, false
	}

	return nil, inUserBlock
}

// ── Runner ────────────────────────────────────────────────────────────────────

func runWpscan(job *WpscanJob, args []string, sessionID int, target string, db *DB, userID int) {
	cmd := exec.Command("wpscan", args...)
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	job.mu.Lock()
	job.cmd = cmd
	job.output = append(job.output, fmt.Sprintf("[*] wpscan %s", strings.Join(args, " ")))
	job.mu.Unlock()

	if err := cmd.Start(); err != nil {
		job.mu.Lock()
		job.err = fmt.Sprintf("failed to start wpscan: %v", err)
		job.done = true
		job.mu.Unlock()
		return
	}

	inUserBlock := false

	readStream := func(sc *bufio.Scanner) {
		for sc.Scan() {
			line := sc.Text()
			var newFinding *WpscanFinding
			job.mu.Lock()
			job.output = append(job.output, line)
			if f, nextUserBlock := parseWpscanLine(line, inUserBlock); f != nil {
				job.found = append(job.found, *f)
				cp := *f
				newFinding = &cp
				inUserBlock = nextUserBlock
			} else {
				inUserBlock = nextUserBlock
			}
			job.mu.Unlock()

			if newFinding != nil {
				AppendWpscanFinding(sessionID, target, newFinding.Type, newFinding.Value)
				if newFinding.Type == "password" {
					parts := strings.SplitN(newFinding.Value, ":", 2)
					if len(parts) == 2 {
						AppendBruteforceCredential(sessionID, target, parts[0], parts[1], "wp-login")
						upsertHostBruteforceLoot(db, userID, sessionID, target, "wp-login", parts[0], parts[1])
					}
				}
			}
		}
	}
	go readStream(bufio.NewScanner(stdout))
	go readStream(bufio.NewScanner(stderr))

	cmd.Wait()

	// Snapshot findings before marking done
	job.mu.Lock()
	allFindings := make([]WpscanFinding, len(job.found))
	copy(allFindings, job.found)
	job.done = true
	job.mu.Unlock()

	if len(allFindings) > 0 {
		upsertWordpressProject(db, userID, sessionID, target, allFindings)
	}
}

// upsertWordpressProject finds or creates a project named "Wordpress",
// finds or creates a "WPScan Results" session within it, then saves all findings.
// If attackSessionID belongs to an existing project, that project is used directly.
func upsertWordpressProject(db *DB, userID, attackSessionID int, target string, findings []WpscanFinding) {
	const projectName = "Wordpress"
	const sessName = "WPScan Results"

	// Prefer the project the attacking session already belongs to
	var proj *Project
	if attackSessionID > 0 {
		if sess, err := db.GetSession(attackSessionID, userID); err == nil && sess.ProjectID != nil {
			proj, _ = db.GetProject(*sess.ProjectID, userID)
		}
	}

	// Fall back: find or create the "Wordpress" project
	if proj == nil {
		projects, err := db.GetUserProjects(userID)
		if err == nil {
			for _, p := range projects {
				if strings.EqualFold(p.Name, projectName) {
					proj = p
					break
				}
			}
		}
		if proj == nil {
			var err error
			proj, err = db.CreateProject(userID, projectName, "")
			if err != nil {
				return
			}
		}
	}

	// Find or create "WPScan Results" session
	var sessID int
	sessions, err := db.GetProjectSessions(proj.ID, userID)
	if err == nil {
		for _, s := range sessions {
			if s.SessionName == sessName {
				sessID = s.ID
				break
			}
		}
	}
	if sessID == 0 {
		sess, err := db.CreateProjectSession(userID, proj.ID, sessName, target)
		if err != nil {
			return
		}
		sessID = sess.ID
	}

	// Save each finding to the project session's loot
	for _, f := range findings {
		AppendWpscanFinding(sessID, target, f.Type, f.Value)
	}
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

func handleStartWpscan(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		sessionID, err := strconv.Atoi(chi.URLParam(r, "id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid session id"}`)
			return
		}
		claims, err := validateToken(extractToken(r))
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}

		if j := getWpscanJob(sessionID); j != nil {
			j.mu.Lock()
			running := !j.done
			j.mu.Unlock()
			if running {
				w.WriteHeader(http.StatusConflict)
				fmt.Fprint(w, `{"error":"wpscan already running"}`)
				return
			}
		}

		var req WpscanRequest
		if err := parseJSON(r, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid request"}`)
			return
		}

		args, err := buildWpscanArgs(req)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"error":%q}`, err.Error())
			return
		}

		job := &WpscanJob{}
		wpscanJobs.Store(sessionID, job)
		go runWpscan(job, args, sessionID, req.URL, db, claims.UserID)

		fmt.Fprint(w, `{"status":"started"}`)
	}
}

func handleGetWpscan(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		sessionID, err := strconv.Atoi(chi.URLParam(r, "id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid session id"}`)
			return
		}
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}

		job := getWpscanJob(sessionID)
		if job == nil {
			fmt.Fprint(w, `{"status":"idle","output":[],"found":[],"error":""}`)
			return
		}

		job.mu.Lock()
		output := make([]string, len(job.output))
		copy(output, job.output)
		found := make([]WpscanFinding, len(job.found))
		copy(found, job.found)
		done := job.done
		jobErr := job.err
		job.mu.Unlock()

		outData, _ := encodeJSON(output)
		foundData, _ := encodeJSON(found)
		status := "running"
		if done {
			status = "done"
		}
		fmt.Fprintf(w, `{"status":%q,"output":%s,"found":%s,"error":%q}`,
			status, outData, foundData, jobErr)
	}
}

func handleStopWpscan(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		sessionID, err := strconv.Atoi(chi.URLParam(r, "id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid session id"}`)
			return
		}
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}

		job := getWpscanJob(sessionID)
		if job == nil {
			fmt.Fprint(w, `{"status":"idle"}`)
			return
		}
		job.mu.Lock()
		cmd := job.cmd
		job.mu.Unlock()
		if cmd != nil && cmd.Process != nil {
			cmd.Process.Kill()
		}
		fmt.Fprint(w, `{"status":"stopped"}`)
	}
}
