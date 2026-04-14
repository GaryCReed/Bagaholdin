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
	"time"

	"github.com/go-chi/chi/v5"
)

// ── Job management ────────────────────────────────────────────────────────────

type BruteforceJob struct {
	mu     sync.Mutex
	cmd    *exec.Cmd
	output []string
	found  []FoundCred
	done   bool
	err    string
}

type FoundCred struct {
	Login    string `json:"login"`
	Password string `json:"password"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Service  string `json:"service"`
}

// bruteJobs maps sessionID → *BruteforceJob.
var bruteJobs sync.Map

func getBruteJob(sessionID int) *BruteforceJob {
	v, _ := bruteJobs.Load(sessionID)
	if v == nil {
		return nil
	}
	return v.(*BruteforceJob)
}

// ── Request / response structs ────────────────────────────────────────────────

type BruteforceRequest struct {
	Service string `json:"service"`

	// Credential mode: "wordlist" | "combo" | "single"
	Mode string `json:"mode"`

	// wordlist mode
	UserFile string `json:"user_file"`
	PassFile string `json:"pass_file"`

	// combo mode
	ComboFile string `json:"combo_file"`

	// single mode
	Login    string `json:"login"`
	Password string `json:"password"`

	// -e flags
	TryNull    bool `json:"try_null"`
	TryAsLogin bool `json:"try_as_login"`
	TryReverse bool `json:"try_reverse"`

	// options
	StopFirst  bool `json:"stop_first"`
	UseSSL     bool `json:"use_ssl"`
	LoopUsers  bool `json:"loop_users"`
	Verbose    bool `json:"verbose"`
	Tasks      int  `json:"tasks"`
	Timeout    int  `json:"timeout"`
	Port       int  `json:"port"`

	// HTTP form options (http-post-form / http-get-form)
	FormURL       string `json:"form_url"`
	FormParams    string `json:"form_params"`
	FormCondition string `json:"form_condition"`
}

// ── Hydra arg builder ─────────────────────────────────────────────────────────

func buildHydraArgs(target string, req BruteforceRequest, outFile string) ([]string, error) {
	var args []string

	// Credential flags
	switch req.Mode {
	case "combo":
		if req.ComboFile == "" {
			return nil, fmt.Errorf("combo file required")
		}
		args = append(args, "-C", req.ComboFile)
	case "single":
		if req.Login != "" {
			args = append(args, "-l", req.Login)
		}
		if req.Password != "" {
			args = append(args, "-p", req.Password)
		}
	default: // wordlist
		if req.UserFile != "" {
			args = append(args, "-L", req.UserFile)
		}
		if req.PassFile != "" {
			args = append(args, "-P", req.PassFile)
		}
	}

	// -e flags
	var eflags []string
	if req.TryNull {
		eflags = append(eflags, "n")
	}
	if req.TryAsLogin {
		eflags = append(eflags, "s")
	}
	if req.TryReverse {
		eflags = append(eflags, "r")
	}
	if len(eflags) > 0 {
		args = append(args, "-e", strings.Join(eflags, ""))
	}

	// Misc flags
	if req.StopFirst {
		args = append(args, "-f")
	}
	if req.UseSSL {
		args = append(args, "-S")
	}
	if req.LoopUsers {
		args = append(args, "-u")
	}
	if req.Verbose {
		args = append(args, "-V")
	}

	tasks := req.Tasks
	if tasks <= 0 {
		tasks = 16
	}
	args = append(args, "-t", strconv.Itoa(tasks))

	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 32
	}
	args = append(args, "-w", strconv.Itoa(timeout))

	if req.Port > 0 {
		args = append(args, "-s", strconv.Itoa(req.Port))
	}

	// Output file
	args = append(args, "-o", outFile, "-b", "text")

	// Ignore existing restore file so re-runs start fresh
	args = append(args, "-I")

	// Target
	args = append(args, target)

	// Service + optional module params
	svc := req.Service
	if svc == "http-post-form" || svc == "http-get-form" {
		url := req.FormURL
		if url == "" {
			url = "/"
		}
		params := req.FormParams
		cond := req.FormCondition
		if cond == "" {
			cond = "F=incorrect"
		}
		args = append(args, svc, fmt.Sprintf("%s:%s:%s", url, params, cond))
	} else {
		args = append(args, svc)
	}

	return args, nil
}

// ── Output parser ─────────────────────────────────────────────────────────────

// hydraFoundRe matches lines like:
// [22][ssh] host: 192.168.0.1   login: admin   password: password123
var hydraFoundRe = regexp.MustCompile(
	`\[(\d+)\]\[([^\]]+)\] host: (\S+)\s+login: (\S+)\s+password: (.+)`)

func parseHydraLine(line string) *FoundCred {
	m := hydraFoundRe.FindStringSubmatch(line)
	if m == nil {
		return nil
	}
	port, _ := strconv.Atoi(m[1])
	return &FoundCred{
		Port:     port,
		Service:  m[2],
		Host:     m[3],
		Login:    m[4],
		Password: strings.TrimSpace(m[5]),
	}
}

// ── Background runner ─────────────────────────────────────────────────────────

func runHydra(sessionID int, target string, req BruteforceRequest, db *DB) {
	outFile := fmt.Sprintf("/tmp/hydra-%d.txt", sessionID)
	os.Remove(outFile)

	args, err := buildHydraArgs(target, req, outFile)
	job := getBruteJob(sessionID)
	if err != nil {
		job.mu.Lock()
		job.err = err.Error()
		job.done = true
		job.mu.Unlock()
		return
	}

	cmd := exec.Command("hydra", args...)
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	job.mu.Lock()
	job.cmd = cmd
	job.output = append(job.output, fmt.Sprintf("[*] hydra %s", strings.Join(args, " ")))
	job.mu.Unlock()

	if err := cmd.Start(); err != nil {
		job.mu.Lock()
		job.err = fmt.Sprintf("failed to start hydra: %v", err)
		job.done = true
		job.mu.Unlock()
		return
	}

	readStream := func(r interface{ Scan() bool; Text() string }) {
		for r.Scan() {
			line := r.Text()
			job.mu.Lock()
			job.output = append(job.output, line)
			if fc := parseHydraLine(line); fc != nil {
				job.found = append(job.found, *fc)
				// Auto-save to loot (best-effort, async-safe via mutex already held above)
				go AppendSessionCredential(sessionID, target, fc.Login, fc.Password)
			}
			job.mu.Unlock()
		}
	}

	go readStream(bufio.NewScanner(stdout))
	go readStream(bufio.NewScanner(stderr))

	_ = cmd.Wait()

	job.mu.Lock()
	job.done = true
	job.mu.Unlock()
}

// ── Wordlist catalogue ────────────────────────────────────────────────────────

type WordlistEntry struct {
	Label string `json:"label"`
	Path  string `json:"path"`
	Group string `json:"group"`
}

func catalogueWordlists() (users []WordlistEntry, passwords []WordlistEntry) {
	type entry struct {
		label string
		path  string
		group string
	}

	userCandidates := []entry{
		{"unix_users", "/usr/share/metasploit-framework/data/wordlists/unix_users.txt", "Metasploit"},
		{"http_default_users", "/usr/share/metasploit-framework/data/wordlists/http_default_users.txt", "Metasploit"},
		{"default_users_services", "/usr/share/metasploit-framework/data/wordlists/default_users_for_services_unhash.txt", "Metasploit"},
		{"postgres_default_user", "/usr/share/metasploit-framework/data/wordlists/postgres_default_user.txt", "Metasploit"},
		{"db2_default_user", "/usr/share/metasploit-framework/data/wordlists/db2_default_user.txt", "Metasploit"},
		{"ipmi_users", "/usr/share/metasploit-framework/data/wordlists/ipmi_users.txt", "Metasploit"},
		{"usernames (nmap)", "/usr/share/nmap/nselib/data/usernames.lst", "Nmap"},
		{"usernames (commix)", "/usr/share/commix/src/txt/default_usernames.txt", "Commix"},
	}

	passCandidates := []entry{
		{"rockyou", "/usr/share/wordlists/rockyou.txt", "Wordlists"},
		{"fasttrack", "/usr/share/wordlists/fasttrack.txt", "Wordlists"},
		{"john", "/usr/share/wordlists/john.lst", "Wordlists"},
		{"password.lst (msf)", "/usr/share/metasploit-framework/data/wordlists/password.lst", "Metasploit"},
		{"ipmi_passwords", "/usr/share/metasploit-framework/data/wordlists/ipmi_passwords.txt", "Metasploit"},
		{"default_pass_services", "/usr/share/metasploit-framework/data/wordlists/default_pass_for_services_unhash.txt", "Metasploit"},
		{"http_default_pass", "/usr/share/metasploit-framework/data/wordlists/http_default_pass.txt", "Metasploit"},
		{"nmap.lst", "/usr/share/wordlists/nmap.lst", "Wordlists"},
	}

	comboCandidates := []entry{
		{"default_userpass_services", "/usr/share/metasploit-framework/data/wordlists/default_userpass_for_services_unhash.txt", "Metasploit Combo"},
		{"http_default_userpass", "/usr/share/metasploit-framework/data/wordlists/http_default_userpass.txt", "Metasploit Combo"},
		{"db2_default_userpass", "/usr/share/metasploit-framework/data/wordlists/db2_default_userpass.txt", "Metasploit Combo"},
		{"postgres_default_userpass", "/usr/share/metasploit-framework/data/wordlists/postgres_default_userpass.txt", "Metasploit Combo"},
		{"oracle_default_userpass", "/usr/share/metasploit-framework/data/wordlists/oracle_default_userpass.txt", "Metasploit Combo"},
		{"scada_default_userpass", "/usr/share/metasploit-framework/data/wordlists/scada_default_userpass.txt", "Metasploit Combo"},
		{"routers_userpass", "/usr/share/metasploit-framework/data/wordlists/routers_userpass.txt", "Metasploit Combo"},
	}

	for _, c := range userCandidates {
		if _, err := os.Stat(c.path); err == nil {
			users = append(users, WordlistEntry{Label: c.label, Path: c.path, Group: c.group})
		}
	}
	// Combo files are also valid as user lists when used with -C
	for _, c := range comboCandidates {
		if _, err := os.Stat(c.path); err == nil {
			users = append(users, WordlistEntry{Label: c.label + " (combo)", Path: c.path, Group: c.group})
		}
	}

	for _, c := range passCandidates {
		if _, err := os.Stat(c.path); err == nil {
			passwords = append(passwords, WordlistEntry{Label: c.label, Path: c.path, Group: c.group})
		}
	}

	// Combo files listed separately for the combo dropdown
	var combos []WordlistEntry
	for _, c := range comboCandidates {
		if _, err := os.Stat(c.path); err == nil {
			combos = append(combos, WordlistEntry{Label: c.label, Path: c.path, Group: c.group})
		}
	}
	// Append combos to passwords slice using a sentinel group so frontend can split them
	passwords = append(passwords, combos...)

	return users, passwords
}

// Also scan /usr/share/seclists if present
func init() {
	go func() {
		time.Sleep(100 * time.Millisecond) // yield to let main set up
		seclists := []string{
			"/usr/share/seclists/Usernames",
			"/usr/share/seclists/Passwords",
		}
		for _, dir := range seclists {
			if _, err := os.Stat(dir); err == nil {
				_ = dir // seclists present — future expansion
			}
		}
	}()
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

func handleGetWordlists() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		users, passwords := catalogueWordlists()
		data, _ := encodeJSON(map[string]interface{}{
			"users":     users,
			"passwords": passwords,
		})
		fmt.Fprint(w, data)
	}
}

func handleStartBruteforce(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		sessionID, err := strconv.Atoi(chi.URLParam(r, "id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid session id"}`)
			return
		}

		token := extractToken(r)
		claims, err := validateToken(token)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}

		session, err := db.GetSession(sessionID, claims.UserID)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"session not found"}`)
			return
		}

		// Reject if already running
		if j := getBruteJob(sessionID); j != nil {
			j.mu.Lock()
			running := !j.done
			j.mu.Unlock()
			if running {
				w.WriteHeader(http.StatusConflict)
				fmt.Fprint(w, `{"error":"attack already running"}`)
				return
			}
		}

		var req BruteforceRequest
		if err := parseJSON(r, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"error":"invalid request: %v"}`, err)
			return
		}

		if req.Service == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"service required"}`)
			return
		}

		job := &BruteforceJob{}
		bruteJobs.Store(sessionID, job)

		go runHydra(sessionID, session.TargetHost, req, db)

		fmt.Fprint(w, `{"status":"started"}`)
	}
}

func handleGetBruteforce(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		sessionID, err := strconv.Atoi(chi.URLParam(r, "id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid session id"}`)
			return
		}

		token := extractToken(r)
		_, err = validateToken(token)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}

		job := getBruteJob(sessionID)
		if job == nil {
			fmt.Fprint(w, `{"status":"idle","output":[],"found":[]}`)
			return
		}

		job.mu.Lock()
		output := make([]string, len(job.output))
		copy(output, job.output)
		found := make([]FoundCred, len(job.found))
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

func handleStopBruteforce(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		sessionID, err := strconv.Atoi(chi.URLParam(r, "id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid session id"}`)
			return
		}

		token := extractToken(r)
		_, err = validateToken(token)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}

		job := getBruteJob(sessionID)
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
