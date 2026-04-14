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

type SqlmapJob struct {
	mu     sync.Mutex
	cmd    *exec.Cmd
	output []string
	found  []SqlmapFinding
	done   bool
	err    string
}

type SqlmapFinding struct {
	Type  string `json:"type"`  // "injection" | "database" | "table" | "hash" | "dump"
	Value string `json:"value"`
}

var sqlmapJobs sync.Map // sessionID → *SqlmapJob

func getSqlmapJob(sessionID int) *SqlmapJob {
	v, _ := sqlmapJobs.Load(sessionID)
	if v == nil {
		return nil
	}
	return v.(*SqlmapJob)
}

// ── Request struct ─────────────────────────────────────────────────────────────

type SqlmapRequest struct {
	// Target
	URL         string `json:"url"`
	Data        string `json:"data"`
	Cookie      string `json:"cookie"`
	Method      string `json:"method"`
	Headers     string `json:"headers"`
	RequestFile string `json:"request_file"`
	DirectConn  string `json:"direct_conn"`

	// Injection
	TestParam string `json:"test_param"`
	DBMS      string `json:"dbms"`
	Prefix    string `json:"prefix"`
	Suffix    string `json:"suffix"`
	Tamper    string `json:"tamper"`
	Technique string `json:"technique"`

	// Detection
	Level  int  `json:"level"`
	Risk   int  `json:"risk"`
	Smart  bool `json:"smart"`
	Forms  bool `json:"forms"`

	// Enumeration
	GetBanner      bool `json:"get_banner"`
	GetCurrentUser bool `json:"get_current_user"`
	GetCurrentDB   bool `json:"get_current_db"`
	GetIsDBA       bool `json:"get_is_dba"`
	GetUsers       bool `json:"get_users"`
	GetPasswords   bool `json:"get_passwords"`
	GetDatabases   bool `json:"get_databases"`
	GetTables      bool `json:"get_tables"`
	GetColumns     bool `json:"get_columns"`
	DumpTable      bool `json:"dump_table"`
	DumpAll        bool `json:"dump_all"`
	Schema         bool `json:"schema"`

	// Enum filters
	Database string `json:"database"`
	Table    string `json:"table"`
	Column   string `json:"column"`

	// Request options
	RandomAgent bool    `json:"random_agent"`
	Proxy       string  `json:"proxy"`
	UseTor      bool    `json:"use_tor"`
	Delay       float64 `json:"delay"`
	Timeout     int     `json:"timeout"`
	Retries     int     `json:"retries"`
	Threads     int     `json:"threads"`
	ForceSSL    bool    `json:"force_ssl"`

	// General
	Verbosity    int    `json:"verbosity"`
	FlushSession bool   `json:"flush_session"`
	ParseErrors  bool   `json:"parse_errors"`
	CrawlDepth   int    `json:"crawl_depth"`
	CustomArgs   string `json:"custom_args"`
}

// ── Arg builder ───────────────────────────────────────────────────────────────

func buildSqlmapArgs(req SqlmapRequest, outputDir string) ([]string, error) {
	// Require at least one target source
	if req.URL == "" && req.RequestFile == "" && req.DirectConn == "" {
		return nil, fmt.Errorf("target URL, request file, or direct connection string required")
	}

	args := []string{"--batch", "--disable-coloring", "--output-dir=" + outputDir}

	// Target
	if req.URL != "" {
		args = append(args, "-u", req.URL)
	}
	if req.RequestFile != "" {
		args = append(args, "-r", req.RequestFile)
	}
	if req.DirectConn != "" {
		args = append(args, "-d", req.DirectConn)
	}

	// Request
	if req.Data != "" {
		args = append(args, "--data="+req.Data)
	}
	if req.Cookie != "" {
		args = append(args, "--cookie="+req.Cookie)
	}
	if req.Method != "" {
		args = append(args, "--method="+req.Method)
	}
	if req.Headers != "" {
		args = append(args, "--headers="+req.Headers)
	}
	if req.RandomAgent {
		args = append(args, "--random-agent")
	}
	if req.Proxy != "" {
		args = append(args, "--proxy="+req.Proxy)
	}
	if req.UseTor {
		args = append(args, "--tor")
	}
	if req.ForceSSL {
		args = append(args, "--force-ssl")
	}
	if req.Delay > 0 {
		args = append(args, fmt.Sprintf("--delay=%.1f", req.Delay))
	}
	if req.Timeout > 0 {
		args = append(args, "--timeout="+strconv.Itoa(req.Timeout))
	}
	if req.Retries > 0 {
		args = append(args, "--retries="+strconv.Itoa(req.Retries))
	}
	if req.Threads > 1 {
		args = append(args, "--threads="+strconv.Itoa(req.Threads))
	}

	// Injection
	if req.TestParam != "" {
		args = append(args, "-p", req.TestParam)
	}
	if req.DBMS != "" {
		args = append(args, "--dbms="+req.DBMS)
	}
	if req.Prefix != "" {
		args = append(args, "--prefix="+req.Prefix)
	}
	if req.Suffix != "" {
		args = append(args, "--suffix="+req.Suffix)
	}
	if req.Tamper != "" {
		args = append(args, "--tamper="+req.Tamper)
	}
	tech := req.Technique
	if tech == "" {
		tech = "BEUSTQ"
	}
	args = append(args, "--technique="+tech)

	// Detection
	level := req.Level
	if level < 1 || level > 5 {
		level = 1
	}
	args = append(args, "--level="+strconv.Itoa(level))

	risk := req.Risk
	if risk < 1 || risk > 3 {
		risk = 1
	}
	args = append(args, "--risk="+strconv.Itoa(risk))

	if req.Smart {
		args = append(args, "--smart")
	}
	if req.Forms {
		args = append(args, "--forms")
	}
	if req.ParseErrors {
		args = append(args, "--parse-errors")
	}

	// Enumeration
	if req.GetBanner {
		args = append(args, "-b")
	}
	if req.GetCurrentUser {
		args = append(args, "--current-user")
	}
	if req.GetCurrentDB {
		args = append(args, "--current-db")
	}
	if req.GetIsDBA {
		args = append(args, "--is-dba")
	}
	if req.GetUsers {
		args = append(args, "--users")
	}
	if req.GetPasswords {
		args = append(args, "--passwords")
	}
	if req.GetDatabases {
		args = append(args, "--dbs")
	}
	if req.GetTables {
		args = append(args, "--tables")
	}
	if req.GetColumns {
		args = append(args, "--columns")
	}
	if req.Schema {
		args = append(args, "--schema")
	}
	if req.DumpTable {
		args = append(args, "--dump")
	}
	if req.DumpAll {
		args = append(args, "--dump-all")
	}

	// Enum filters
	if req.Database != "" {
		args = append(args, "-D", req.Database)
	}
	if req.Table != "" {
		args = append(args, "-T", req.Table)
	}
	if req.Column != "" {
		args = append(args, "-C", req.Column)
	}

	// General
	v := req.Verbosity
	if v < 0 || v > 6 {
		v = 1
	}
	args = append(args, "-v", strconv.Itoa(v))

	if req.FlushSession {
		args = append(args, "--flush-session")
	}
	if req.CrawlDepth > 0 {
		args = append(args, "--crawl="+strconv.Itoa(req.CrawlDepth))
	}

	if req.CustomArgs != "" {
		args = append(args, strings.Fields(req.CustomArgs)...)
	}

	return args, nil
}

// ── Output parsing ────────────────────────────────────────────────────────────

var (
	reDBMS       = regexp.MustCompile(`(?i)the back-end DBMS is ([^\n\r]+)`)
	reInjectable = regexp.MustCompile(`(?i)(injectable|SQL injection (vulnerability|point))`)
	reDatabase   = regexp.MustCompile(`^\[\*\] (.+)$`)
	reDumpRow    = regexp.MustCompile(`^\| .+ \|`)
	reDBLine     = regexp.MustCompile(`(?i)^Database:\s+(\S+)`)
	reTblLine    = regexp.MustCompile(`(?i)^Table:\s+(\S+)`)
)

// parseSqlmapLine inspects a single output line and returns a finding if one is detected.
func parseSqlmapLine(line string) *SqlmapFinding {
	// DBMS identification
	if m := reDBMS.FindStringSubmatch(line); len(m) > 1 {
		return &SqlmapFinding{Type: "injection", Value: "DBMS: " + strings.TrimSpace(m[1])}
	}
	// Injectable parameter
	if reInjectable.MatchString(line) {
		return &SqlmapFinding{Type: "injection", Value: strings.TrimSpace(line)}
	}
	// Database list entry (sqlmap prints [*] <dbname> when listing dbs)
	if strings.Contains(line, "available databases") || strings.Contains(line, "database schemas") {
		return &SqlmapFinding{Type: "database", Value: strings.TrimSpace(line)}
	}
	if m := reDatabase.FindStringSubmatch(line); len(m) > 1 {
		val := strings.TrimSpace(m[1])
		// Avoid matching generic info lines
		if !strings.Contains(val, "[") && !strings.Contains(val, "starting") {
			return &SqlmapFinding{Type: "database", Value: val}
		}
	}
	// Table name line in dump output
	if m := reDBLine.FindStringSubmatch(line); len(m) > 1 {
		return &SqlmapFinding{Type: "database", Value: strings.TrimSpace(m[1])}
	}
	if m := reTblLine.FindStringSubmatch(line); len(m) > 1 {
		return &SqlmapFinding{Type: "table", Value: strings.TrimSpace(m[1])}
	}
	// Password hash lines
	if strings.Contains(line, "password hash") || strings.Contains(line, "Password hash") {
		return &SqlmapFinding{Type: "hash", Value: strings.TrimSpace(line)}
	}
	// Dump row
	if reDumpRow.MatchString(line) {
		return &SqlmapFinding{Type: "dump", Value: strings.TrimSpace(line)}
	}
	// Generic [+] found line
	if strings.HasPrefix(strings.TrimSpace(line), "[+]") {
		return &SqlmapFinding{Type: "injection", Value: strings.TrimSpace(line)}
	}
	return nil
}

// ── Runner ────────────────────────────────────────────────────────────────────

func runSqlmap(job *SqlmapJob, args []string) {
	cmd := exec.Command("sqlmap", args...)
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	job.mu.Lock()
	job.cmd = cmd
	job.output = append(job.output, fmt.Sprintf("[*] sqlmap %s", strings.Join(args, " ")))
	job.mu.Unlock()

	if err := cmd.Start(); err != nil {
		job.mu.Lock()
		job.err = fmt.Sprintf("failed to start sqlmap: %v", err)
		job.done = true
		job.mu.Unlock()
		return
	}

	readStream := func(sc *bufio.Scanner) {
		for sc.Scan() {
			line := sc.Text()
			job.mu.Lock()
			job.output = append(job.output, line)
			if f := parseSqlmapLine(line); f != nil {
				job.found = append(job.found, *f)
			}
			job.mu.Unlock()
		}
	}
	go readStream(bufio.NewScanner(stdout))
	go readStream(bufio.NewScanner(stderr))

	cmd.Wait()

	job.mu.Lock()
	job.done = true
	job.mu.Unlock()
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

func handleStartSqlmap(db *DB) http.HandlerFunc {
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

		// Reject if already running
		if j := getSqlmapJob(sessionID); j != nil {
			j.mu.Lock()
			running := !j.done
			j.mu.Unlock()
			if running {
				w.WriteHeader(http.StatusConflict)
				fmt.Fprint(w, `{"error":"sqlmap already running"}`)
				return
			}
		}

		var req SqlmapRequest
		if err := parseJSON(r, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid request"}`)
			return
		}

		outputDir := fmt.Sprintf("/tmp/sqlmap-%d", sessionID)
		os.MkdirAll(outputDir, 0o755)

		args, err := buildSqlmapArgs(req, outputDir)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"error":%q}`, err.Error())
			return
		}

		job := &SqlmapJob{}
		sqlmapJobs.Store(sessionID, job)
		go runSqlmap(job, args)

		fmt.Fprint(w, `{"status":"started"}`)
	}
}

func handleGetSqlmap(db *DB) http.HandlerFunc {
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

		job := getSqlmapJob(sessionID)
		if job == nil {
			fmt.Fprint(w, `{"status":"idle","output":[],"found":[],"error":""}`)
			return
		}

		job.mu.Lock()
		output := make([]string, len(job.output))
		copy(output, job.output)
		found := make([]SqlmapFinding, len(job.found))
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

func handleStopSqlmap(db *DB) http.HandlerFunc {
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

		job := getSqlmapJob(sessionID)
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
