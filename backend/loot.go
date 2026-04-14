package main

import (
	"encoding/xml"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// lootMu serialises all loot file reads+writes to prevent concurrent goroutines
// from overwriting each other (e.g. multiple hydra creds found simultaneously).
var lootMu sync.Mutex

// ── XML / JSON structures ────────────────────────────────────────────────────

type LootField struct {
	Name  string `xml:"name,attr" json:"name"`
	Value string `xml:",chardata" json:"value"`
}

type LootItem struct {
	Type      string      `xml:"type"       json:"type"`
	Source    string      `xml:"source"     json:"source"`
	Timestamp string      `xml:"timestamp"  json:"timestamp"`
	Fields    []LootField `xml:"data>field" json:"fields"`
}

type LootDocument struct {
	XMLName   xml.Name   `xml:"loot"`
	SessionID int        `xml:"session_id,attr"`
	Target    string     `xml:"target,attr"`
	Items     []LootItem `xml:"items>item"`
}

// ── File path ────────────────────────────────────────────────────────────────

func lootXMLPath(sessionID int) string {
	return fmt.Sprintf("/tmp/loot-%d.xml", sessionID)
}

// ── Load / Save ──────────────────────────────────────────────────────────────

func loadLootDocument(sessionID int) *LootDocument {
	data, err := os.ReadFile(lootXMLPath(sessionID))
	if err != nil {
		return nil
	}
	var doc LootDocument
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil
	}
	return &doc
}

func saveLootDocument(doc *LootDocument) error {
	data, err := xml.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(lootXMLPath(doc.SessionID),
		append([]byte(xml.Header), data...), 0644)
}

// appendCredential is the shared implementation for credential loot entries.
// lootMu must NOT be held by the caller — this function acquires it.
func appendCredential(sessionID int, target, lootType, source, username, password string) error {
	if username == "" && password == "" {
		return nil
	}
	lootMu.Lock()
	defer lootMu.Unlock()

	doc := loadLootDocument(sessionID)
	if doc == nil {
		doc = &LootDocument{SessionID: sessionID, Target: target}
	}
	// Dedup: skip if an identical (type, username, password) entry already exists.
	for _, item := range doc.Items {
		if item.Type != lootType {
			continue
		}
		uMatch, pMatch := false, false
		for _, f := range item.Fields {
			if f.Name == "username" && f.Value == username {
				uMatch = true
			}
			if f.Name == "password" && f.Value == password {
				pMatch = true
			}
		}
		if uMatch && pMatch {
			return nil
		}
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	doc.Items = append(doc.Items, LootItem{
		Type:      lootType,
		Source:    source,
		Timestamp: ts,
		Fields:    lootFields("username", username, "password", password),
	})
	return saveLootDocument(doc)
}

// AppendSessionCredential saves credentials captured when an MSF session opens.
func AppendSessionCredential(sessionID int, target, username, password string) error {
	return appendCredential(sessionID, target, "session_credential", "msf_session_open", username, password)
}

// AppendBruteforceCredential saves a credential pair found by Hydra.
func AppendBruteforceCredential(sessionID int, target, username, password, service string) error {
	if username == "" && password == "" {
		return nil
	}
	lootMu.Lock()
	defer lootMu.Unlock()

	doc := loadLootDocument(sessionID)
	if doc == nil {
		doc = &LootDocument{SessionID: sessionID, Target: target}
	}
	for _, item := range doc.Items {
		if item.Type != "bruteforce_credential" {
			continue
		}
		uMatch, pMatch := false, false
		for _, f := range item.Fields {
			if f.Name == "username" && f.Value == username {
				uMatch = true
			}
			if f.Name == "password" && f.Value == password {
				pMatch = true
			}
		}
		if uMatch && pMatch {
			return nil
		}
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	doc.Items = append(doc.Items, LootItem{
		Type:      "bruteforce_credential",
		Source:    "hydra/" + service,
		Timestamp: ts,
		Fields:    lootFields("username", username, "password", password, "service", service),
	})
	return saveLootDocument(doc)
}

// AppendLoot parses cmd+output for useful loot and appends to the session's loot.xml.
func AppendLoot(sessionID int, target, cmd, output string) error {
	items := extractLoot(cmd, output)
	if len(items) == 0 {
		return nil
	}
	doc := loadLootDocument(sessionID)
	if doc == nil {
		doc = &LootDocument{SessionID: sessionID, Target: target}
	}
	doc.Items = append(doc.Items, items...)
	return saveLootDocument(doc)
}

// ── Dispatch ─────────────────────────────────────────────────────────────────

func extractLoot(cmd, output string) []LootItem {
	c := strings.ToLower(strings.TrimSpace(cmd))
	ts := time.Now().UTC().Format(time.RFC3339)

	switch {
	case c == "sysinfo":
		return parseSysinfo(output, ts)
	case c == "getuid":
		return parseGetuid(output, ts)
	case c == "getsystem":
		return parseGetsystem(output, ts)
	case c == "getprivs":
		return parseGetprivs(output, ts)
	case c == "is_admin":
		return parseIsAdmin(output, ts)
	case c == "hashdump", c == "run post/linux/gather/hashdump":
		return parseHashdump(output, ts)
	case c == "shell id", c == "id":
		return parseLinuxID(output, ts)
	case c == "whoami", c == "shell whoami":
		return parseWhoami(output, ts)
	case c == "shell whoami /all", c == "whoami /all":
		return parseWhoamiAll(output, ts)
	case c == "shell uname -a", c == "uname -a":
		return parseUname(output, ts)
	case c == "shell ver":
		return parseWindowsVer(output, ts)
	case c == "shell net user", c == "net user":
		return parseNetUser(output, ts)
	case c == "shell cat /etc/passwd", c == "cat /etc/passwd":
		return parseEtcPasswd(output, ts)
	case c == "shell systeminfo", c == "systeminfo":
		return parseSysteminfo(output, ts)
	case c == "env", c == "shell env":
		return parseEnv(output, ts)
	case c == "arp", c == "shell arp":
		return parseArp(output, ts)
	case c == "run post/linux/gather/mimipenguin":
		return parseMimipenguin(output, ts)
	case c == "run post/windows/gather/lsa_secrets":
		return parseLsaSecrets(output, ts)
	case c == "run post/windows/gather/cachedump":
		return parseCachedump(output, ts)
	default:
		return nil
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func lootFields(pairs ...string) []LootField {
	out := make([]LootField, 0, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		if pairs[i+1] != "" {
			out = append(out, LootField{Name: pairs[i], Value: pairs[i+1]})
		}
	}
	return out
}

func singleLootItem(lootType, source, ts string, f []LootField) []LootItem {
	if len(f) == 0 {
		return nil
	}
	return []LootItem{{Type: lootType, Source: source, Timestamp: ts, Fields: f}}
}

// extractLineValue returns the value after "prefix:" from multi-line output (case-insensitive).
func extractLineValue(output, prefix string) string {
	pLower := strings.ToLower(prefix)
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(trimmed), pLower) {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

// ── Parsers ──────────────────────────────────────────────────────────────────

func parseSysinfo(output, ts string) []LootItem {
	return singleLootItem("system_info", "sysinfo", ts, lootFields(
		"hostname",     extractLineValue(output, "Computer"),
		"os",           extractLineValue(output, "OS"),
		"arch",         extractLineValue(output, "Architecture"),
		"language",     extractLineValue(output, "System Language"),
		"session_type", extractLineValue(output, "Meterpreter"),
	))
}

func parseGetuid(output, ts string) []LootItem {
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(strings.ToLower(line), "server username") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return singleLootItem("current_user", "getuid", ts,
					lootFields("username", strings.TrimSpace(parts[1])))
			}
		}
	}
	return nil
}

func parseGetsystem(output, ts string) []LootItem {
	for _, line := range strings.Split(output, "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "got system") || strings.Contains(lower, "already running as system") {
			return singleLootItem("privilege_escalation", "getsystem", ts,
				lootFields("result", strings.TrimSpace(line)))
		}
	}
	return nil
}

func parseGetprivs(output, ts string) []LootItem {
	var privs []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Se") {
			privs = append(privs, line)
		}
	}
	return singleLootItem("privileges", "getprivs", ts,
		lootFields("privileges", strings.Join(privs, ", ")))
}

func parseIsAdmin(output, ts string) []LootItem {
	lower := strings.ToLower(output)
	result := "false"
	if strings.Contains(lower, "admin") &&
		(strings.Contains(lower, "yes") || strings.Contains(lower, "true") ||
			strings.Contains(lower, "has admin") || strings.Contains(lower, "is admin")) {
		result = "true"
	}
	return singleLootItem("is_admin", "is_admin", ts, lootFields("admin", result))
}

var hashdumpRe = regexp.MustCompile(`^([^:]+):(\d+):([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::`)

func parseHashdump(output, ts string) []LootItem {
	var items []LootItem
	for _, line := range strings.Split(output, "\n") {
		m := hashdumpRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		items = append(items, LootItem{
			Type: "credential", Source: "hashdump", Timestamp: ts,
			Fields: lootFields("username", m[1], "rid", m[2], "lm_hash", m[3], "nt_hash", m[4]),
		})
	}
	return items
}

var linuxIDRe = regexp.MustCompile(`uid=(\d+)\(([^)]+)\)`)

func parseLinuxID(output, ts string) []LootItem {
	m := linuxIDRe.FindStringSubmatch(output)
	if m == nil {
		return nil
	}
	return singleLootItem("current_user", "id", ts, lootFields("uid", m[1], "username", m[2]))
}

func parseWhoami(output, ts string) []LootItem {
	val := strings.TrimSpace(output)
	if val == "" {
		return nil
	}
	return singleLootItem("current_user", "whoami", ts, lootFields("username", val))
}

func parseWhoamiAll(output, ts string) []LootItem {
	var groups, privs []string
	inGroup, inPriv := false, false
	for _, line := range strings.Split(output, "\n") {
		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.Contains(lower, "group name") {
			inGroup, inPriv = true, false
			continue
		}
		if strings.Contains(lower, "privilege name") {
			inGroup, inPriv = false, true
			continue
		}
		if lower == "" || strings.HasPrefix(lower, "---") || strings.HasPrefix(lower, "user name") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		if inGroup && strings.ContainsAny(parts[0], `\`) {
			groups = append(groups, parts[0])
		}
		if inPriv && strings.HasPrefix(parts[0], "Se") {
			privs = append(privs, parts[0])
		}
	}
	var items []LootItem
	if len(groups) > 0 {
		items = append(items, LootItem{Type: "groups", Source: "whoami /all", Timestamp: ts,
			Fields: []LootField{{Name: "groups", Value: strings.Join(groups, ", ")}}})
	}
	if len(privs) > 0 {
		items = append(items, LootItem{Type: "privileges", Source: "whoami /all", Timestamp: ts,
			Fields: []LootField{{Name: "privileges", Value: strings.Join(privs, ", ")}}})
	}
	return items
}

func parseUname(output, ts string) []LootItem {
	val := strings.TrimSpace(output)
	if val == "" {
		return nil
	}
	return singleLootItem("system_info", "uname -a", ts, lootFields("kernel", val))
}

func parseWindowsVer(output, ts string) []LootItem {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(strings.ToLower(line), "windows") || strings.Contains(line, "Version") {
			if line != "" {
				return singleLootItem("system_info", "ver", ts, lootFields("os_version", line))
			}
		}
	}
	return nil
}

var netUserWordRe = regexp.MustCompile(`\b[A-Za-z][A-Za-z0-9_\-\.]{2,19}\b`)

func parseNetUser(output, ts string) []LootItem {
	var users []string
	inList := false
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "---") {
			inList = true
			continue
		}
		if !inList || line == "" || strings.HasPrefix(strings.ToLower(line), "the command") {
			continue
		}
		for _, u := range netUserWordRe.FindAllString(line, -1) {
			users = append(users, u)
		}
	}
	return singleLootItem("user_list", "net user", ts,
		lootFields("users", strings.Join(users, ", ")))
}

var passwdLineRe = regexp.MustCompile(`^([^:]+):[^:]*:(\d+):(\d+):[^:]*:([^:]+):([^:\n]+)`)

func parseEtcPasswd(output, ts string) []LootItem {
	var items []LootItem
	for _, line := range strings.Split(output, "\n") {
		m := passwdLineRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		uid := 0
		fmt.Sscanf(m[2], "%d", &uid)
		if uid != 0 && uid < 1000 {
			continue // skip system accounts except root
		}
		items = append(items, LootItem{
			Type: "user_account", Source: "cat /etc/passwd", Timestamp: ts,
			Fields: lootFields("username", m[1], "uid", m[2], "gid", m[3],
				"home", m[4], "shell", strings.TrimSpace(m[5])),
		})
	}
	return items
}

func parseSysteminfo(output, ts string) []LootItem {
	return singleLootItem("system_info", "systeminfo", ts, lootFields(
		"hostname",   extractLineValue(output, "Host Name"),
		"os",         extractLineValue(output, "OS Name"),
		"os_version", extractLineValue(output, "OS Version"),
		"arch",       extractLineValue(output, "System Type"),
		"domain",     extractLineValue(output, "Domain"),
		"patches",    extractLineValue(output, "Hotfix(es)"),
	))
}

var envCredRe = regexp.MustCompile(`(?i)(pass|password|secret|key|token|api|credential)`)

func parseEnv(output, ts string) []LootItem {
	var interesting []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && envCredRe.MatchString(line) {
			interesting = append(interesting, line)
		}
	}
	return singleLootItem("environment", "env", ts,
		lootFields("interesting_vars", strings.Join(interesting, "\n")))
}

var arpEntryRe = regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([0-9a-fA-F:]{17})`)

func parseArp(output, ts string) []LootItem {
	var hosts []string
	for _, line := range strings.Split(output, "\n") {
		m := arpEntryRe.FindStringSubmatch(line)
		if m != nil {
			hosts = append(hosts, fmt.Sprintf("%s (%s)", m[1], m[2]))
		}
	}
	return singleLootItem("network_hosts", "arp", ts,
		lootFields("hosts", strings.Join(hosts, ", ")))
}

func parseMimipenguin(output, ts string) []LootItem {
	var creds []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && strings.Contains(line, ":") && !strings.HasPrefix(line, "[") {
			creds = append(creds, line)
		}
	}
	return singleLootItem("credential", "mimipenguin", ts,
		lootFields("credentials", strings.Join(creds, "\n")))
}

func parseLsaSecrets(output, ts string) []LootItem {
	var secrets []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[+]") || strings.HasPrefix(line, "[-]") {
			secrets = append(secrets, line)
		}
	}
	return singleLootItem("credential", "lsa_secrets", ts,
		lootFields("secrets", strings.Join(secrets, "\n")))
}

func parseCachedump(output, ts string) []LootItem {
	var creds []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, ":$DCC2$") || strings.Contains(line, "Username:") {
			creds = append(creds, line)
		}
	}
	return singleLootItem("credential", "cachedump", ts,
		lootFields("cached_credentials", strings.Join(creds, "\n")))
}
