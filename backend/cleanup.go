package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

func setupCleanup() {
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		<-ch
		removeTempArtefacts()
		os.Exit(0)
	}()
}

func removeTempArtefacts() {
	patterns := []string{
		"/tmp/msf-scans",
		"/tmp/msf-notes-*.txt",
		"/tmp/loot-*.xml",
		"/tmp/hydra-*.txt",
		"/tmp/sqlmap-*",
		"/tmp/ferox-*",
		"/tmp/hashcat-*",
		"/tmp/wifi-cap-*",
	}
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		for _, m := range matches {
			if err := os.RemoveAll(m); err == nil {
				fmt.Printf("[cleanup] removed %s\n", m)
			}
		}
	}
}
