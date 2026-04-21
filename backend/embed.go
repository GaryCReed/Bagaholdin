package main

import "embed"

//go:embed all:ui
var staticFiles embed.FS
