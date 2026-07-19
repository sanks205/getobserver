//go:build !windows

package main

import (
	"os/exec"
	"runtime"
)

// launchedByDoubleClick is Windows-only behavior; elsewhere the CLI always shows
// help when run with no arguments.
func launchedByDoubleClick() bool { return false }

// openBrowser best-effort opens url in the default browser (macOS / Linux).
func openBrowser(url string) {
	bin := "xdg-open"
	if runtime.GOOS == "darwin" {
		bin = "open"
	}
	_ = exec.Command(bin, url).Start()
}
