//go:build windows

package main

import (
	"os/exec"
	"syscall"
	"unsafe"
)

// openBrowser best-effort opens url in the default browser (Windows).
func openBrowser(url string) {
	_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
}

// launchedByDoubleClick reports whether the process was started by double-clicking
// in Explorer rather than from an existing terminal. When double-clicked, Windows
// allocates a fresh console attached only to this process, so GetConsoleProcessList
// returns 1; launched from a shell, the shell's process is also attached (>= 2).
func launchedByDoubleClick() bool {
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("GetConsoleProcessList")
	var pids [4]uint32
	n, _, _ := proc.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	return n == 1
}
