//go:build windows

package engineutil

import (
	"os"
	"os/exec"
	"strconv"
)

// prepareCmd is a no-op on Windows; taskkill /T (in killTree) already walks the
// whole descendant tree, so no process-group setup is needed.
func prepareCmd(cmd *exec.Cmd) {}

// killTree terminates pid and all of its descendants. /T walks the child tree and
// /F forces termination, so a hung engine (e.g. semgrep -> python -> semgrep-core)
// cannot keep the scan alive past its timeout.
func killTree(p *os.Process) {
	if p == nil {
		return
	}
	_ = exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(p.Pid)).Run()
}
