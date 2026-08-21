//go:build !windows

package engineutil

import (
	"os"
	"os/exec"
	"syscall"
)

// prepareCmd puts the child in its own process group so killTree can target the
// whole tree via a single group kill.
func prepareCmd(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killTree kills the entire process group rooted at pid. A negative pid targets
// the group created with Setpgid, taking down any grandchildren (e.g. the node
// subprocess an ESLint plugin spawns).
func killTree(p *os.Process) {
	if p == nil {
		return
	}
	_ = syscall.Kill(-p.Pid, syscall.SIGKILL)
}
