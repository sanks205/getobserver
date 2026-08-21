// Package engineutil runs external analysis engines (Semgrep, PHPStan, Bandit,
// gosec, ESLint) as subprocesses with a hard, tree-aware timeout.
//
// Why this exists: the naive `exec.CommandContext(...).Output()` pattern only
// kills the IMMEDIATE child process when the context is cancelled. Several
// engines spawn a process tree — most notably Semgrep (semgrep -> python ->
// semgrep-core) — that inherits the stdout pipe. Killing just the launcher leaves
// the tree running and holding the pipe open, so Output() blocks forever and the
// whole scan hangs past its deadline. Run() instead kills the entire descendant
// tree (taskkill /T on Windows, process-group kill on Unix) so the timeout is
// actually enforced and a hung engine cannot keep a scan alive indefinitely.
package engineutil

import (
	"context"
	"io"
	"os/exec"
)

// Run executes name with args and returns its stdout. If dir is non-empty it is
// used as the working directory. When ctx is cancelled (e.g. a scan timeout), the
// entire descendant process tree is terminated — not just the immediate child —
// so the scan cannot be stranded by a long-lived grandchild holding the pipe.
func Run(ctx context.Context, dir, name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Stderr = io.Discard
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	prepareCmd(cmd) // OS-specific: process group on Unix, no-op on Windows
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			killTree(cmd.Process)
		case <-done:
		}
	}()
	out, rerr := io.ReadAll(stdout)
	werr := cmd.Wait()
	close(done)
	if rerr != nil && len(out) == 0 {
		return nil, rerr
	}
	// Only surface an error when we got no output at all; engines commonly exit
	// non-zero when they find issues, which is success for us.
	if werr != nil && len(out) == 0 {
		return nil, werr
	}
	return out, nil
}

// prepareCmd and killTree are defined per-OS in engineutil_windows.go /
// engineutil_unix.go so this file compiles everywhere.
// killTree terminates pid and all of its descendants.
