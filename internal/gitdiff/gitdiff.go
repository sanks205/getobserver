// Package gitdiff resolves which lines changed in a git working tree, so a scan
// can be scoped to "only what changed" — for example, reviewing exactly what you
// (or an AI assistant) just wrote, rather than re-scanning the whole project.
//
// It shells out to the `git` binary (stdlib os/exec only, no cgo, no git library)
// and parses a --unified=0 diff into per-file changed line ranges.
package gitdiff

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Mode selects which set of changes to consider.
type Mode int

const (
	// WorkingTree = everything changed vs HEAD (staged + unstaged) plus untracked
	// files. This is "what does my working copy differ from the last commit".
	WorkingTree Mode = iota
	// Staged = only staged changes (git diff --cached). Used by the pre-commit hook.
	Staged
	// BaseRef = changes introduced on the current branch since it diverged from a
	// base ref (git diff base...HEAD). Used for PR-style review.
	BaseRef
)

// ErrNotGitRepo is returned when the target is not inside a git work tree (or the
// git binary is not installed).
var ErrNotGitRepo = errors.New("not a git repository (or git is not installed)")

// Changes records which lines changed, keyed by forward-slash file path relative
// to the repo root.
type Changes struct {
	files map[string]*lineSet
}

type lineSet struct {
	all    bool     // whole file is new/added: every line counts as changed
	ranges [][2]int // inclusive [start,end] line ranges in the new file
}

// Contains reports whether file+line was changed. line is 1-based; a line <= 0
// (a file-level finding with no specific line) matches if the file changed at all.
func (c *Changes) Contains(file string, line int) bool {
	if c == nil {
		return false
	}
	ls := c.files[normPath(file)]
	if ls == nil {
		return false
	}
	if ls.all || line <= 0 {
		return true
	}
	for _, r := range ls.ranges {
		if line >= r[0] && line <= r[1] {
			return true
		}
	}
	return false
}

// FileCount is the number of files with changes.
func (c *Changes) FileCount() int {
	if c == nil {
		return 0
	}
	return len(c.files)
}

// Empty reports whether no files changed.
func (c *Changes) Empty() bool { return c.FileCount() == 0 }

func normPath(p string) string {
	return strings.TrimPrefix(filepath.ToSlash(p), "./")
}

// Resolve computes the changed lines for the git repo containing root, using the
// given mode. base is used only when mode == BaseRef.
func Resolve(root string, mode Mode, base string) (*Changes, error) {
	if _, err := run(root, "rev-parse", "--is-inside-work-tree"); err != nil {
		return nil, ErrNotGitRepo
	}

	var args []string
	switch mode {
	case Staged:
		args = []string{"diff", "--cached", "--unified=0", "--no-color", "--no-ext-diff"}
	case BaseRef:
		args = []string{"diff", "--unified=0", "--no-color", "--no-ext-diff", base + "...HEAD"}
	default: // WorkingTree
		args = []string{"diff", "--unified=0", "--no-color", "--no-ext-diff", "HEAD"}
	}
	out, err := run(root, args...)
	if err != nil {
		return nil, err
	}

	c := &Changes{files: map[string]*lineSet{}}
	parseUnifiedDiff(out, c)

	// Working-tree mode also folds in brand-new (untracked) files — exactly the
	// files an AI assistant tends to create — treating every line as changed.
	if mode == WorkingTree {
		if ut, err := run(root, "ls-files", "--others", "--exclude-standard"); err == nil {
			for _, f := range strings.Split(strings.TrimSpace(ut), "\n") {
				if f = strings.TrimSpace(f); f != "" {
					c.files[normPath(f)] = &lineSet{all: true}
				}
			}
		}
	}
	return c, nil
}

// hunkRe captures the new-file side of a unified-diff hunk header:
// "@@ -old[,n] +start[,count] @@". Group 1 = start, group 2 = count (may be empty → 1).
var hunkRe = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@`)

func parseUnifiedDiff(diff string, c *Changes) {
	sc := bufio.NewScanner(strings.NewReader(diff))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	var cur string
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "+++ "):
			p := strings.TrimPrefix(line, "+++ ")
			if p == "/dev/null" { // the new side of a deleted file
				cur = ""
				continue
			}
			cur = normPath(strings.TrimPrefix(p, "b/"))
			if c.files[cur] == nil {
				c.files[cur] = &lineSet{}
			}
		case strings.HasPrefix(line, "@@"):
			m := hunkRe.FindStringSubmatch(line)
			if m == nil || cur == "" {
				continue
			}
			start, _ := strconv.Atoi(m[1])
			count := 1
			if m[2] != "" {
				count, _ = strconv.Atoi(m[2])
			}
			if count == 0 { // pure deletion: nothing added on the new side
				continue
			}
			ls := c.files[cur]
			ls.ranges = append(ls.ranges, [2]int{start, start + count - 1})
		}
	}
}

func run(root string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}
