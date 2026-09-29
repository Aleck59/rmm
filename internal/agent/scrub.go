package agent

import (
	"errors"
	"os"
	"strings"
)

// scrubEnrollToken blanks enroll_token in agent.yaml after a successful
// enrollment. It edits only that line, preserving comments, key order and
// line endings of a file that an administrator may have written by hand.
func scrubEnrollToken(path string) error {
	if path == "" {
		return nil
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	changed := false
	for i, line := range lines {
		cr := strings.HasSuffix(line, "\r")
		body := strings.TrimSuffix(line, "\r")
		trimmed := strings.TrimLeft(body, " \t")
		if !strings.HasPrefix(trimmed, "enroll_token:") {
			continue
		}
		indent := body[:len(body)-len(trimmed)]
		lines[i] = indent + "enroll_token: '' # removed after successful enrollment"
		if cr {
			lines[i] += "\r"
		}
		changed = true
	}
	if !changed {
		return nil
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), info.Mode().Perm())
}
