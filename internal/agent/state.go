package agent

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// stateFileName holds the device identity. On Windows its content is
// encrypted with DPAPI (machine scope): other processes on the same PC are
// kept out by the directory ACL, and a copy is useless on another computer.
const stateFileName = "state.bin"

// State is the agent's persistent identity.
type State struct {
	AgentUID    string `json:"agent_uid"`
	DeviceID    int64  `json:"device_id,omitempty"`
	DeviceToken string `json:"device_token,omitempty"`
}

// Enrolled reports whether the agent holds a device token.
func (s State) Enrolled() bool { return s.DeviceToken != "" }

func loadState(dir string) (State, error) {
	var st State
	data, err := os.ReadFile(filepath.Join(dir, stateFileName))
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, fmt.Errorf("read state: %w", err)
	}
	plain, err := unprotect(data)
	if err != nil {
		return st, fmt.Errorf("decrypt state: %w", err)
	}
	if err := json.Unmarshal(plain, &st); err != nil {
		return st, fmt.Errorf("decode state: %w", err)
	}
	return st, nil
}

func saveState(dir string, st State) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	plain, err := json.Marshal(st)
	if err != nil {
		return err
	}
	data, err := protect(plain)
	if err != nil {
		return fmt.Errorf("encrypt state: %w", err)
	}
	// Write-then-rename so a crash never leaves a truncated identity file.
	tmp := filepath.Join(dir, stateFileName+".tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, stateFileName)); err != nil {
		return fmt.Errorf("replace state: %w", err)
	}
	return nil
}

// newUUID returns a random (version 4) UUID string.
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40 // version 4
	b[8] = b[8]&0x3f | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
