//go:build !windows

package agent

// Off Windows (development only) the state file is protected by its 0600
// permissions alone; there is no DPAPI equivalent in scope.
func protect(data []byte) ([]byte, error)   { return data, nil }
func unprotect(data []byte) ([]byte, error) { return data, nil }
