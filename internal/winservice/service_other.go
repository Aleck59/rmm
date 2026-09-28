//go:build !windows

package winservice

import "errors"

// errUnsupported is returned by the service-management calls off Windows.
var errUnsupported = errors.New("windows service management is only available on Windows")

// IsService always reports false off Windows.
func IsService() (bool, error) { return false, nil }

// Install is unsupported off Windows.
func Install(_ Config, _ string) error { return errUnsupported }

// Remove is unsupported off Windows.
func Remove(_ string) error { return errUnsupported }

// Start is unsupported off Windows.
func Start(_ string) error { return errUnsupported }

// Stop is unsupported off Windows.
func Stop(_ string) error { return errUnsupported }

// RunAsService is never reached off Windows because IsService reports false;
// it is defined so callers compile on every platform.
func RunAsService(_ string, _ RunFunc) error { return errUnsupported }
