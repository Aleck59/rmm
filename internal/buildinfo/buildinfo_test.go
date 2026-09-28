package buildinfo

import (
	"runtime"
	"testing"
)

func TestGet(t *testing.T) {
	got := Get()
	if got.Version != Version {
		t.Errorf("Version = %q, want %q", got.Version, Version)
	}
	if got.Go != runtime.Version() {
		t.Errorf("Go = %q, want %q", got.Go, runtime.Version())
	}
	if got.Platform != runtime.GOOS+"/"+runtime.GOARCH {
		t.Errorf("Platform = %q, want %q", got.Platform, runtime.GOOS+"/"+runtime.GOARCH)
	}
}
