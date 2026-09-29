package tokens

import (
	"bytes"
	"strings"
	"testing"
)

func TestGenerateAndValidate(t *testing.T) {
	tok, err := Generate(DevicePrefix)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok, DevicePrefix) {
		t.Fatalf("token %q lacks prefix", tok)
	}
	if !Valid(tok, DevicePrefix) {
		t.Fatalf("freshly generated token is not Valid")
	}
	if Valid(tok, EnrollPrefix) {
		t.Fatalf("device token must not validate as enrollment token")
	}
	other, _ := Generate(DevicePrefix)
	if tok == other {
		t.Fatalf("two generated tokens are equal")
	}
}

func TestValidRejectsMalformed(t *testing.T) {
	for _, tok := range []string{"", "imagt_", "imagt_short", "imagt_" + strings.Repeat("!", 43), "Bearer imagt_x"} {
		if Valid(tok, DevicePrefix) {
			t.Errorf("Valid(%q) = true, want false", tok)
		}
	}
}

func TestHashIsStableAndDistinct(t *testing.T) {
	a, b := Hash("imagt_a"), Hash("imagt_b")
	if !bytes.Equal(a, Hash("imagt_a")) {
		t.Fatal("hash not deterministic")
	}
	if bytes.Equal(a, b) || len(a) != 32 {
		t.Fatalf("unexpected hash properties: len=%d", len(a))
	}
}

func TestDisplayPrefix(t *testing.T) {
	tok, _ := Generate(EnrollPrefix)
	if got := DisplayPrefix(tok); got != tok[:10] {
		t.Fatalf("DisplayPrefix = %q, want %q", got, tok[:10])
	}
	if got := DisplayPrefix("garbage"); got != "" {
		t.Fatalf("DisplayPrefix(garbage) = %q, want empty", got)
	}
}
