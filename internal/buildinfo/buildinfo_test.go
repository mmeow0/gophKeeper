package buildinfo

import (
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	Set("1.2.3", "2026-05-26", "abc123")
	if got := String(); !strings.Contains(got, "1.2.3") || !strings.Contains(got, "2026-05-26") {
		t.Fatalf("String() = %q", got)
	}
}
