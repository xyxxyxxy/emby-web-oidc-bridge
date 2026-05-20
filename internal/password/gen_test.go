package password_test

import (
	"regexp"
	"testing"

	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/password"
)

func TestGenerate_Length(t *testing.T) {
	pw := password.Generate()
	if len(pw) != 8 {
		t.Fatalf("expected length 8, got %d: %q", len(pw), pw)
	}
}

func TestGenerate_Charset(t *testing.T) {
	re := regexp.MustCompile(`^[a-z0-9]{8}$`)
	pw := password.Generate()
	if !re.MatchString(pw) {
		t.Fatalf("password %q does not match [a-z0-9]{8}", pw)
	}
}

func TestGenerate_Uniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		pw := password.Generate()
		seen[pw] = true
	}
	// With 36^8 possible passwords, 100 generations should all be unique
	if len(seen) < 90 {
		t.Fatalf("expected mostly unique passwords, got only %d unique out of 100", len(seen))
	}
}
