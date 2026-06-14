package handler_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/handler"
)

func TestLogout_EvictsSessionAndRedirects(t *testing.T) {
	var invalidatedSub string
	invalidate := func(sub string) {
		invalidatedSub = sub
	}
	extractSub := func(r *http.Request) string {
		return r.Header.Get("X-Forwarded-Sub")
	}

	h := handler.Logout(extractSub, invalidate)

	req := httptest.NewRequest(http.MethodPost, "/Sessions/Logout", nil)
	req.Header.Set("X-Forwarded-Sub", "sub-logout-user")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	// Should invalidate the session for the correct sub.
	if invalidatedSub != "sub-logout-user" {
		t.Errorf("expected invalidated sub %q, got %q", "sub-logout-user", invalidatedSub)
	}

	// Should redirect to root with 302.
	if rec.Code != http.StatusFound {
		t.Errorf("expected status %d, got %d", http.StatusFound, rec.Code)
	}
	location := rec.Header().Get("Location")
	if location != "/" {
		t.Errorf("expected redirect to '/', got %q", location)
	}
}

func TestLogout_NoSubStillRedirects(t *testing.T) {
	var invalidateCalled bool
	invalidate := func(sub string) {
		invalidateCalled = true
	}
	extractSub := func(r *http.Request) string {
		return "" // No sub available.
	}

	h := handler.Logout(extractSub, invalidate)

	req := httptest.NewRequest(http.MethodPost, "/Sessions/Logout", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	// Should NOT call invalidate when sub is empty.
	if invalidateCalled {
		t.Error("invalidateSession should not be called when sub is empty")
	}

	// Should still redirect to root.
	if rec.Code != http.StatusFound {
		t.Errorf("expected status %d, got %d", http.StatusFound, rec.Code)
	}
	location := rec.Header().Get("Location")
	if location != "/" {
		t.Errorf("expected redirect to '/', got %q", location)
	}
}

func TestLogout_UsesExtractSubFromRequest(t *testing.T) {
	var invalidatedSub string
	invalidate := func(sub string) {
		invalidatedSub = sub
	}

	// Use the real ExtractSubFromRequest function.
	h := handler.Logout(handler.ExtractSubFromRequest, invalidate)

	req := httptest.NewRequest(http.MethodPost, "/Sessions/Logout", nil)
	req.Header.Set("X-Forwarded-Sub", "real-sub-123")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if invalidatedSub != "real-sub-123" {
		t.Errorf("expected invalidated sub %q, got %q", "real-sub-123", invalidatedSub)
	}
	if rec.Code != http.StatusFound {
		t.Errorf("expected status %d, got %d", http.StatusFound, rec.Code)
	}
}
