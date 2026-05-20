package middleware_test

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/middleware"
)

func parseCIDR(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("failed to parse CIDR %q: %v", cidr, err)
	}
	return network
}

func TestIsIPTrusted(t *testing.T) {
	trusted := []*net.IPNet{
		parseCIDR(t, "10.0.0.0/8"),
		parseCIDR(t, "192.168.1.0/24"),
		parseCIDR(t, "172.16.0.1/32"),
	}

	tests := []struct {
		name    string
		ip      string
		trusted bool
	}{
		{"IP in 10.0.0.0/8", "10.1.2.3", true},
		{"IP in 192.168.1.0/24", "192.168.1.100", true},
		{"exact match 172.16.0.1/32", "172.16.0.1", true},
		{"IP outside all ranges", "8.8.8.8", false},
		{"IP just outside /24", "192.168.2.1", false},
		{"IP just outside /32", "172.16.0.2", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP %q", tt.ip)
			}
			got := middleware.IsIPTrusted(ip, trusted)
			if got != tt.trusted {
				t.Errorf("IsIPTrusted(%s) = %v, want %v", tt.ip, got, tt.trusted)
			}
		})
	}
}

func TestIsIPTrusted_EmptyList(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	if middleware.IsIPTrusted(ip, nil) {
		t.Error("expected false for nil trusted list")
	}
	if middleware.IsIPTrusted(ip, []*net.IPNet{}) {
		t.Error("expected false for empty trusted list")
	}
}

func TestTrustedProxy_AllowsTrustedIP(t *testing.T) {
	trusted := []*net.IPNet{parseCIDR(t, "127.0.0.0/8")}

	handler := middleware.TrustedProxy(trusted)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestTrustedProxy_RejectsUntrustedIP(t *testing.T) {
	trusted := []*net.IPNet{parseCIDR(t, "10.0.0.0/8")}

	handler := middleware.TrustedProxy(trusted)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called for untrusted IP")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1:54321"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

func TestTrustedProxy_InvalidRemoteAddr(t *testing.T) {
	trusted := []*net.IPNet{parseCIDR(t, "10.0.0.0/8")}

	handler := middleware.TrustedProxy(trusted)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called for invalid remote addr")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "not-a-valid-addr"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}
