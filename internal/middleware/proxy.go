// Package middleware provides HTTP middleware for the Emby Authentication Bridge.
package middleware

import (
	"log/slog"
	"net"
	"net/http"
)

// TrustedProxy returns middleware that rejects requests from IPs not in the trusted list.
func TrustedProxy(trusted []*net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				slog.Warn("failed to parse remote address",
					"remote_addr", r.RemoteAddr,
					"error", err,
				)
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			ip := net.ParseIP(host)
			if ip == nil {
				slog.Warn("failed to parse IP from remote address",
					"remote_addr", r.RemoteAddr,
					"host", host,
				)
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			if !IsIPTrusted(ip, trusted) {
				slog.Warn("request from untrusted IP rejected",
					"source_ip", ip.String(),
				)
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// IsIPTrusted checks whether an IP is contained in any of the trusted networks.
func IsIPTrusted(ip net.IP, trusted []*net.IPNet) bool {
	for _, network := range trusted {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
