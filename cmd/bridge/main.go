// Package main is the entry point for the Emby Authentication Bridge service.
package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/config"
	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/db"
	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/emby"
	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/handler"
	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/middleware"
)

func main() {
	// Set up structured logging.
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// Load configuration from environment variables.
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load configuration: %v", err)
	}
	slog.Info("configuration loaded",
		"bridge_port", cfg.BridgePort,
		"emby_api_url", cfg.EmbyAPIURL,
		"database_path", cfg.DatabasePath,
		"template_user_name", cfg.TemplateUserName,
		"watchparty_url", cfg.WatchpartyURL,
	)

	// Open database.
	database, err := db.Open(cfg.DatabasePath)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer func() { _ = database.Close() }()
	slog.Info("database opened", "path", cfg.DatabasePath)

	// Create Emby client.
	embyClient := emby.NewClient(cfg.EmbyAPIURL, cfg.EmbyAPIKey)

	// Wait for Emby to become available and validate template user.
	// Timeout after 60 seconds to avoid hanging indefinitely on misconfiguration.
	var templateUser *emby.User
	startupDeadline := time.Now().Add(60 * time.Second)
	for {
		if time.Now().After(startupDeadline) {
			log.Fatalf("timed out waiting for Emby to become available after 60s")
		}
		var err error
		templateUser, err = embyClient.FindUserByName(context.Background(), cfg.TemplateUserName)
		if err != nil {
			slog.Warn("waiting for Emby to become available",
				"error", err,
			)
			time.Sleep(5 * time.Second)
			continue
		}
		if templateUser == nil {
			log.Fatalf("template user %q not found in Emby", cfg.TemplateUserName)
		}
		break
	}
	slog.Info("template user validated",
		"template_user_name", cfg.TemplateUserName,
		"template_user_id", templateUser.ID,
	)

	// Fetch template user's full policy to use as base for new users.
	templatePolicy, err := embyClient.GetUserPolicy(context.Background(), templateUser.ID)
	if err != nil {
		log.Fatalf("failed to fetch template user policy: %v", err)
	}
	slog.Info("template user policy loaded", "template_user_id", templateUser.ID)

	// Create middleware functions.
	trustedProxy := middleware.TrustedProxy(cfg.TrustedProxies)
	auth := middleware.Auth(embyClient, database, templateUser.ID, templatePolicy, cfg.OIDCIssuerURL)

	// Create proxy handler.
	proxyHandler := handler.Proxy(cfg.EmbyAPIURL, middleware.InvalidateSession)

	// Register routes.
	mux := http.NewServeMux()

	// /health — no middleware (accessible without trusted proxy check).
	mux.HandleFunc("GET /health", handler.Health(database, embyClient))

	// /account — trusted proxy check only (account page reads sub from headers/JWT).
	mux.Handle("GET /account", trustedProxy(http.HandlerFunc(handler.Account(database))))

	// /api/credentials — JSON endpoint for authenticated user's Emby credentials.
	mux.Handle("GET /api/credentials", trustedProxy(auth(http.HandlerFunc(handler.Credentials(database)))))

	// / — redirect to /web/index.html (which handles credential injection).
	mux.Handle("GET /{$}", trustedProxy(auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/web/index.html", http.StatusFound)
	}))))

	// /web/index.html — fetch real Emby page, inject credentials inline.
	mux.Handle("GET /web/index.html", trustedProxy(auth(http.HandlerFunc(handler.InjectCredentials(cfg.EmbyAPIURL)))))

	// /watchparty/ — optional watchparty integration.
	// The login handler performs server-side pre-auth on the first request
	// (no bridge cookie present), then proxies all subsequent requests directly.
	if cfg.WatchpartyEnabled() {
		watchpartyProxy := handler.WatchpartyProxy(cfg.WatchpartyURL)
		watchpartyLogin := handler.WatchpartyLogin(database, cfg.WatchpartyURL, watchpartyProxy)
		mux.Handle("/watchparty/", trustedProxy(auth(watchpartyLogin)))
	}

	if cfg.WatchpartyEnabled() {
		slog.Info("watchparty feature enabled", "watchparty_url", cfg.WatchpartyURL)
	} else {
		slog.Info("watchparty feature disabled")
	}

	// /* — full middleware chain: trustedProxy → auth → proxy.
	mux.Handle("/", trustedProxy(auth(proxyHandler)))

	// Create HTTP server with timeouts.
	addr := fmt.Sprintf(":%d", cfg.BridgePort)
	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start server in a goroutine.
	go func() {
		slog.Info("starting server", "addr", addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	// Wait for interrupt signal for graceful shutdown.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	slog.Info("received shutdown signal", "signal", sig.String())

	// Give in-flight requests 15 seconds to complete.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("server shutdown error", "error", err)
	}

	slog.Info("server stopped gracefully")
}
