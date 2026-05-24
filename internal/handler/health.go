package handler

import (
	"encoding/json"
	"net/http"

	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/db"
	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/emby"
)

// healthResponse represents the JSON body returned by the health check endpoint.
type healthResponse struct {
	Status string `json:"status"`
	DB     string `json:"db"`
	Emby   string `json:"emby"`
}

// Health returns an http.HandlerFunc for the /health endpoint.
// It checks SQLite connectivity and Emby API connectivity.
// Returns 200 OK when both are healthy, 503 Service Unavailable when either is unreachable.
func Health(database *db.DB, embyClient *emby.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		dbHealthy := database.IsHealthy()
		embyHealthy := embyClient.Ping(r.Context()) == nil

		resp := healthResponse{
			Status: "healthy",
			DB:     "up",
			Emby:   "up",
		}

		if !dbHealthy {
			resp.DB = "down"
		}
		if !embyHealthy {
			resp.Emby = "down"
		}

		w.Header().Set("Content-Type", "application/json")

		if !dbHealthy || !embyHealthy {
			resp.Status = "unhealthy"
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}

		_ = json.NewEncoder(w).Encode(resp)
	}
}
