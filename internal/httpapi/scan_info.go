package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"

	"YOUR/MODULE/PATH/internal/config"
	"YOUR/MODULE/PATH/internal/taskstore"
)

func ScanInfoHandler(paths config.UploadPaths, store *taskstore.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}

		t, err := store.Get(r.Context(), id)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				http.Error(w, "task not found", http.StatusNotFound)
				return
			}
			http.Error(w, "task not found", http.StatusNotFound)
			return
		}

		switch t.Status {
		case taskstore.StatusQueued, taskstore.StatusRunning:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"zip_id": id,
				"status": string(t.Status),
				"ts":     t.Timestamp,
			})
			return

		case taskstore.StatusFailed:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"zip_id": id,
				"status": "failed",
				"error":  t.Error,
				"ts":     t.Timestamp,
			})
			return

		case taskstore.StatusDone:
			resPath := filepath.Join(paths.Results, "result-"+id+".json")
			b, err := os.ReadFile(resPath)
			if err != nil {
				http.Error(w, "result not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(b)
			return

		default:
			http.Error(w, "unknown status", http.StatusInternalServerError)
			return
		}
	}
}
