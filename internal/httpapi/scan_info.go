package httpapi

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"scaserv/sbom-serv/internal/config"
	"scaserv/sbom-serv/internal/storage"
)

func ScanInfoHandler(paths config.UploadPaths) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}

		st, err := store.Get(r.Context(), id)
			if err != nil {
			http.Error(w, "task not found", http.StatusNotFound)
			return
		}

		resPath := filepath.Join(paths.Results, "result-"+id+".json")


		switch st.Status {
		case "queued", "running":
			w.WriteHeader(http.StatusAccepted)
			storage.WriteJSON(w, map[string]any{"zip_id": id, "status": st.Status})
		case "failed":
			storage.WriteJSON(w, map[string]any{"zip_id": id, "status": "failed", "error": st.Error})
		case "done":
			b, err := os.ReadFile(resPath)
			if err != nil {
				http.Error(w, "result not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(b)
		default:
			http.Error(w, "unknown status", http.StatusInternalServerError)
		}
	}
}
