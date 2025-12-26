package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/google/uuid"

	"sbom-serv/internal/config"
	"sbom-serv/internal/taskstore"
)

func UploadZipHandler(paths config.UploadPaths, store *taskstore.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.Body == nil {
			http.Error(w, "empty body", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		id := uuid.NewString()
		zipPath := filepath.Join(paths.Zips, "zip-"+id+".zip")

		if err := saveBodyAtomic(zipPath, r.Body); err != nil {
			http.Error(w, "failed to save zip: "+err.Error(), http.StatusBadRequest)
			return
		}

		if err := store.Enqueue(r.Context(), id); err != nil {
			_ = os.Remove(zipPath)
			http.Error(w, "failed to enqueue: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"zip_id": id,
			"status": "queued",
		})
	}
}

func saveBodyAtomic(finalPath string, body io.Reader) error {
	if err := os.MkdirAll(filepath.Dir(finalPath), 0o755); err != nil {
		return err
	}

	tmpDir := filepath.Dir(finalPath)
	f, err := os.CreateTemp(tmpDir, ".upload-*.tmp")
	if err != nil {
		return err
	}
	tmpName := f.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := io.Copy(f, body); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmpName, finalPath); err != nil {
		return err
	}

	if _, err := os.Stat(finalPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.New("zip not created")
		}
		return err
	}
	return nil
}
