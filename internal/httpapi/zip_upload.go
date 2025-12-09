package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"scaserv/sbom-serv/internal/config"
	"scaserv/sbom-serv/internal/storage"
	"strings"

	"github.com/google/uuid"
)

const (
	maxZipUploadBytes = 1500 << 20
)

func validateZipType(w http.ResponseWriter, r *http.Request) (io.Reader, bool) {
	ct := r.Header.Get("Content-Type")
	ct = strings.ToLower(strings.TrimSpace(strings.Split(ct, ";")[0]))
	if ct != "application/zip" {
		http.Error(w, "unsupported content-type", http.StatusUnsupportedMediaType)
		return nil, false
	}

	const sniffBytes = 6
	buf := make([]byte, sniffBytes)

	n, err := io.ReadFull(r.Body, buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return nil, false
	}
	buf = buf[:n]
	if len(buf) == 0 {
		http.Error(w, "empty body", http.StatusBadRequest)
		return nil, false
	}
	if !CheckMagicBytes(buf) {
		http.Error(w, "invalid file type", http.StatusBadRequest)
		return nil, false
	}
	return io.MultiReader(bytes.NewReader(buf), r.Body), true
}

func CheckMagicBytes(first []byte) bool {
	sigs := [][]byte{
		{'P', 'K', 0x03, 0x04},
		{'P', 'K', 0x05, 0x06},
		{'P', 'K', 0x07, 0x08},
	}
	for _, s := range sigs {
		if bytes.HasPrefix(first, s) {
			return true
		}
	}
	return false
}

func UploadZipHandler(paths config.UploadPaths) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxZipUploadBytes)
		defer r.Body.Close()

		bodyReader, ok := validateZipType(w, r)
		if !ok {
			return
		}

		id := uuid.New().String()

		if err := store.Enqueue(r.Context(), id); err != nil {
			_ = os.Remove(zipPath)
			http.Error(w, "failed to enqueue task", http.StatusInternalServerError)
			return
		}

		zipPath := filepath.Join(paths.Zips, "zip-"+id+".zip")


		if err := storage.SaveStreamAtomic(zipPath, bodyReader); err != nil {
			http.Error(w, "failed to save zip", http.StatusBadRequest)
			return
		}


		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "queued",
			"zip_id": id,
		})
	}
}
