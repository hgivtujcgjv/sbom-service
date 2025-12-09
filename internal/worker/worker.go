package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"scaserv/sbom-serv/internal/config"
	"scaserv/sbom-serv/internal/storage"
	"strings"
	"time"
)

func processTask(ctx context.Context, zipPath, resultPath string) error {
	tmp := resultPath + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	defer out.Close()

	cmd := exec.CommandContext(ctx, "syft", zipPath, "-o", "json")

	cmd.Stdout = out
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("syft failed: %v: %s", err, stderr.String())
	}

	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}

	return os.Rename(tmp, resultPath)
}

func StartWorker(ctx context.Context, paths config.UploadPaths, maxParallel int) {
	if maxParallel <= 0 {
		maxParallel = 4
	}
	sem := make(chan struct{}, maxParallel)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			statusFiles, _ := filepath.Glob(filepath.Join(paths.Status, "status-*.json"))

			for _, stPath := range statusFiles {
				data, err := os.ReadFile(stPath)
				if err != nil {
					continue
				}

				var st storage.TaskStatus
				if err := json.Unmarshal(data, &st); err != nil {
					continue
				}
				if st.Status != "queued" {
					continue
				}

				base := filepath.Base(stPath)
				id := strings.TrimSuffix(strings.TrimPrefix(base, "status-"), ".json")

				zipPath := filepath.Join(paths.Zips, "zip-"+id+".zip")
				resultPath := filepath.Join(paths.Results, "result-"+id+".json")

				if _, err := os.Stat(zipPath); err != nil {
					continue
				}

				if err := storage.SaveFile(stPath, storage.TaskStatus{Status: "running"}); err != nil {
					continue
				}

				sem <- struct{}{}
				go func(id, zipPath, stPath, resultPath string) {
					defer func() { <-sem }()

					if err := processTask(ctx, zipPath, resultPath); err != nil {
						_ = storage.SaveFile(stPath, storage.TaskStatus{Status: "failed", Error: err.Error()})
						return
					}

					_ = os.Remove(zipPath)

					_ = storage.SaveFile(stPath, storage.TaskStatus{Status: "done"})
				}(id, zipPath, stPath, resultPath)
			}

			time.Sleep(500 * time.Millisecond)
		}
	}()
}
