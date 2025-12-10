package worker

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"scaserv/sbom-serv/internal/config"
	"scaserv/sbom-serv/internal/taskstore"
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
func StartWorker(ctx context.Context, store *taskstore.Store, paths config.UploadPaths, maxParallel int) {
	sem := make(chan struct{}, maxParallel)

	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// завершения
			for i := 0; i < maxParallel; i++ {
				select {
				case sem <- struct{}{}:
				case <-time.After(3 * time.Second):
					return
				}
			}
			return

		case <-ticker.C:
			select {
			case sem <- struct{}{}:
				// слот получен
			default:
				// нет свободных слотов
				continue
			}

			task, ok, err := store.ClaimNextQueued(ctx)
			if err != nil {
				<-sem
				continue
			}
			if !ok {
				<-sem
				continue
			}

			id := task.ID
			zipPath := filepath.Join(paths.Zips, "zip-"+id+".zip")
			resultPath := filepath.Join(paths.Results, "result-"+id+".json")

			go func(id, zipPath, resultPath string) {
				defer func() { <-sem }()

				if err := processTask(ctx, zipPath, resultPath); err != nil {
					msg := err.Error()
					_ = store.SetStatus(ctx, id, taskstore.StatusFailed, &msg)
					return
				}

				_ = os.Remove(zipPath)
				_ = store.SetStatus(ctx, id, taskstore.StatusDone, nil)
			}(id, zipPath, resultPath)
		}
	}
}
