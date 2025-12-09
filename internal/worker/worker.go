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

			task, ok, err := store.ClaimNextQueued(ctx)
			if err != nil {
				time.Sleep(500 * time.Millisecond)
				continue
			}
			if !ok {
				time.Sleep(500 * time.Millisecond)
				continue
			}

			id := task.ID
			zipPath := filepath.Join(paths.Zips, "zip-"+id+".zip")
			resultPath := filepath.Join(paths.Results, "result-"+id+".json")

			sem <- struct{}{}
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
	}()
}
