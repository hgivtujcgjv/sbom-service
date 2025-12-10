package janitor

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"scaserv/sbom-serv/internal/config"
)

type RunningAction string

const (
	RunningFail   RunningAction = "fail"
	RunningRequeue RunningAction = "requeue"
)

type Config struct {
	// Как часто запускать чистку
	Every time.Duration

	// Через сколько времени удалять done/failed задачи + файлы
	Retention time.Duration

	// Чистка зависших running (0 = выключено)
	RunningTimeout time.Duration

	// Что делать с зависшими running: "fail" или "requeue"
	RunningTimeoutAction RunningAction

	// Через сколько удалять *.tmp
	TmpMaxAge time.Duration

	// Ограничение количества задач на один прогон
	BatchSize int

	// Advisory lock key (одно число на весь кластер)
	AdvisoryLockKey int64
}

func DefaultConfig() Config {
	return Config{
		Every:               1 * time.Minute,
		Retention:           24 * time.Hour,
		RunningTimeout:      30 * time.Minute,
		RunningTimeoutAction: RunningFail,
		TmpMaxAge:           10 * time.Minute,
		BatchSize:           500,
		// любое постоянное число, главное одинаковое на всех инстансах:
		AdvisoryLockKey:     9876543,
	}
}

type Janitor struct {
	db    *sql.DB
	paths config.UploadPaths
	cfg   Config
	logf  func(string, ...any)
}

func New(db *sql.DB, paths config.UploadPaths, cfg Config) *Janitor {
	j := &Janitor{
		db:    db,
		paths: paths,
		cfg:   cfg,
		logf:  log.Printf,
	}
	if j.cfg.BatchSize <= 0 {
		j.cfg.BatchSize = 500
	}
	if j.cfg.Every <= 0 {
		j.cfg.Every = 1 * time.Minute
	}
	if j.cfg.TmpMaxAge <= 0 {
		j.cfg.TmpMaxAge = 10 * time.Minute
	}
	return j
}

func (j *Janitor) Start(ctx context.Context) {
	ticker := time.NewTicker(j.cfg.Every)
	defer ticker.Stop()

	// Можно сразу прогнать один раз на старте
	j.RunOnce(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			j.RunOnce(ctx)
		}
	}
}

func (j *Janitor) RunOnce(ctx context.Context) {
	// Пинним соединение, потому что advisory lock "живет" на сессии.
	conn, err := j.db.Conn(ctx)
	if err != nil {
		j.logf("[janitor] db.Conn: %v", err)
		return
	}
	defer conn.Close()

	ok, err := tryAdvisoryLock(ctx, conn, j.cfg.AdvisoryLockKey)
	if err != nil {
		j.logf("[janitor] try lock: %v", err)
		return
	}
	if !ok {
		// Другой инстанс уже чистит — спокойно выходим
		return
	}
	defer func() {
		_ = advisoryUnlock(context.Background(), conn, j.cfg.AdvisoryLockKey)
	}()

	// 1) опционально — обработка зависших running
	if j.cfg.RunningTimeout > 0 {
		if err := j.handleStuckRunning(ctx, conn); err != nil {
			j.logf("[janitor] handleStuckRunning: %v", err)
		}
	}

	// 2) удалить старые done/failed и их файлы
	if j.cfg.Retention > 0 {
		if err := j.cleanupOldDoneFailed(ctx, conn); err != nil {
			j.logf("[janitor] cleanupOldDoneFailed: %v", err)
		}
	}

	// 3) почистить *.tmp в папках
	if err := cleanupTmpFiles(j.paths.Results, j.cfg.TmpMaxAge); err != nil {
		j.logf("[janitor] cleanup tmp in results: %v", err)
	}
	if err := cleanupTmpFiles(j.paths.Zips, j.cfg.TmpMaxAge); err != nil {
		j.logf("[janitor] cleanup tmp in zips: %v", err)
	}
}

func tryAdvisoryLock(ctx context.Context, conn *sql.Conn, key int64) (bool, error) {
	var ok bool
	err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&ok)
	return ok, err
}

func advisoryUnlock(ctx context.Context, conn *sql.Conn, key int64) error {
	_, err := conn.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, key)
	return err
}

// Помечаем "долго running" как failed или requeue.
// ВАЖНО: это эвристика. Если реальная обработка длится дольше RunningTimeout — ставь timeout больше.
func (j *Janitor) handleStuckRunning(ctx context.Context, conn *sql.Conn) error {
	seconds := int64(j.cfg.RunningTimeout.Seconds())
	if seconds <= 0 {
		return nil
	}

	var status string
	var errText string

	switch j.cfg.RunningTimeoutAction {
	case RunningRequeue:
		status = "queued"
		errText = "requeued by janitor: running too long"
	default:
		status = "failed"
		errText = "failed by janitor: running too long"
	}

	// Запрос:
	// UPDATE ... WHERE status='running' AND ts < now() - timeout
	// timeout передаем как секунды, чтобы не мудрить с interval параметрами.
	_, err := conn.ExecContext(ctx, `
		UPDATE sbom_tasks
		SET status = $1::sbom_task_status,
		    ts = now(),
		    error = $2
		WHERE status = 'running'
		  AND ts < now() - ($3 * interval '1 second')
	`, status, errText, seconds)
	return err
}

func (j *Janitor) cleanupOldDoneFailed(ctx context.Context, conn *sql.Conn) error {
	seconds := int64(j.cfg.Retention.Seconds())
	if seconds <= 0 {
		return nil
	}

	// 1) Берем пачку "старых done/failed"
	rows, err := conn.QueryContext(ctx, `
		SELECT id::text, status::text
		FROM sbom_tasks
		WHERE status IN ('done','failed')
		  AND ts < now() - ($1 * interval '1 second')
		ORDER BY ts ASC
		LIMIT $2
	`, seconds, j.cfg.BatchSize)
	if err != nil {
		return err
	}
	defer rows.Close()

	type item struct {
		id     string
		status string
	}

	var items []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.id, &it.status); err != nil {
			return err
		}
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(items) == 0 {
		return nil
	}

	// 2) Для каждой задачи: удаляем файлы (если есть) + удаляем строку из БД
	for _, it := range items {
		id := it.id

		// result файл обычно только у done, но если есть — удаляем и у failed тоже
		_ = removeIfExists(filepath.Join(j.paths.Results, "result-"+id+".json"))
		_ = removeIfExists(filepath.Join(j.paths.Results, "result-"+id+".json.tmp"))

		// zip можно держать для дебага failed; если не нужно — чистим всегда
		_ = removeIfExists(filepath.Join(j.paths.Zips, "zip-"+id+".zip"))
		_ = removeIfExists(filepath.Join(j.paths.Zips, "zip-"+id+".zip.tmp"))

		// Удаляем запись
		_, err := conn.ExecContext(ctx, `DELETE FROM sbom_tasks WHERE id = $1`, id)
		if err != nil {
			// если удаление не удалось — не падаем всем прогоном, а идем дальше
			j.logf("[janitor] delete row id=%s: %v", id, err)
			continue
		}
	}

	return nil
}

func removeIfExists(path string) error {
	err := os.Remove(path)
	if err == nil {
		return nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func cleanupTmpFiles(dir string, maxAge time.Duration) error {
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		// если папки нет — это скорее проблема конфигурации, но не фатально
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	cutoff := time.Now().Add(-maxAge)

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".tmp") {
			continue
		}
		full := filepath.Join(dir, name)
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			_ = os.Remove(full)
		}
	}

	return nil
}
