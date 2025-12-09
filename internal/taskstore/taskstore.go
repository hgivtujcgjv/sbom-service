package taskstore

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type Status string

const (
	StatusQueued  Status = "queued"
	StatusRunning Status = "running"
	StatusDone    Status = "done"
	StatusFailed  Status = "failed"
)

type Task struct {
	ID        string
	Status    Status
	Timestamp time.Time
	Error     *string
}

type Store struct {
	db *sql.DB
}

func New(db *sql.DB) *Store { return &Store{db: db} }

func (s *Store) Enqueue(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sbom_tasks(id, status, ts, error)
		VALUES ($1, 'queued', now(), NULL)
	`, id)
	return err
}

func (s *Store) Get(ctx context.Context, id string) (Task, error) {
	var t Task
	var errNS sql.NullString

	err := s.db.QueryRowContext(ctx, `
		SELECT id::text, status::text, ts, error
		FROM sbom_tasks
		WHERE id = $1
	`, id).Scan(&t.ID, &t.Status, &t.Timestamp, &errNS)
	if err != nil {
		return Task{}, err
	}
	if errNS.Valid {
		t.Error = &errNS.String
	}
	return t, nil
}

func (s *Store) ClaimNextQueued(ctx context.Context) (Task, bool, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return Task{}, false, err
	}
	defer func() { _ = tx.Rollback() }()

	var id string
	err = tx.QueryRowContext(ctx, `
		SELECT id::text
		FROM sbom_tasks
		WHERE status = 'queued'
		ORDER BY ts ASC
		FOR UPDATE SKIP LOCKED
		LIMIT 1
	`).Scan(&id)

	if errors.Is(err, sql.ErrNoRows) {
		_ = tx.Commit()
		return Task{}, false, nil
	}
	if err != nil {
		return Task{}, false, err
	}

	_, err = tx.ExecContext(ctx, `
		UPDATE sbom_tasks
		SET status = 'running', ts = now(), error = NULL
		WHERE id = $1
	`, id)
	if err != nil {
		return Task{}, false, err
	}

	if err := tx.Commit(); err != nil {
		return Task{}, false, err
	}

	t, err := s.Get(ctx, id)
	if err != nil {
		return Task{}, false, err
	}
	return t, true, nil
}

func (s *Store) SetStatus(ctx context.Context, id string, status Status, errMsg *string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE sbom_tasks
		SET status = $2::sbom_task_status,
		    ts = now(),
		    error = $3
		WHERE id = $1
	`, id, string(status), errMsg)
	return err
}
