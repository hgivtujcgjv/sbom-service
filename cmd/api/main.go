package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"YOUR/MODULE/PATH/internal/config"
	"YOUR/MODULE/PATH/internal/httpapi"
	"YOUR/MODULE/PATH/internal/taskstore"
	"YOUR/MODULE/PATH/internal/worker"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		<-ch
		cancel()
	}()

	dsn := "DATABASE_URL"

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(20)
	db.SetConnMaxLifetime(30 * time.Minute)

	if err := db.PingContext(ctx); err != nil {
		log.Fatal(err)
	}

	store := taskstore.New(db)

	paths := config.MustLoadUploadPaths()
	
	go worker.StartWorker(ctx, store, paths, 4)

	mux := http.NewServeMux()
	mux.Handle("/upload", httpapi.UploadZipHandler(paths, store))
	mux.Handle("/scan", httpapi.ScanInfoHandler(paths, store))

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Println("listening on", srv.Addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
