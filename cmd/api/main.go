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
	httpSwagger "github.com/swaggo/http-swagger/v2"

	"sbom-serv/internal/config"
	"sbom-serv/internal/httpapi"
	"sbom-serv/internal/janitor"
	"sbom-serv/internal/taskstore"
	"sbom-serv/internal/worker"
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

	dsn := os.Getenv("DATABASE_URL")

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		log.Fatal(err)
	}
	if err2 := db.Ping(); err2 != nil {
		log.Fatal(err2)
	}

	defer db.Close()

	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(20)
	db.SetConnMaxLifetime(30 * time.Minute)

	if err := db.PingContext(ctx); err != nil {
		log.Fatal(err)
	}

	store := taskstore.New(db)

	paths := config.NewUploadPaths("./uploads")
	if err := paths.Ensure(); err != nil {
		log.Fatal(err)
	}

	cfg := janitor.DefaultConfig()
	cfg.Retention = 24 * time.Hour     // интервал удаления задач
	cfg.RunningTimeout = 3 * time.Hour // умершие задачи
	cfg.RunningTimeoutAction = janitor.RunningFail
	cfg.Every = 1 * time.Hour

	j := janitor.New(db, paths, cfg)
	go j.Start(ctx)
	go worker.StartWorker(ctx, store, paths, 5) // тут поменять количетсво потоков

	mux := http.NewServeMux()
	mux.Handle("/scan", httpapi.UploadZipHandler(paths, store))
	mux.Handle("/scan/info", httpapi.ScanInfoHandler(paths, store))

	mux.HandleFunc("/openapi.yaml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
		http.ServeFile(w, r, "./docs/openapi.yaml")
	})

	mux.Handle("/swagger/", httpSwagger.Handler(
		httpSwagger.URL("/openapi.yaml"),
	))
	srv := &http.Server{
		Addr:              ":8082",
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	certFile := "/app/certs/server-cert.pem"
	keyFile := "/app/certs/SBOM_GEN.key"
	log.Println("listening on", srv.Addr)
	if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
