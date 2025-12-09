package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"scaserv/sbom-serv/internal/config"
	"scaserv/sbom-serv/internal/httpapi"
	"scaserv/sbom-serv/internal/worker"
	"syscall"
	"database/sql"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	paths := config.NewUploadPaths("./uploads")
	if err := paths.Ensure(); err != nil {
		log.Fatal("mkdir uploads: %v", err)
	}

	worker.StartWorker(ctx, paths, 4) // поменять количество потоков с генерацией
	mux := http.NewServeMux()

	mux.Handle("/scan", httpapi.UploadZipHandler(paths))

	mux.Handle("/info", httpapi.ScanInfoHandler(paths))

	srv := &http.Server{
		Addr:    ":8082",
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		_ = srv.Shutdown(context.Background())
	}()

	log.Println("Server ready")
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server error %v", err)
	}
}
