// Command ubixvault is the uBix Vault server and CLI.
//
// Implemented so far: the `server` command, which runs the HTTP API over a
// file-backed, encrypted store. Initialization and unsealing are driven through
// the /v1/sys/* endpoints (see docs/DESIGN.md §4).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cwolsen7905/ubixvault/internal/api"
	"github.com/cwolsen7905/ubixvault/internal/core"
	"github.com/cwolsen7905/ubixvault/internal/storage"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "0.0.0-dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}
	switch os.Args[1] {
	case "server":
		if err := runServer(os.Args[2:]); err != nil {
			log.Fatalf("server: %v", err)
		}
	case "version", "-v", "--version":
		fmt.Printf("uBix Vault %s\n", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Printf("uBix Vault %s\n\n", version)
	fmt.Println("usage: ubixvault <command> [flags]")
	fmt.Println("\ncommands:")
	fmt.Println("  server    run the HTTP API server")
	fmt.Println("  version   print the version")
}

func runServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:8200", "address to listen on")
	dataDir := fs.String("data", "./data", "directory for encrypted storage")
	tlsCert := fs.String("tls-cert", "", "TLS certificate file (enables HTTPS)")
	tlsKey := fs.String("tls-key", "", "TLS private key file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	phys, err := storage.NewFileBackend(*dataDir)
	if err != nil {
		return fmt.Errorf("open storage: %w", err)
	}
	c := core.New(phys)
	handler := api.NewHandler(c)

	srv := &http.Server{
		Addr:              *listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Revoke expired dynamic-database leases in the background.
	go handler.RunLeaseSweeper(ctx, time.Minute)

	errCh := make(chan error, 1)
	go func() {
		if *tlsCert != "" && *tlsKey != "" {
			log.Printf("uBix Vault %s listening on https://%s (data: %s)", version, *listen, *dataDir)
			errCh <- srv.ListenAndServeTLS(*tlsCert, *tlsKey)
		} else {
			log.Printf("WARNING: serving plain HTTP without TLS — set -tls-cert/-tls-key for production")
			log.Printf("uBix Vault %s listening on http://%s (data: %s)", version, *listen, *dataDir)
			errCh <- srv.ListenAndServe()
		}
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		log.Println("shutting down…")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
