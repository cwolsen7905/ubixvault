// Command ubixvault is the uBix Vault server and CLI.
//
// Implemented so far: the `server` command, which runs the HTTP API over a
// file-backed, encrypted store. Initialization and unsealing are driven through
// the /v1/sys/* endpoints (see docs/DESIGN.md §4).
package main

import (
	"context"
	"encoding/hex"
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
	"github.com/cwolsen7905/ubixvault/internal/audit"
	"github.com/cwolsen7905/ubixvault/internal/client"
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
	case "operator":
		if err := runOperator(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
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
	fmt.Println("  server                     run the HTTP API server")
	fmt.Println("  operator init              initialize a vault")
	fmt.Println("  operator unseal <key>      submit an unseal key")
	fmt.Println("  operator seal-status       show seal status")
	fmt.Println("  operator seal              re-seal (requires -token)")
	fmt.Println("  version                    print the version")
	fmt.Println("\nGlobal operator flags: -address (or $UBIXVAULT_ADDR), -token (or $UBIXVAULT_TOKEN)")
}

func runServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:8200", "address to listen on")
	dataDir := fs.String("data", "./data", "directory for encrypted storage")
	tlsCert := fs.String("tls-cert", "", "TLS certificate file (enables HTTPS)")
	tlsKey := fs.String("tls-key", "", "TLS private key file")
	auditLog := fs.String("audit-log", "", "path to an audit log file (enables fail-closed audit logging)")
	autoUnsealKey := fs.String("auto-unseal-key", os.Getenv("UBIXVAULT_AUTO_UNSEAL_KEY"),
		"hex-encoded 32-byte key-encryption key; enables auto-unseal (or set $UBIXVAULT_AUTO_UNSEAL_KEY)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	phys, err := storage.NewFileBackend(*dataDir)
	if err != nil {
		return fmt.Errorf("open storage: %w", err)
	}

	var coreOpts []core.Option
	if *autoUnsealKey != "" {
		kek, err := hex.DecodeString(*autoUnsealKey)
		if err != nil || len(kek) != 32 {
			return fmt.Errorf("auto-unseal-key must be 64 hex characters (32 bytes)")
		}
		coreOpts = append(coreOpts, core.WithAutoUnsealKey(kek))
	}
	c := core.New(phys, coreOpts...)

	// Auto-unseal on startup if configured and already initialized.
	if c.AutoUnsealEnabled() {
		switch err := c.AutoUnseal(context.Background()); {
		case err == nil:
			log.Printf("auto-unsealed")
		case errors.Is(err, core.ErrNotInitialized):
			log.Printf("auto-unseal configured; vault is not yet initialized")
		default:
			log.Printf("WARNING: auto-unseal failed, starting sealed: %v", err)
		}
	}

	var opts []api.Option
	if *auditLog != "" {
		device, err := audit.NewFileDevice(*auditLog)
		if err != nil {
			return fmt.Errorf("open audit log: %w", err)
		}
		broker := audit.NewBroker(device)
		defer func() { _ = broker.Close() }()
		opts = append(opts, api.WithAudit(broker))
		log.Printf("audit logging to %s", *auditLog)
	}

	handler := api.NewHandler(c, opts...)

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

// --- operator commands (a thin client over the HTTP API) ---

func runOperator(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("operator requires a subcommand: init, unseal, seal-status, seal")
	}
	switch args[0] {
	case "init":
		return operatorInit(args[1:])
	case "unseal":
		return operatorUnseal(args[1:])
	case "seal-status":
		return operatorSealStatus(args[1:])
	case "seal":
		return operatorSeal(args[1:])
	default:
		return fmt.Errorf("unknown operator subcommand %q", args[0])
	}
}

func defaultAddr() string {
	if a := os.Getenv("UBIXVAULT_ADDR"); a != "" {
		return a
	}
	return "http://127.0.0.1:8200"
}

func operatorInit(args []string) error {
	fs := flag.NewFlagSet("operator init", flag.ExitOnError)
	addr := fs.String("address", defaultAddr(), "server address")
	shares := fs.Int("shares", 5, "number of unseal key shares")
	threshold := fs.Int("threshold", 3, "shares required to unseal")
	if err := fs.Parse(args); err != nil {
		return err
	}

	res, err := client.New(*addr, "").Init(context.Background(), *shares, *threshold)
	if err != nil {
		return err
	}
	for i, k := range res.Keys {
		fmt.Printf("Unseal Key %d: %s\n", i+1, k)
	}
	fmt.Printf("\nInitial Root Token: %s\n", res.RootToken)
	fmt.Printf("\nSave these now — they are shown only once.\n")
	fmt.Printf("Unseal with any %d of the %d keys.\n", *threshold, *shares)
	return nil
}

func operatorUnseal(args []string) error {
	fs := flag.NewFlagSet("operator unseal", flag.ExitOnError)
	addr := fs.String("address", defaultAddr(), "server address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	key := fs.Arg(0)
	if key == "" {
		return fmt.Errorf("usage: operator unseal [-address URL] <key>")
	}
	st, err := client.New(*addr, "").Unseal(context.Background(), key)
	if err != nil {
		return err
	}
	printStatus(st)
	return nil
}

func operatorSealStatus(args []string) error {
	fs := flag.NewFlagSet("operator seal-status", flag.ExitOnError)
	addr := fs.String("address", defaultAddr(), "server address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := client.New(*addr, "").SealStatus(context.Background())
	if err != nil {
		return err
	}
	printStatus(st)
	return nil
}

func operatorSeal(args []string) error {
	fs := flag.NewFlagSet("operator seal", flag.ExitOnError)
	addr := fs.String("address", defaultAddr(), "server address")
	token := fs.String("token", os.Getenv("UBIXVAULT_TOKEN"), "auth token")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := client.New(*addr, *token).Seal(context.Background()); err != nil {
		return err
	}
	fmt.Println("Sealed.")
	return nil
}

func printStatus(st *client.SealStatus) {
	fmt.Printf("Initialized: %t\n", st.Initialized)
	fmt.Printf("Sealed:      %t\n", st.Sealed)
	if st.Initialized {
		fmt.Printf("Threshold:   %d\n", st.Threshold)
		fmt.Printf("Shares:      %d\n", st.Shares)
		fmt.Printf("Progress:    %d/%d\n", st.Progress, st.Threshold)
	}
}
