// Command plimsoll-indexer ingests Plimsoll contract events, posts supply
// snapshots, syncs issuer stellar.toml data, and serves the read API.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/stellar/go-stellar-sdk/clients/rpcclient"
	"github.com/stellar/go-stellar-sdk/keypair"

	"github.com/plimsoll-protocol/plimsoll-indexer/internal/api"
	"github.com/plimsoll-protocol/plimsoll-indexer/internal/config"
	"github.com/plimsoll-protocol/plimsoll-indexer/internal/horizon"
	"github.com/plimsoll-protocol/plimsoll-indexer/internal/soroban"
	"github.com/plimsoll-protocol/plimsoll-indexer/internal/stellartoml"
	"github.com/plimsoll-protocol/plimsoll-indexer/internal/store"
	"github.com/plimsoll-protocol/plimsoll-indexer/internal/webhook"
	"github.com/plimsoll-protocol/plimsoll-indexer/internal/worker"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "verify" {
		os.Exit(runVerifyCommand(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(runHealthcheck())
	}

	cfg, err := config.Load()
	log := newLogger(cfg.LogLevel)
	if err != nil {
		log.Error("invalid configuration", "err", err)
		os.Exit(1)
	}
	if err := run(cfg, log); err != nil {
		log.Error("indexer stopped", "err", err)
		os.Exit(1)
	}
}

func run(cfg config.Config, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	jobs := &jobGroup{}

	db, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()

	rpc := rpcclient.NewClient(cfg.RPCURL, &http.Client{Timeout: 30 * time.Second})
	defer rpc.Close()
	hz := horizon.NewClient(cfg.HorizonURL)

	var webhookCodec *webhook.SecretCodec
	var webhookDispatcher *webhook.Dispatcher
	if cfg.WebhookAdminToken != "" {
		webhookCodec, err = webhook.NewSecretCodec(cfg.WebhookEncryptionKey)
		if err != nil {
			return err
		}
		webhookDispatcher = webhook.NewDispatcher(db, webhookCodec)
	}

	ingester := &worker.Ingester{
		RPC:         rpc,
		Store:       db,
		ContractIDs: []string{cfg.CoverageLedgerID, cfg.ReporterRegistryID},
		StartLedger: cfg.StartLedger,
		Log:         log.With("job", "ingest"),
	}
	// Ingest once before the other jobs start, so they see the listed assets.
	if err := ingester.Run(ctx); err != nil {
		log.Error("initial ingest failed", "err", err)
	}
	jobs.startEvery(ctx, "ingest", cfg.IngestInterval, log.With("job", "ingest"), ingester.Run)

	// Repairs what an ingestion gap lost by reading contract state back.
	// Reading is simulation, so this needs no key and runs even on an instance
	// that cannot sign.
	reconciler := &worker.Reconciler{
		Invoker:  &soroban.Reader{RPC: rpc},
		Store:    db,
		LedgerID: cfg.CoverageLedgerID,
		Log:      log.With("job", "reconcile"),
	}
	if err := reconciler.Run(ctx); err != nil {
		log.Error("initial reconcile failed", "err", err)
	}
	jobs.startEvery(ctx, "reconcile", cfg.ReconcileInterval, log.With("job", "reconcile"), reconciler.Run)

	tomlSync := &worker.TomlSync{
		Horizon:  hz,
		Fetcher:  stellartoml.NewFetcher(),
		Store:    db,
		Webhooks: webhookDispatcher,
		MaxAge:   cfg.TomlInterval,
		Log:      log.With("job", "toml"),
	}
	// Checks every minute; each asset is refreshed once per TOML_INTERVAL.
	jobs.startEvery(ctx, "toml", time.Minute, log.With("job", "toml"), tomlSync.Run)

	if cfg.KeepAwakeURL != "" {
		keepAwake := worker.NewKeepAwake(cfg.KeepAwakeURL)
		kaLog := log.With("job", "keepawake")
		kaLog.Info("keep-awake enabled", "url", cfg.KeepAwakeURL, "interval", cfg.KeepAwakeInterval)
		jobs.start(ctx, "keepawake", func(ctx context.Context) error {
			// Wait one interval first: the HTTP server is not listening yet.
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(cfg.KeepAwakeInterval):
			}
			everyTracked(jobs, ctx, "keepawake", cfg.KeepAwakeInterval, kaLog, keepAwake.Run)
			return nil
		})
	}

	if cfg.PostingEnabled() {
		signer, err := keypair.ParseFull(cfg.PosterSecret)
		if err != nil {
			return errors.New("SUPPLY_POSTER_SECRET is not a valid secret seed")
		}
		invoker := &soroban.Invoker{
			RPC:        rpc,
			Signer:     signer,
			Passphrase: cfg.NetworkPassphrase,
		}
		poster := &worker.Poster{
			Horizon:     hz,
			RPC:         rpc,
			Invoker:     invoker,
			Store:       db,
			LedgerID:    cfg.CoverageLedgerID,
			RepostAfter: cfg.RepostAfter,
			Log:         log.With("job", "poster"),
			Now:         time.Now,
		}
		// Left nil when no second Horizon is configured: comparing hz against
		// itself would always agree and prove nothing.
		if cfg.HorizonCheckURL != "" {
			poster.HorizonCheck = horizon.NewClient(cfg.HorizonCheckURL)
			log.Info("supply cross-check enabled", "check_horizon", cfg.HorizonCheckURL)
		} else {
			log.Info("supply cross-check disabled (HORIZON_CHECK_URL not set)")
		}
		log.Info("supply posting enabled", "poster", signer.Address())
		jobs.startEvery(ctx, "poster", cfg.PostInterval, log.With("job", "poster"), poster.Run)

	} else {
		log.Info("supply posting disabled (SUPPLY_POSTER_SECRET not set)")
	}

	srv := &http.Server{
		Addr: ":" + cfg.Port,
		Handler: (&api.Server{
			Store:             db,
			WebhookStore:      db,
			WebhookAdminToken: cfg.WebhookAdminToken,
			WebhookCodec:      webhookCodec,
			Network: api.NetworkInfo{
				NetworkPassphrase:  cfg.NetworkPassphrase,
				RPCURL:             cfg.RPCURL,
				HorizonURL:         cfg.HorizonURL,
				CoverageLedgerID:   cfg.CoverageLedgerID,
				ReporterRegistryID: cfg.ReporterRegistryID,
			},
			CORS: cfg.CORSOrigins,
			Log:  log.With("component", "api"),
			Now:  time.Now,
		}).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	var shutdownDeadline atomic.Int64
	go func() {
		<-ctx.Done()
		shutdownDeadline.Store(time.Now().Add(cfg.ShutdownTimeout).UnixNano())
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	log.Info("listening", "addr", srv.Addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		stop()
		jobs.wait(shutdownRemaining(shutdownDeadline.Load(), cfg.ShutdownTimeout), log)
		return err
	}
	stop()
	jobs.wait(shutdownRemaining(shutdownDeadline.Load(), cfg.ShutdownTimeout), log)
	return nil
}

func shutdownRemaining(deadlineUnixNano int64, fallback time.Duration) time.Duration {
	if deadlineUnixNano == 0 {
		return fallback
	}
	return time.Until(time.Unix(0, deadlineUnixNano))
}

type jobGroup struct {
	mu       sync.Mutex
	running  map[string]bool
	active   int
	done     chan struct{}
	doneOnce sync.Once
}

func (g *jobGroup) start(ctx context.Context, name string, fn func(context.Context) error) {
	g.mu.Lock()
	if g.running == nil {
		g.running = make(map[string]bool)
		g.done = make(chan struct{})
	}
	g.active++
	g.mu.Unlock()

	go func() {
		defer func() {
			g.mu.Lock()
			delete(g.running, name)
			g.active--
			done := g.done
			finished := g.active == 0
			g.mu.Unlock()
			if finished {
				g.doneOnce.Do(func() { close(done) })
			}
		}()
		g.mu.Lock()
		g.running[name] = true
		g.mu.Unlock()
		_ = fn(ctx)
	}()
}

func (g *jobGroup) startEvery(ctx context.Context, name string, interval time.Duration, log *slog.Logger, fn func(context.Context) error) {
	g.start(ctx, name, func(ctx context.Context) error {
		everyTracked(g, ctx, name, interval, log, fn)
		return nil
	})
}

func everyTracked(g *jobGroup, ctx context.Context, name string, interval time.Duration, log *slog.Logger, fn func(context.Context) error) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		g.begin(name)
		err := fn(ctx)
		g.end(name)
		if err != nil && ctx.Err() == nil {
			log.Error("job failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (g *jobGroup) begin(name string) {
	g.mu.Lock()
	g.running[name] = true
	g.mu.Unlock()
}

func (g *jobGroup) end(name string) {
	g.mu.Lock()
	delete(g.running, name)
	g.mu.Unlock()
}

func (g *jobGroup) wait(timeout time.Duration, log *slog.Logger) {
	g.mu.Lock()
	done := g.done
	g.mu.Unlock()
	if done == nil {
		return
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return
	case <-timer.C:
		g.mu.Lock()
		names := make([]string, 0, len(g.running))
		for name := range g.running {
			names = append(names, name)
		}
		sort.Strings(names)
		g.mu.Unlock()
		log.Error("shutdown deadline reached with jobs still running", "running_jobs", strings.Join(names, ","))
	}
}

// runHealthcheck requests /healthz on the local server and exits 0 on success
// or 1 on any failure. It honours the PORT environment variable so it matches
// whatever port the container is actually listening on.
func runHealthcheck() int {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:"+port+"/healthz", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: %v\n", err)
		return 1
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: %v\n", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return 0
	}
	fmt.Fprintf(os.Stderr, "healthcheck: status %d\n", resp.StatusCode)
	return 1
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
}
