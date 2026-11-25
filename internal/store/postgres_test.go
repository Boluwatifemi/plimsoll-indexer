package store

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/plimsoll-protocol/plimsoll-indexer/internal/coverage"
)

// The store tests run against a real Postgres: embedded-postgres downloads the
// binaries once (cached in ~/.embedded-postgres-go) and starts one server for
// the package. Each test gets a database of its own from newDatabase.
// `go test -short` skips them.

// adminURL is the server's maintenance database; empty when the server is not
// running, in which case database tests skip.
var adminURL string

var databaseSeq atomic.Int64

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}
	os.Exit(runWithPostgres(m))
}

func runWithPostgres(m *testing.M) int {
	dir, err := os.MkdirTemp("", "plimsoll-store-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "embedded postgres:", err)
		return 1
	}
	defer os.RemoveAll(dir)

	port, err := freePort()
	if err != nil {
		fmt.Fprintln(os.Stderr, "embedded postgres:", err)
		return 1
	}
	var serverLog bytes.Buffer
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Port(port).
		RuntimePath(filepath.Join(dir, "runtime")).
		DataPath(filepath.Join(dir, "data")).
		BinariesPath(filepath.Join(dir, "bin")).
		StartTimeout(60 * time.Second).
		Logger(&serverLog))
	if err := pg.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "embedded postgres: %v\n%s", err, serverLog.String())
		return 1
	}
	defer func() {
		if err := pg.Stop(); err != nil {
			fmt.Fprintln(os.Stderr, "embedded postgres stop:", err)
		}
	}()

	adminURL = fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres?sslmode=disable", port)
	return m.Run()
}

func freePort() (uint32, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return uint32(l.Addr().(*net.TCPAddr).Port), nil
}

// newDatabase creates an empty database for one test, drops it when the test
// ends, and returns its URL.
func newDatabase(t *testing.T) string {
	t.Helper()
	if adminURL == "" {
		t.Skip("embedded postgres is not running (go test -short)")
	}
	ctx := context.Background()
	name := fmt.Sprintf("store_test_%d_%d", os.Getpid(), databaseSeq.Add(1))
	admin, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		t.Fatalf("connect to embedded postgres: %v", err)
	}
	defer admin.Close(ctx)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		conn, err := pgx.Connect(context.Background(), adminURL)
		if err != nil {
			t.Errorf("drop database %s: %v", name, err)
			return
		}
		defer conn.Close(context.Background())
		if _, err := conn.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
			t.Errorf("drop database %s: %v", name, err)
		}
	})
	return fmt.Sprintf("postgres://postgres:postgres@localhost:%s/%s?sslmode=disable", portOf(adminURL), name)
}

// openStore opens a Store on a fresh database, applying the schema the way
// the indexer does on start.
func openStore(t *testing.T) (*Store, string) {
	t.Helper()
	url := newDatabase(t)
	s, err := Open(context.Background(), url)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(s.Close)
	return s, url
}

func portOf(url string) string {
	cfg, err := pgx.ParseConfig(url)
	if err != nil {
		panic(err)
	}
	return fmt.Sprint(cfg.Port)
}

// execSQL runs statements on the database at url outside any Store.
func execSQL(t *testing.T, url, sql string, args ...any) {
	t.Helper()
	conn, err := pgx.Connect(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	if _, err := conn.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("exec %.60q: %v", sql, err)
	}
}

// testPool is a connection pool on the database at url, closed with the test.
func testPool(t *testing.T, url string) *pgxpool.Pool {
	t.Helper()
	p, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

func TestIssuerTomlSnapshotsDetectChanges(t *testing.T) {
	s, _ := openStore(t)
	ctx := context.Background()
	at := time.Date(2026, 11, 24, 15, 0, 0, 0, time.UTC)

	old, changed, err := s.SaveIssuerTomlSnapshot(ctx, "GISSUER", "issuer.example", "hash-one", at)
	if err != nil || old != "" || changed {
		t.Fatalf("initial snapshot: old=%q changed=%v err=%v", old, changed, err)
	}
	old, changed, err = s.SaveIssuerTomlSnapshot(ctx, "GISSUER", "issuer.example", "hash-one", at.Add(time.Hour))
	if err != nil || old != "hash-one" || changed {
		t.Fatalf("same snapshot: old=%q changed=%v err=%v", old, changed, err)
	}
	old, changed, err = s.SaveIssuerTomlSnapshot(ctx, "GISSUER", "issuer.example", "hash-two", at.Add(2*time.Hour))
	if err != nil || old != "hash-one" || !changed {
		t.Fatalf("changed snapshot: old=%q changed=%v err=%v", old, changed, err)
	}
	old, changed, err = s.SaveIssuerTomlSnapshot(ctx, "GISSUER", "issuer.example", "hash-two", at.Add(3*time.Hour))
	if err != nil || old != "hash-two" || changed {
		t.Fatalf("repeated snapshot: old=%q changed=%v err=%v", old, changed, err)
	}

	var count int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM issuer_toml_snapshots WHERE issuer = $1`, "GISSUER").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("stored %d snapshots, want 2", count)
	}
}

func TestWebhookPersistence(t *testing.T) {
	s, _ := openStore(t)
	ctx := context.Background()
	ciphertext := []byte{1, 2, 3, 4}
	created, err := s.CreateWebhook(ctx, "https://receiver.example/hook", "sha256-hash", ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if created.ID < 1 || created.SecretHash != "sha256-hash" || !bytes.Equal(created.SecretCiphertext, ciphertext) {
		t.Fatalf("created webhook = %+v", created)
	}

	list, err := s.ListWebhooks(ctx)
	if err != nil || len(list) != 1 || list[0].ID != created.ID ||
		list[0].URL != created.URL || list[0].SecretHash != created.SecretHash ||
		!bytes.Equal(list[0].SecretCiphertext, ciphertext) {
		t.Fatalf("listed webhooks = %+v, %v", list, err)
	}
	deleted, err := s.DeleteWebhook(ctx, created.ID)
	if err != nil || !deleted {
		t.Fatalf("delete webhook: deleted=%v err=%v", deleted, err)
	}
	deleted, err = s.DeleteWebhook(ctx, created.ID)
	if err != nil || deleted {
		t.Fatalf("delete missing webhook: deleted=%v err=%v", deleted, err)
	}
}

func TestLatestSuppliesAndReportsBySAC(t *testing.T) {
	s, _ := openStore(t)
	ctx := context.Background()
	at := time.Date(2026, 11, 25, 1, 0, 0, 0, time.UTC)

	for _, supply := range []coverage.Supply{
		{Amount: big.NewInt(100), Ledger: 10, PostedAt: at, BreakdownHash: "old", Poster: "G1"},
		{Amount: big.NewInt(200), Ledger: 20, PostedAt: at.Add(time.Hour), BreakdownHash: "new", Poster: "G1"},
	} {
		if _, err := s.SaveChainSupply(ctx, "CSAC1", supply); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.SaveChainSupply(ctx, "CSAC2", coverage.Supply{
		Amount: big.NewInt(300), Ledger: 30, PostedAt: at, BreakdownHash: "two", Poster: "G2",
	}); err != nil {
		t.Fatal(err)
	}

	reports := []coverage.Report{
		{Tier: coverage.TierIssuerSigned, Amount: big.NewInt(110), AsOf: at, PostedAt: at, Reporter: "G1", DocURI: "old"},
		{Tier: coverage.TierIssuerSigned, Amount: big.NewInt(210), AsOf: at.Add(time.Hour), PostedAt: at.Add(time.Hour), Reporter: "G1", DocURI: "new"},
		{Tier: coverage.TierAuditorSigned, Amount: big.NewInt(220), AsOf: at, PostedAt: at, Reporter: "G2", DocURI: "audit"},
	}
	for _, report := range reports {
		if _, err := s.SaveChainReport(ctx, "CSAC1", report); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.SaveChainReport(ctx, "CSAC2", coverage.Report{
		Tier: coverage.TierTranscribed, Amount: big.NewInt(290), AsOf: at, PostedAt: at, Reporter: "G3", DocURI: "two",
	}); err != nil {
		t.Fatal(err)
	}

	supplies, err := s.LatestSupplies(ctx, []string{"CSAC1", "CSAC2", "CSAC3"})
	if err != nil {
		t.Fatal(err)
	}
	if supplies["CSAC1"] == nil || supplies["CSAC1"].Ledger != 20 || supplies["CSAC1"].Amount.String() != "200" {
		t.Fatalf("CSAC1 supply = %+v", supplies["CSAC1"])
	}
	if supplies["CSAC2"] == nil || supplies["CSAC2"].Ledger != 30 {
		t.Fatalf("CSAC2 supply = %+v", supplies["CSAC2"])
	}
	if supplies["CSAC3"] != nil {
		t.Fatalf("missing CSAC3 supply should be nil: %+v", supplies["CSAC3"])
	}

	bySAC, err := s.LatestReportsBySAC(ctx, []string{"CSAC1", "CSAC2", "CSAC3"})
	if err != nil {
		t.Fatal(err)
	}
	if len(bySAC["CSAC1"]) != 2 {
		t.Fatalf("CSAC1 reports = %+v", bySAC["CSAC1"])
	}
	if got := bySAC["CSAC1"][coverage.TierIssuerSigned].Amount.String(); got != "210" {
		t.Fatalf("latest issuer_signed amount = %q, want 210", got)
	}
	if len(bySAC["CSAC2"]) != 1 {
		t.Fatalf("CSAC2 reports = %+v", bySAC["CSAC2"])
	}
}
