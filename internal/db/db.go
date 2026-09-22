// Package db owns the connection pool and the embedded migration runner.
package db

import (
	"context"
	"embed"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed all:migrations
var migrationFS embed.FS

// Pool is the application's database handle.
type Pool struct {
	*pgxpool.Pool
}

func Open(ctx context.Context, url string) (*Pool, error) {
	p, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("db: open: %w", err)
	}
	if err := p.Ping(ctx); err != nil {
		p.Close()
		return nil, fmt.Errorf("db: ping: %w", err)
	}
	return &Pool{p}, nil
}

// Migrate applies every embedded migration not yet recorded in
// schema_migrations, in filename order, each in its own transaction.
func (p *Pool) Migrate(ctx context.Context) ([]string, error) {
	if _, err := p.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return nil, err
	}
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	var applied []string
	for _, name := range names {
		var exists bool
		if err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE name=$1)`, name).Scan(&exists); err != nil {
			return applied, err
		}
		if exists {
			continue
		}
		sql, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return applied, err
		}
		err = pgx.BeginFunc(ctx, p, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, string(sql)); err != nil {
				return fmt.Errorf("migration %s: %w", name, err)
			}
			_, err := tx.Exec(ctx, `INSERT INTO schema_migrations(name) VALUES($1)`, name)
			return err
		})
		if err != nil {
			return applied, err
		}
		applied = append(applied, name)
	}
	return applied, nil
}

// Tx runs fn in a transaction. It exists so services never touch pgx.BeginFunc
// directly and so the transaction shape is one thing everywhere.
func (p *Pool) Tx(ctx context.Context, fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, p, fn)
}
