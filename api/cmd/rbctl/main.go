package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/tetraneurons/reversebug/api/internal/config"
	"github.com/tetraneurons/reversebug/api/internal/db"
	"github.com/tetraneurons/reversebug/api/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "migrate":
		if err := runMigrate(); err != nil {
			fmt.Fprintf(os.Stderr, "migrate error: %v\n", err)
			os.Exit(1)
		}
	case "bootstrap-admin":
		if err := runBootstrapAdmin(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "bootstrap-admin error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`ReverseBug Operator CLI (rbctl)

Usage:
  rbctl migrate                     Apply database migrations
  rbctl bootstrap-admin -email=...  Promote an existing verified user to system_admin

Environment:
  RB_DATABASE_URL                   Required connection string to PostgreSQL`)
}

func runMigrate() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	fmt.Println("Applying database migrations...")
	if err := db.Migrate(ctx, pool); err != nil {
		return err
	}
	fmt.Println("Migrations applied successfully.")
	return nil
}

func runBootstrapAdmin(args []string) error {
	fs := flag.NewFlagSet("bootstrap-admin", flag.ExitOnError)
	emailFlag := fs.String("email", "", "Email of verified user to promote to system_admin")
	roleFlag := fs.String("role", "system_admin", "Role to assign (support_admin, billing_admin, system_admin)")
	_ = fs.Parse(args)

	email := strings.TrimSpace(*emailFlag)
	if email == "" {
		return fmt.Errorf("-email flag is required")
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	st := store.New(pool)
	id, err := st.SetPlatformRole(ctx, strings.ToLower(email), *roleFlag)
	if err != nil {
		return fmt.Errorf("user must already exist and have verified email address: %w", err)
	}

	fmt.Printf("Successfully promoted user %s (%s) to %s.\n", email, id, *roleFlag)
	return nil
}
