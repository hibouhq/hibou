package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/hibouhq/hibou/internal/config"
	"github.com/hibouhq/hibou/internal/seed"
	"github.com/hibouhq/hibou/internal/store"
)

var seedCmd = &cobra.Command{
	Use:   "seed",
	Short: "Populate the database with sample data for development",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}

		log := newLogger(cfg)
		db, err := store.New(cfg.DatabaseURL)
		if err != nil {
			return fmt.Errorf("connecting database: %w", err)
		}
		defer func() {
			_ = db.Close()
		}()

		if err := store.Migrate(db); err != nil {
			return fmt.Errorf("migrating database: %w", err)
		}

		return seed.Run(cmd.Context(), db, log)
	},
}

// seedCmd is registered conditionally in root.go based on personality.
