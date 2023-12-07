package sessions

import (
	"embed"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/glebarez/sqlite"
	assetdb "github.com/owasp-amass/asset-db"
	pgmigrations "github.com/owasp-amass/asset-db/migrations/postgres"
	sqlitemigrations "github.com/owasp-amass/asset-db/migrations/sqlite3"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/config/config"
	"github.com/owasp-amass/engine/cache"
	"github.com/owasp-amass/engine/pubsub"
	migrate "github.com/rubenv/sql-migrate"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// NewSession initializes a new Session object based on the provided configuration.
// The session object represents the state of an active engine enumeration.
func NewSession(cfg *config.Config) (*Session, error) {
	// Use default configuration if none is provided
	if cfg == nil {
		cfg = config.NewConfig()
	}

	// Create a new session object
	s := &Session{
		Cfg:    cfg,
		PubSub: pubsub.NewLogger(),
		Cache:  cache.NewOAMCache(nil),
		Stats:  new(SessionStats),
	}

	if err := s.setupDB(); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *Session) setupDB() error {
	if err := s.selectDBMS(); err != nil {
		return err
	}
	if err := s.migrations(); err != nil {
		return err
	}
	return nil
}

func (s *Session) selectDBMS() error {
	// If no graph databases are specified, use a default SQLite database.
	if s.Cfg.GraphDBs == nil {
		s.Cfg.GraphDBs = []*config.Database{
			{
				Primary: true,
				System:  "sqlite",
			},
		}
	}
	// Iterate over the GraphDBs specified in the configuration.
	// The goal is to determine the primary database's connection details.
	for _, db := range s.Cfg.GraphDBs {
		if db.Primary {
			// Convert the database system name to lowercase for consistent comparison.
			db.System = strings.ToLower(db.System)
			if db.System == "postgres" {
				// Construct the connection string for a Postgres database.
				s.dsn = fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s", db.Host, db.Port, db.Username, db.Password, db.DBName)
				s.dbtype = repository.Postgres
			} else if db.System == "sqlite" || db.System == "sqlite3" {
				// Define the connection path for an SQLite database.
				path := filepath.Join(config.OutputDirectory(s.Cfg.Dir), "amass.sqlite")
				s.dsn = path
				s.dbtype = repository.SQLite
			}
			// Break the loop once the primary database is found.
			break
		}
	}
	// Check if a valid database connection string was generated.
	if s.dsn == "" || s.dbtype == "" {
		return errors.New("no primary database specified in the configuration")
	}
	// Initialize the database store
	store := assetdb.New(s.dbtype, s.dsn)
	if store == nil {
		return errors.New("failed to initialize database store")
	}

	s.DB = store
	return nil
}

func (s *Session) migrations() error {
	var name string
	var fs embed.FS
	var database gorm.Dialector

	switch s.dbtype {
	case repository.SQLite:
		name = "sqlite3"
		fs = sqlitemigrations.Migrations()
		database = sqlite.Open(s.dsn)
	case repository.Postgres:
		name = "postgres"
		fs = pgmigrations.Migrations()
		database = postgres.Open(s.dsn)
	default:
		return fmt.Errorf("unsupported database type: %s", s.dbtype)
	}
	// Initialize the GORM database connection
	sql, err := gorm.Open(database, &gorm.Config{})
	if err != nil {
		return fmt.Errorf("failed to open database: %s", err)
	}
	// Set up migrations
	migrationsSource := migrate.EmbedFileSystemMigrationSource{
		FileSystem: fs,
		Root:       "/",
	}
	// Extract the raw SQL database instance
	sqlDb, err := sql.DB()
	if err != nil {
		return fmt.Errorf("failed to extract raw SQL DB from GORM: %s", err)
	}
	// Run migrations
	_, err = migrate.Exec(sqlDb, name, migrationsSource, migrate.Up)
	if err != nil {
		return fmt.Errorf("failed to execute migrations: %s", err)
	}

	return nil
}
