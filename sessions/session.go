package sessions

import (
	"fmt"
	"path/filepath"
	"strings"

	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/config/config"
	"github.com/owasp-amass/engine/pubsub"
)

// NewSession initializes a new Session object based on the provided configuration.
// The session object represents the state of an active engine enumeration.
//
// Parameters:
// - cfg: Configuration settings for the session. If nil, a default configuration is used.
//
// Returns:
// - A pointer to the initialized Session object.
// - An error if the session initialization fails (e.g., invalid database configuration).
func NewSession(cfg *config.Config) (*Session, error) {
	var dsn string               // Data Source Name: Represents the database connection string.
	var dbtype repository.DBType // Type of the database (e.g., Postgres, SQLite).

	// Use default configuration if none is provided.
	if cfg == nil {
		cfg = config.NewConfig()
	}

	// If no graph databases are specified, use a default SQLite database.
	if cfg.GraphDBs == nil {
		cfg.GraphDBs = []*config.Database{
			{
				Primary: true,
				System:  "sqlite",
			},
		}
	}
	// Iterate over the GraphDBs specified in the configuration.
	// The goal is to determine the primary database's connection details.
	for _, db := range cfg.GraphDBs {
		if db.Primary {
			// Convert the database system name to lowercase for consistent comparison.
			db.System = strings.ToLower(db.System)
			if db.System == "postgres" {
				// Construct the connection string for a Postgres database.
				dsn = fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s", db.Host, db.Port, db.Username, db.Password, db.DBName)
				dbtype = repository.Postgres
			} else if db.System == "sqlite" || db.System == "sqlite3" {
				// Define the connection path for an SQLite database.
				path := filepath.Join(config.OutputDirectory(cfg.Dir), "amass.sqlite")
				dsn = path
				dbtype = repository.SQLite
			}
			// Break the loop once the primary database is found.
			break
		}
	}

	// Check if a valid database connection string was generated.
	if dsn == "" || dbtype == "" {
		return nil, fmt.Errorf("no primary graph database specified in the configuration")
	}

	// Create a new session object.
	newSes := &Session{
		Cfg:    cfg,                // Store the provided configuration.
		PubSub: pubsub.NewLogger(), // Initialize a new logger for publishing/subscribing.
	}

	// Initialize the session's database with the identified type and connection string.
	newSes.DB = assetdb.New(dbtype, dsn)

	// Return the initialized session object.
	return newSes, nil
}
