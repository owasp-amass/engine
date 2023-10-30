package sessions_test

import (
	"testing"

	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/config/config"
	. "github.com/owasp-amass/engine/sessions"
)

func TestNewSession(t *testing.T) {
	// Create a new configuration object.
	cfg := config.NewConfig()

	// Test the function with a nil configuration object.
	ses, err := NewSession(nil)
	if err != nil {
		t.Errorf("Error creating new session: %v", err)
	}
	if ses == nil {
		t.Error("Session is nil")
	}

	// Test the function with a valid configuration object.
	ses, err = NewSession(cfg)
	if err != nil {
		t.Errorf("Error creating new session: %v", err)
	}
	if ses == nil {
		t.Error("Session is nil")
	}

	// Test the function with an invalid configuration object.
	cfg.GraphDBs = []*config.Database{}
	ses, err = NewSession(cfg)
	if err == nil {
		t.Error("Expected error creating new session")
	}
	if ses != nil {
		t.Error("Session should be nil")
	}

	// Test the function with a valid configuration object and Postgres database.
	cfg.GraphDBs = []*config.Database{
		{
			Primary:  true,
			System:   "postgres",
			Host:     "localhost",
			Port:     "5432",
			Username: "postgres",
			Password: "password",
			DBName:   "test",
		},
	}
	ses, err = NewSession(cfg)
	if err != nil {
		t.Errorf("Error creating new session: %v", err)
	}
	if ses == nil {
		t.Error("Session is nil")
	}
	if repository.DBType(cfg.GraphDBs[0].System) != repository.Postgres {
		t.Error("Session database type is incorrect")
	}

	// Test the function with a valid configuration object and SQLite database.
	cfg.GraphDBs = []*config.Database{
		{
			Primary: true,
			System:  "sqlite",
		},
	}
	ses, err = NewSession(cfg)
	if err != nil {
		t.Errorf("Error creating new session: %v", err)
	}
	if ses == nil {
		t.Error("Session is nil")
	}
	if repository.DBType(cfg.GraphDBs[0].System) != repository.SQLite {
		t.Error("Session database type is incorrect")
	}
}
