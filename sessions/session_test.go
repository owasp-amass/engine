// Copyright © by Jeff Foley 2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"testing"

	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/config/config"
)

func TestNewSession(t *testing.T) {
	// Create a new configuration object.
	cfg := config.NewConfig()

	// Test the function with a nil configuration object.
	if ses, err := NewSession(nil); err != nil {
		t.Errorf("Error creating new session: %v", err)
	} else if ses == nil {
		t.Error("Session is nil")
	}
	// Test the function with a valid configuration object.
	if ses, err := NewSession(cfg); err != nil {
		t.Errorf("Error creating new session: %v", err)
	} else if ses == nil {
		t.Error("Session is nil")
	}

	// Test the function with an invalid configuration object.
	cfg.GraphDBs = []*config.Database{}
	if ses, err := NewSession(cfg); err == nil {
		t.Error("Expected error creating new session")
	} else if ses != nil {
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
	if ses, err := NewSession(cfg); err != nil {
		t.Errorf("Error creating new session: %v", err)
	} else if ses == nil {
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
	if ses, err := NewSession(cfg); err != nil {
		t.Errorf("Error creating new session: %v", err)
	} else if ses == nil {
		t.Error("Session is nil")
	}
	if repository.DBType(cfg.GraphDBs[0].System) != repository.SQLite {
		t.Error("Session database type is incorrect")
	}
}
