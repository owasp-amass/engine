// Copyright © by Jeff Foley 2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"log"
	"os"
	"testing"

	"github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
)

func TestNewRegistry(t *testing.T) {
	r := NewRegistry(log.New(
		os.Stdout,
		"Test: ",
		log.Ldate|log.Ltime|log.Lshortfile,
	))
	if r == nil {
		t.Error("Registry is nil")
	}
}

func FakeHandler(e *types.Event) error {
	return nil
}

func TestRegisterHandler(t *testing.T) {
	r := NewRegistry(log.New(
		os.Stdout,
		"Test: ",
		log.Ldate|log.Ltime|log.Lshortfile,
	))

	// Register a handler
	err := r.RegisterHandler(&Handler{
		Name:       "Test-MainHandler",
		Transforms: []string{"Test-Transform"},
		EventType:  oam.FQDN,
		Handler:    FakeHandler,
	})
	if err != nil || r.HandlersMapSize() == 0 {
		t.Error("No handlers registered")
	}
}
