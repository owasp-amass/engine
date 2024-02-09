// Copyright © by Jeff Foley 2023-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"log"
	"sync"

	"github.com/google/uuid"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/config/config"
	"github.com/owasp-amass/engine/cache"
	"github.com/owasp-amass/engine/pubsub"
)

type Session interface {
	ID() uuid.UUID
	Log() *log.Logger
	PubSub() *pubsub.Logger
	Config() *config.Config
	DB() *assetdb.AssetDB
	Cache() cache.Cache
	Stats() *SessionStats
	Done() bool
	Kill()
}

type SessionStats struct {
	sync.Mutex
	WorkItemsCompleted int `json:"workItemsCompleted"`
	WorkItemsTotal     int `json:"workItemsTotal"`
}

type SessionManager interface {
	NewSession(cfg *config.Config) (Session, error)
	AddSession(s Session) (uuid.UUID, error)
	CancelSession(id uuid.UUID)
	GetSession(id uuid.UUID) Session
	Shutdown()
}
