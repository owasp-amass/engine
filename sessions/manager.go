// Copyright © by Jeff Foley 2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

/*
 * Amass Engine allow users to create multiple sessions.
 * Each session has its own configuration.
 * The session manager is responsible for managing all sessions,
 * it's a singleton object and it's thread-safe.
 */

import (
	"log"
	"sync"

	"github.com/google/uuid"
	"github.com/owasp-amass/config/config"
	et "github.com/owasp-amass/engine/types"
)

type manager struct {
	sync.RWMutex // Mutex for thread-safety
	logger       *log.Logger
	sessions     map[uuid.UUID]et.Session
}

var (
	zeroSessionUUID = uuid.UUID{}
)

// NewManager: creates a new session storage.
func NewManager(l *log.Logger) et.SessionManager {
	if zeroSessionUUID == uuid.Nil {
		zeroSessionUUID = uuid.UUID{}
	}
	return &manager{
		logger:   l,
		sessions: make(map[uuid.UUID]et.Session),
	}
}

func (ss *manager) NewSession(cfg *config.Config) (et.Session, error) {
	session, err := NewSession(cfg)
	if err == nil {
		_, err = ss.AddSession(session)
		if err == nil {
			return session, nil
		}
	}
	return nil, err
}

// Add: adds a session to a session storage after checking the session config.
func (ss *manager) AddSession(s et.Session) (uuid.UUID, error) {
	if s == nil {
		return uuid.UUID{}, nil
	}

	sess := s.(*session)
	sess.log = ss.logger

	ss.Lock()
	defer ss.Unlock()

	id := uuid.New()
	sess.id = id
	ss.sessions[id] = sess
	// TODO: Need to add the session config checks here (using the Registry)
	return id, nil
}

// Cancel: cancels a session in a session storage.
func (ss *manager) CancelSession(id uuid.UUID) {
	if id == zeroSessionUUID {
		return
	}

	ss.Lock()
	defer ss.Unlock()

	delete(ss.sessions, id)
}

// Get: returns a session from a session storage.
func (ss *manager) GetSession(id uuid.UUID) et.Session {
	if id == zeroSessionUUID {
		return nil
	}

	ss.RLock()
	defer ss.RUnlock()

	return ss.sessions[id]
}

func (ss *manager) cleanAll() {
	ss.Lock()
	defer ss.Unlock()

	for k := range ss.sessions {
		delete(ss.sessions, k)
	}
}

// Shutdown: cleans all sessions from a session storage and shutdown the session storage.
func (ss *manager) Shutdown() {
	ss.cleanAll()
}
