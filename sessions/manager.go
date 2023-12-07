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

	"github.com/google/uuid"
)

var (
	zeroSessionUUID = uuid.UUID{}
)

// NewManager: creates a new session storage.
func NewManager(l *log.Logger) *Manager {
	if zeroSessionUUID == uuid.Nil {
		zeroSessionUUID = uuid.UUID{}
	}
	return &Manager{
		Log:      l,
		sessions: make(map[uuid.UUID]*Session),
	}
}

// Add: adds a session to a session storage after checking the session config.
func (ss *Manager) Add(s *Session) (uuid.UUID, error) {
	if s == nil {
		return uuid.UUID{}, nil
	}

	s.Log = ss.Log

	ss.Lock()
	defer ss.Unlock()

	id := uuid.New()
	s.ID = id
	ss.sessions[id] = s
	// TODO: Need to add the session config checks here (using the Registry)
	return id, nil
}

// Cancel: cancels a session in a session storage.
func (ss *Manager) Cancel(id uuid.UUID) {
	if id == zeroSessionUUID {
		return
	}

	ss.Lock()
	defer ss.Unlock()

	delete(ss.sessions, id)
}

// Get: returns a session from a session storage.
func (ss *Manager) Get(id uuid.UUID) *Session {
	if id == zeroSessionUUID {
		return nil
	}

	ss.RLock()
	defer ss.RUnlock()

	return ss.sessions[id]
}

// CleanAll: cleans all sessions from a session storage.
func (ss *Manager) CleanAll() {
	ss.Lock()
	defer ss.Unlock()

	for k := range ss.sessions {
		delete(ss.sessions, k)
	}
}

// Shutdown: cleans all sessions from a session storage and shutdown the session storage.
func (ss *Manager) Shutdown() {
	ss.CleanAll()
}
