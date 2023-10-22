package session_manager

import (
	"fmt"

	"github.com/google/uuid"
)

var (
	// SessionStorage is the global session storage.
	sessionStorage *SessionStorage
)

/*
 * SessionManager API:
 * SessionManagerInit initializes the global session storage.
 * SessionManagerShutdown cleans up the global session storage.
 * SessionManagerAddSession adds a session to the global session storage.
 * SessionManagerCancelSession cancels a session in the global session storage.
 * SessionManagerGetSession gets a session from the global session storage.
 * SessionManagerCleanAllSessions cleans all sessions from the global session storage.
 *
 */

// SessionManagerInit initializes the global session storage.
func SessionManagerInit() {
	sessionStorage = NewSessionStorage()
}

// SessionManagerShutdown cleans up the global session storage.
func SessionManagerShutdown() {
	if sessionStorage == nil {
		return
	}
	sessionStorage.CleanAllSessions()
	// reset the global session storage
	sessionStorage = nil
}

// SessionManagerAddSession adds a session to the global session storage.
func SessionManagerAddSession(s *SessionConfig) uuid.UUID {
	if sessionStorage == nil {
		return uuid.UUID{}
	}
	return sessionStorage.AddSession(s)
}

// SessionManagerCancelSession cancels a session in the global session storage.
func SessionManagerCancelSession(id uuid.UUID) error {
	if sessionStorage == nil {
		return fmt.Errorf("session manager is not initialized")
	}
	sessionStorage.CancelSession(id)
	return nil
}

// SessionManagerGetSession gets a session from the global session storage.
func SessionManagerGetSession(id uuid.UUID) *SessionConfig {
	if sessionStorage == nil {
		return nil
	}
	return sessionStorage.GetSession(id)
}

// SessionManagerCleanAllSessions cleans all sessions from the global session storage.
func SessionManagerCleanAllSessions() {
	if sessionStorage == nil {
		return
	}
	sessionStorage.CleanAllSessions()
}
