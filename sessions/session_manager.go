package sessions

/*
 * Amass Engine allow users to create multiple sessions.
 * Each session has its own configuration.
 * The session manager is responsible for managing all sessions,
 * it's a singleton object and it's thread-safe.
 *
 * How to use the session manager:
 * The session manager should be initialized when the engine
 * starts and it should shutdown when the engine stops.
 * There are methods to do both of these things (look at the
 * main_session_manager_api.go for more details).
 */

import (
	"github.com/google/uuid"
)

/*
 * The session manager also offer an API to build sub-sessions
 * managers if needed. But, as of now, it's not used.
 *
 * The session manager API to create sub-sessions managers:
 * NewSessionStorage creates a new session storage.
 * AddSession adds a session to the session storage.
 * CancelSession cancels a session in the session storage.
 * GetSession gets a session from the session storage.
 * CleanAllSessions cleans all sessions from the session storage.
 * Shutdown cleans all sessions from the session storage and shutdown the session storage.
 *
 */

var (
	zeroSessionUUID = uuid.UUID{}
)

// NewSessionStorage creates a new session storage.
func NewSessionStorage() *SessionStorage {
	if zeroSessionUUID == uuid.Nil {
		zeroSessionUUID = uuid.UUID{}
	}
	return &SessionStorage{
		sessions: make(map[uuid.UUID]*Config),
	}
}

// AddSession adds a session to a session storage after checking the session config.
func (ss *SessionStorage) AddSession(s *Config) uuid.UUID {
	if s == nil {
		return uuid.UUID{}
	}
	ss.mu.Lock()
	defer ss.mu.Unlock()

	id := uuid.New()
	ss.sessions[id] = s

	// TODO: Need to add the session config checks here (using the Registry)

	return id
}

// CancelSession cancels a session in a session storage.
func (ss *SessionStorage) CancelSession(id uuid.UUID) {
	if id == zeroSessionUUID {
		return
	}

	ss.mu.Lock()
	defer ss.mu.Unlock()

	delete(ss.sessions, id)
}

// GetSession returns a session from a session storage.
func (ss *SessionStorage) GetSession(id uuid.UUID) *Config {
	if id == zeroSessionUUID {
		return nil
	}

	ss.mu.RLock()
	defer ss.mu.RUnlock()

	return ss.sessions[id]
}

// CleanAllSessions cleans all sessions from a session storage.
func (ss *SessionStorage) CleanAllSessions() {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	for k := range ss.sessions {
		delete(ss.sessions, k)
	}
}

// Shutdown cleans all sessions from a session storage and shutdown the session storage.
func (ss *SessionStorage) Shutdown() {
	ss.CleanAllSessions()
	ss = nil
}
