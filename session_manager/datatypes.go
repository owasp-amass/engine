package session_manager

// Data structures for session-manager

import (
	"sync"

	"github.com/google/uuid"
)

// SessionConfig is a struct that holds the configuration parameters for a session.
type SessionConfig struct {
	// Whatever configuration parameters you want.
}

// SessionStorage is a struct that holds the sessions in memory.
type SessionStorage struct {
	mu       sync.RWMutex // Mutex for thread-safety
	sessions map[uuid.UUID]*SessionConfig
}
