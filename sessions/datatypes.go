package sessions

// Data structures for session_manager

import (
	"sync"

	"github.com/google/uuid"
)

// SessionStorage is a struct that holds the sessions in memory.
type SessionStorage struct {
	mu       sync.RWMutex // Mutex for thread-safety
	sessions map[uuid.UUID]*Config
}
