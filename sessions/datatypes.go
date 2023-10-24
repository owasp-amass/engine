package sessions

// Data structures for session_manager

import (
	"sync"

	"github.com/google/uuid"
	"github.com/owasp-amass/config/config"
)

// SessionStorage is a struct that holds the sessions in memory.
type Storage struct {
	mu       sync.RWMutex // Mutex for thread-safety
	sessions map[uuid.UUID]*config.Config
}
