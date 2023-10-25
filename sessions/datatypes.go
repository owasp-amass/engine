package sessions

// Data structures for session_manager

import (
	"sync"

	"github.com/google/uuid"
	"github.com/owasp-amass/config/config"
)

// Session
type Session struct {
	Cfg *config.Config
}

// SessionStorage is a struct that holds the sessions in memory.
type Manager struct {
	mu       sync.RWMutex // Mutex for thread-safety
	sessions map[uuid.UUID]*Session
}
