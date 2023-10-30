package sessions

// Data structures for session_manager

import (
	"log"
	"sync"

	"github.com/google/uuid"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/config/config"
	"github.com/owasp-amass/engine/pubsub"
)

// Session
type Session struct {
	Cfg       *config.Config
	PubSub    *pubsub.Logger
	EngineLog *log.Logger
	DB        *assetdb.AssetDB
}

// SessionStorage is a struct that holds the sessions in memory.
type Manager struct {
	mu        sync.RWMutex // Mutex for thread-safety
	sessions  map[uuid.UUID]*Session
	EngineLog *log.Logger
}
