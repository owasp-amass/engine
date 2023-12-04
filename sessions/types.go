package sessions

// Data structures for session_manager

import (
	"log"
	"sync"

	"github.com/google/uuid"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/config/config"
	"github.com/owasp-amass/engine/cache"
	"github.com/owasp-amass/engine/pubsub"
)

// Session
type Session struct {
	Log    *log.Logger
	PubSub *pubsub.Logger
	Cfg    *config.Config
	DB     *assetdb.AssetDB
	Cache  cache.Cache
}

// SessionStorage is a struct that holds the sessions in memory.
type Manager struct {
	sync.RWMutex // Mutex for thread-safety
	Log          *log.Logger
	sessions     map[uuid.UUID]*Session
}
