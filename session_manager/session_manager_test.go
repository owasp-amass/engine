package session_manager

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
)

var (
	zeroUUID = uuid.UUID{}
)

func TestMain(m *testing.M) {
	SessionManagerInit()
	defer SessionManagerShutdown()
	zeroUUID = uuid.UUID{}
	m.Run()
}

func TestAddSession001(t *testing.T) {
	// Create a session
	s := &SessionConfig{
		// ...
	}
	id := SessionManagerAddSession(s)
	fmt.Println("Session ID:", id)
	if id == zeroUUID {
		t.Error("Session ID is zero")
	}
}
