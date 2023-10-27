package sessions

import (
	"fmt"
	"log"
	"os"
	"testing"
)

var (
	ss *Manager
)

func TestMain(m *testing.M) {
	// Create a new logger for testing.
	logger := log.New(os.Stdout, "Test: ", log.Ldate|log.Ltime|log.Lshortfile)
	ss := NewStorage(logger)
	defer ss.Shutdown()

	m.Run()
}

func TestAddSession001(t *testing.T) {
	// Create a session
	s := &Session{
		// ...
	}
	id := ss.Add(s)
	fmt.Println("Session ID:", id)
	if id == zeroSessionUUID {
		t.Error("Session ID is zero")
	}
}
