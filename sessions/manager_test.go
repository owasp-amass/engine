package sessions

import (
	"fmt"
	"testing"

	"github.com/owasp-amass/config/config"
)

var (
	ss *Storage
)

func TestMain(m *testing.M) {
	ss := NewStorage()
	defer ss.Shutdown()

	m.Run()
}

func TestAddSession001(t *testing.T) {
	// Create a session
	s := &config.Config{
		// ...
	}
	id := ss.Add(s)
	fmt.Println("Session ID:", id)
	if id == zeroSessionUUID {
		t.Error("Session ID is zero")
	}
}
