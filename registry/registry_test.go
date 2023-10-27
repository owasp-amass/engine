package registry

import (
	"log"
	"os"
	"testing"

	"github.com/owasp-amass/engine/types"
)

func TestNewRegistry(t *testing.T) {
	logger := log.New(os.Stdout, "Test: ", log.Ldate|log.Ltime|log.Lshortfile)
	r := NewRegistry(logger)
	if r == nil {
		t.Error("Registry is nil")
	}
}

func FakeHandler(e *types.Event) error {
	return nil
}

func TestRegisterHandler(t *testing.T) {
	logger := log.New(os.Stdout, "Test: ", log.Ldate|log.Ltime|log.Lshortfile)
	r := NewRegistry(logger)

	// Register a handler
	r.RegisterHandler(
		Handler{
			Name:       "Test-MainHandler",
			Transforms: []string{"Test-Transform"},
			EventType:  types.EventTypeLog,
			Handler:    FakeHandler,
		})

	// Check if the handler was registered
	if r.HandlersMapSize() == 0 {
		t.Error("No handlers registered")
	}
}

/* Can't run this test because we don't have plugins yet
func TestLoadPlugins(t *testing.T) {
	r := NewRegistry()
	err := r.LoadPlugins("../plugins")
	if err != nil {
		t.Error("Error loading plugins:", err)
	}
	if len(r.Plugins) == 0 {
		t.Error("No plugins loaded")
	}
}
*/
