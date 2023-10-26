package registry

import (
	"testing"

	"github.com/owasp-amass/engine/events"
)

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()
	if r == nil {
		t.Error("Registry is nil")
	}
}

func FakeHandler(e *events.Event) error {
	return nil
}

func TestRegisterHandler(t *testing.T) {
	r := NewRegistry()

	// Register a handler
	r.RegisterHandler(
		Handler{
			Name:       "Test-MainHandler",
			Transforms: []string{"Test-Transform"},
			EventType:  events.EventTypeLog,
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
