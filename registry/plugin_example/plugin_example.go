package plugin_example

// Amass plugin example

import (
	"fmt"

	"github.com/owasp-amass/engine/events"
	"github.com/owasp-amass/engine/registry"
	// Add OAM dependecy (the Plugin has to deal with the response)
)

type PluginOne struct{}

func (p *PluginOne) handleSampleEvent(e *events.Event) error {
	fmt.Println("PluginOne handling:", e.Data)
	return nil
}

// Check if we need to pass a reference to the DB or if the
// Plugin
func (p *PluginOne) Start(r *registry.Registry) error {
	// Register the handler
	r.RegisterHandler(
		registry.Handler{
			Name:      "PluginOne-MainHandler",
			EventType: events.EventTypeLog,
			Handler:   p.handleSampleEvent,
		})

	return nil
}

var Plugin PluginOne
