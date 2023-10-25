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
	r.RegisterHandler(
		&registry.Handler{
			EventType: events.EventTypeSay,
			Handler:   p.handleSampleEvent, // check if it's not nil
		})

	return nil
}

var Plugin PluginOne
