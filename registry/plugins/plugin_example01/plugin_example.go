package main

// Amass plugin example

import (
	"fmt"
	"time"

	"github.com/owasp-amass/engine/registry"
	"github.com/owasp-amass/engine/types"
	// Add OAM dependency (the Plugin has to deal with the response)
)

type PluginOne struct{}

func (p *PluginOne) handleSampleEvent(e *types.Event) error {
	fmt.Println("PluginOne handling:", e.Data)
	return nil
}

// Check if we need to pass a reference to the DB or if the
// Plugin
func (p *PluginOne) Start(r *registry.Registry) error {
	// Register the handler
	r.RegisterHandler(
		registry.Handler{
			Name:       "PluginOne-MainHandler",
			Transforms: []string{"Test-Transform"},
			EventType:  types.EventTypeLog,
			Handler:    p.handleSampleEvent,
		})

	return nil
}

var Plugin PluginOne

// Generic main function
func main() {
	fmt.Println("PluginOne main function")
	// Go to sleep
	for {
		// Sleep for 1 second
		time.Sleep(1 * time.Second)
	}
}
