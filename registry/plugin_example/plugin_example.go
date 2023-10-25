package plugin_example

// Amass plugin example

import (
	"fmt"

	"github.com/owasp-amass/engine/events"
	"github.com/owasp-amass/engine/registry"
)

type PluginOne struct{}

func (p *PluginOne) handleSampleEvent(e *events.Event) error {
	fmt.Println("PluginOne handling:", e.Data)
	return nil
}

func (p *PluginOne) InitPlugin(h *registry.Handlers) error {
	*h = append(*h, registry.Handler{
		EventType: []events.EventType{"sampleEvent"},
		Handler:   p.handleSampleEvent,
	})
	return nil
}

var Plugin PluginOne
