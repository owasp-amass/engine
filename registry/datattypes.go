package registry

import (
	"github.com/owasp-amass/engine/events"
)

// plugin interface
type AmassPlugin interface {
	Start(r *Registry) error
}

// Each plugins must return an Handlers list at initPlugin() time
// so that we can determine which events should be sent to the plugin
// and which handlers should be called for each event.

type Handler struct {
	Name       string
	EventType  events.EventType
	Transforms []string
	Handler    func(*events.Event) error
}

type Handlers []Handler
