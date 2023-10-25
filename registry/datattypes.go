package registry

import (
	"github.com/owasp-amass/engine/events"
)

// plugin interface
type AmassPlugin interface {
	InitPlugin(h *Handlers) error
	notify(e *events.Event) error
}

// Each plugins must return an Handlers list at initPlugin() time
// so that we can determine which events should be sent to the plugin
// and which handlers should be called for each event.

type Handler struct {
	EventType []events.EventType
	Handler   func(*events.Event) error
}

type Handlers []Handler
