package registry

import (
	"github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
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
	EventType  oam.AssetType
	Transforms []string
	Handler    func(*types.Event) error
}

type Handlers []Handler
