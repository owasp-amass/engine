package registry

// plugin registry for both statically linked plugins and Go Plugin based ones

import (
	"errors"
	"fmt"
	"os"
	"plugin"
	"strings"

	"github.com/owasp-amass/engine/events"
)

// Registry storage (private)
type registry struct {
	Plugins     map[string]AmassPlugin
	HandlersMap map[events.EventType][]func(*events.Event) error
}

func NewRegistry() *registry {
	return &registry{
		Plugins:     make(map[string]AmassPlugin),
		HandlersMap: make(map[events.EventType][]func(*events.Event) error),
	}
}

func (r *registry) LoadPlugins(dir string) error {
	files, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".so") {
			p, err := r.loadPlugin(dir + "/" + file.Name())
			if err != nil {
				fmt.Printf("Error loading plugin %s: %s\n", file.Name(), err)
				continue
			}
			r.Plugins[file.Name()] = p
		}
	}
	return nil
}

func (r *registry) loadPlugin(path string) (AmassPlugin, error) {
	plug, err := plugin.Open(path)
	if err != nil {
		return nil, err
	}

	symPlugin, err := plug.Lookup("Plugin")
	if err != nil {
		return nil, err
	}

	var p AmassPlugin
	if p, ok := symPlugin.(AmassPlugin); ok {
		var h Handlers
		if err := p.InitPlugin(&h); err != nil {
			return nil, err
		}

		for _, handler := range h {
			for _, eventType := range handler.EventType {
				r.HandlersMap[eventType] = append(r.HandlersMap[eventType], handler.Handler)
			}
		}
	} else {
		return nil, errors.New("unexpected plugin type")
	}

	return p, nil
}
