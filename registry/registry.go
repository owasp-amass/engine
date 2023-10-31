package registry

// plugin registry for both statically linked plugins and Go Plugin based ones

import (
	"errors"
	"fmt"
	"log"
	"os"
	"plugin"
	"strings"
	"sync"

	oam "github.com/owasp-amass/open-asset-model"
)

// Registry storage
type Registry struct {
	pluginLock  sync.Mutex
	plugins     map[string]AmassPlugin
	handlerLock sync.RWMutex
	handlers    map[oam.AssetType]map[string][]Handler
	l           *log.Logger
}

// Create a new instance of Registry
func NewRegistry(l *log.Logger) *Registry {
	return &Registry{
		plugins:  make(map[string]AmassPlugin),
		handlers: make(map[oam.AssetType]map[string][]Handler),
		l:        l,
	}
}

// Load all Plugins in a given path:
func (r *Registry) LoadPlugins(dir string) error {
	files, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	// Ensure that only one goroutine is accessing the map (in case of concurrent calls)
	r.pluginLock.Lock()
	defer r.pluginLock.Unlock()

	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".so") {
			p, err := r.loadPlugin(dir + "/" + file.Name())
			if err != nil {
				r.l.Fatalf("Error loading plugin %s: %s\n", file.Name(), err)
				continue
			}
			r.plugins[file.Name()] = p
		}
	}
	return nil
}

// Load and process a given Plugin
func (r *Registry) loadPlugin(path string) (AmassPlugin, error) {
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
		fmt.Println(p)
		//var h Handlers
		if err := p.Start(r); err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("unexpected plugin type")
	}
	return p, nil
}

// Register a Plugin Handler on the registry:
func (r *Registry) RegisterHandler(h Handler) error {
	// Check if the event Type is correct
	// TODO: Check if the event Type is correct against the OAM relationships

	// Check if the handler is already registered
	for _, transformation := range h.Transforms {
		// Check if this transformation has a relationship with the eventType
		if transformation == "" {
			continue
		}
	}

	r.handlerLock.Lock()
	defer r.handlerLock.Unlock()

	// All checks passed, let's add the handler to the registry
	if _, ok := r.handlers[h.EventType]; !ok {
		for _, transformation := range h.Transforms {
			r.handlers[h.EventType] = make(map[string][]Handler)
			tName := strings.ToLower(strings.TrimSpace(transformation))
			r.handlers[h.EventType][transformation] = append(r.handlers[h.EventType][tName], h)
		}
	} else {
		if _, ok := r.handlers[h.EventType][h.Name]; ok {
			return fmt.Errorf("handler %s already registered for EventType %s", h.Name, h.EventType)
		}
	}
	return nil
}

// Returns a list of handlers for a given event type. Assets can optionally be specified to filter transforms.
func (r *Registry) GetHandlers(eventType oam.AssetType, transforms ...string) ([]Handler, error) {
	// Check if the event Type is correct
	// TODO: Check if the event Type is correct against the OAM relationships

	r.handlerLock.RLock()
	defer r.handlerLock.RUnlock()
	// Check if there are any handlers registered for this EventType
	trans, ok := r.handlers[eventType]
	if !ok {
		return nil, fmt.Errorf("no handlers registered for EventType %s", eventType)
	}

	var results []Handler
	if len(transforms) == 0 {
		for _, handlers := range trans {
			results = append(results, handlers...)
		}
	} else {
		for _, t := range transforms {
			if h, ok := trans[t]; ok {
				results = append(results, h...)
			}
		}
	}
	return results, nil
}

// Returns the size of the handlers map
func (r *Registry) HandlersMapSize() int {
	return len(r.handlers)
}
