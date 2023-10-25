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

// Registry storage
type Registry struct {
	Plugins map[string]AmassPlugin
	//HandlersMap map[events.EventType][]func(*events.Event) error
	HandlersMap map[events.EventType]map[string][]func(*events.Event) error
}

// Create a new instance of Registry
func NewRegistry() *Registry {
	return &Registry{
		Plugins: make(map[string]AmassPlugin),
		//HandlersMap: make(map[events.EventType][]func(*events.Event) error),
		HandlersMap: make(map[events.EventType]map[string][]func(*events.Event) error),
	}
}

// Load all Plugins in a given path:
func (r *Registry) LoadPlugins(dir string) error {
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
func (r *Registry) RegisterHandler(h *Handler) error {
	// Check if the event Type is correct
	if h.EventType < 0 || h.EventType > events.EventType(events.MaxEventTypes) {
		return fmt.Errorf("Invalid EventType")
	}
	// TODO: Use the Transformation against the OAM relationships to ensure that
	//       the EventType and Transformation have a relationship
	for _, transformation := range h.Transform {
		// Check if this transformation has a relationship with the eventType
		if transformation == "" {
			continue
		}
	}
	// All checks passed, let's add the handler to the registry
	//r.HandlersMap[h.EventType] = append(r.HandlersMap[h.EventType], h.Handler)
	if _, ok := r.HandlersMap[h.EventType]; !ok {
		for _, transformation := range h.Transform {
			r.HandlersMap[h.EventType] = make(map[string][]func(*events.Event) error)
			r.HandlersMap[h.EventType][transformation] = append(r.HandlersMap[h.EventType][transformation], h.Handler)
		}
	} else {
		if _, ok := r.HandlersMap[h.EventType][h.Name]; ok {
			return fmt.Errorf("Handler %s already registered for EventType %d", h.Name, h.EventType)
		}
	}
	return nil
}

// Returns a list of handlers for a given event type
func (r *Registry) GetHandlers(eventType events.EventType) ([]func(*events.Event) error, error) {
	// Check if the event Type is correct
	if eventType < 0 || eventType > events.EventType(events.MaxEventTypes) {
		return nil, fmt.Errorf("Invalid EventType")
	}
	// Check if the event Type is correct
	transformations, ok := r.HandlersMap[eventType]
	if !ok {
		return nil, fmt.Errorf("No handlers registered for EventType %d", eventType)
	}
	// Aggregate handlers into a slice
	var handlers []func(*events.Event) error
	for _, handler := range transformations {
		handlers = append(handlers, handler...)
	}
	return handlers, nil
}
