// Copyright © by Jeff Foley 2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"fmt"
	"log"

	oam "github.com/owasp-amass/open-asset-model"
)

// Create a new instance of Registry
func NewRegistry(l *log.Logger) *Registry {
	return &Registry{
		Log:       l,
		handlers:  make(map[string]map[int][]*Handler),
		pipelines: make(map[string]*AssetPipeline),
	}
}

// Register a Plugin Handler on the registry:
func (r *Registry) RegisterHandler(h *Handler) error {
	r.Lock()
	defer r.Unlock()

	// is the entry currently empty?
	if _, found := r.handlers[string(h.EventType)]; !found {
		r.handlers[string(h.EventType)] = make(map[int][]*Handler)
	}
	// has this registration been made already?
	var found bool
loop:
	for _, handlers := range r.handlers[string(h.EventType)] {
		for _, handler := range handlers {
			if handler.Name == h.Name {
				found = true
				break loop
			}
		}
	}
	if found {
		return fmt.Errorf("handler %s already registered for EventType %s", h.Name, h.EventType)
	}

	if h.Priority == 0 {
		h.Priority = 5
	} else if h.Priority < 0 {
		h.Priority = 1
	} else if h.Priority > 9 {
		h.Priority = 9
	}

	et, p := string(h.EventType), h.Priority
	r.handlers[et][p] = append(r.handlers[et][p], h)
	return nil
}

func (r *Registry) GetPipeline(eventType oam.AssetType) (*AssetPipeline, error) {
	r.RLock()
	defer r.RUnlock()

	if p, found := r.pipelines[string(eventType)]; found {
		return p, nil
	}
	return nil, fmt.Errorf("no handlers registered for the EventType: %s", eventType)
}

// Returns the size of the handlers map
func (r *Registry) HandlersMapSize() int {
	r.RLock()
	defer r.RUnlock()

	return len(r.handlers)
}
