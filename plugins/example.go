// Copyright © by Jeff Foley 2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"fmt"

	"github.com/owasp-amass/engine/registry"
	"github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
)

type examplePlugin struct{}

// This needs to be added to the slice of function pointers
// in order for LoadAndStartPlugins to include it during startup.
func newExamplePlugin() Plugin {
	return &examplePlugin{}
}

func (p *examplePlugin) Start(r *registry.Registry) error {
	name := "Example-MainHandler"
	if err := r.RegisterHandler(&registry.Handler{
		Name:       name,
		Transforms: []string{"fqdn"},
		EventType:  oam.FQDN,
		Handler:    p.handler,
	}); err != nil {
		r.Log.Printf("Failed to register the %s: %v", name, err)
		return err
	}

	return nil
}

func (p *examplePlugin) Stop() {}

func (p *examplePlugin) handler(e *types.Event) error {
	fmt.Println("Example Plugin handler: ", e.Data)
	return nil
}
