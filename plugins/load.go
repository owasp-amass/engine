// Copyright © by Jeff Foley 2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"github.com/owasp-amass/engine/registry"
)

var pluginStartFuncs = []func() Plugin{
	newDNSIP,
	newDNSCNAME,
	newDNSReverse,
	newHackerTarget,
	newBGPTools,
	newIPNetblock,
}

func LoadAndStartPlugins(r *registry.Registry) error {
	var started []Plugin

	for _, f := range pluginStartFuncs {
		if p := f(); p != nil {
			if err := p.Start(r); err != nil {
				stopPlugins(started)
				return err
			}
		}
	}

	return nil
}

func stopPlugins(started []Plugin) {
	for _, p := range started {
		p.Stop()
	}
}
