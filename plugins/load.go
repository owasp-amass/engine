// Copyright © by Jeff Foley 2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"github.com/owasp-amass/engine/plugins/dns"
	et "github.com/owasp-amass/engine/types"
)

var pluginStartFuncs = []func() et.Plugin{
	dns.NewCNAME,
	dns.NewIP,
	dns.NewSub,
	dns.NewReverse,
	dns.NewApex,
	newHackerTarget,
	newBGPTools,
	newIPNetblock,
}

func LoadAndStartPlugins(r et.Registry) error {
	var started []et.Plugin

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

func stopPlugins(started []et.Plugin) {
	for _, p := range started {
		p.Stop()
	}
}
