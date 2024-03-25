// Copyright © by Jeff Foley 2023-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"log/slog"

	"github.com/miekg/dns"
	"github.com/owasp-amass/engine/plugins/support"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
)

type dnsPlugin struct {
	name    string
	log     *slog.Logger
	alts    *alts
	apex    *dnsApex
	cname   *dnsCNAME
	ip      *dnsIP
	reverse *dnsReverse
	subs    *dnsSubs
}

func NewDNS() et.Plugin {
	return &dnsPlugin{name: "DNS"}
}

func (d *dnsPlugin) Name() string {
	return d.name
}

func (d *dnsPlugin) Start(r et.Registry) error {
	d.log = r.Log().WithGroup("plugin").With("name", d.name)

	d.alts = NewAlterations(d)
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       d,
		Name:         d.alts.name,
		Priority:     7,
		MaxInstances: support.MaxHandlerInstances,
		Transforms:   []string{"fqdn"},
		EventType:    oam.FQDN,
		Callback:     d.alts.handler,
	}); err != nil {
		return err
	}

	d.apex = &dnsApex{name: d.name + "-Apex", plugin: d}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       d,
		Name:         d.apex.name,
		Priority:     9,
		MaxInstances: support.NumTrustedResolvers() * 2,
		Transforms:   []string{"fqdn"},
		EventType:    oam.FQDN,
		Callback:     d.apex.handler,
	}); err != nil {
		return err
	}

	d.cname = &dnsCNAME{name: d.name + "-CNAME", plugin: d}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       d,
		Name:         d.cname.name,
		Priority:     1,
		MaxInstances: support.MaxHandlerInstances,
		Transforms:   []string{"fqdn"},
		EventType:    oam.FQDN,
		Callback:     d.cname.handler,
	}); err != nil {
		return err
	}

	d.ip = &dnsIP{
		name:    d.name + "-IP",
		queries: []uint16{dns.TypeA, dns.TypeAAAA},
		plugin:  d,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       d,
		Name:         d.ip.name,
		Priority:     2,
		MaxInstances: support.MaxHandlerInstances,
		Transforms:   []string{"ipaddress"},
		EventType:    oam.FQDN,
		Callback:     d.ip.handler,
	}); err != nil {
		return err
	}

	d.reverse = NewReverse(d)
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       d,
		Name:         d.reverse.name,
		Priority:     9,
		MaxInstances: support.MaxHandlerInstances,
		Transforms:   []string{"fqdn"},
		EventType:    oam.IPAddress,
		Callback:     d.reverse.handler,
	}); err != nil {
		return err
	}

	d.subs = NewSubs(d)
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       d,
		Name:         d.subs.name,
		Priority:     3,
		MaxInstances: support.MaxHandlerInstances,
		Transforms:   []string{"fqdn"},
		EventType:    oam.FQDN,
		Callback:     d.subs.check,
	}); err != nil {
		return err
	}
	go d.subs.process()

	d.log.Info("Plugin started")
	return nil
}

func (d *dnsPlugin) Stop() {
	d.subs.Stop()
	d.log.Info("Plugin stopped")
}
