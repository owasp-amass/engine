// Copyright © by Jeff Foley 2023-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"fmt"
	"log/slog"

	"github.com/miekg/dns"
	"github.com/owasp-amass/engine/plugins/support"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
)

type dnsPlugin struct {
	Name    string
	log     *slog.Logger
	alts    *alts
	apex    *dnsApex
	cname   *dnsCNAME
	ip      *dnsIP
	reverse *dnsReverse
	subs    *dnsSubs
}

func NewDNS() et.Plugin {
	return &dnsPlugin{Name: "DNS"}
}

func (d *dnsPlugin) Start(r et.Registry) error {
	d.log = r.Log().WithGroup("plugin").With("name", d.Name)

	d.alts = NewAlterations(d)
	if err := r.RegisterHandler(&et.Handler{
		Name:         d.alts.Name,
		Priority:     7,
		MaxInstances: support.MaxHandlerInstances,
		Transforms:   []string{"fqdn"},
		EventType:    oam.FQDN,
		Callback:     d.alts.handler,
	}); err != nil {
		r.Log().Error(fmt.Sprintf("Failed to register a handler: %v", err),
			slog.Group("plugin", "name", d.Name, "handler", d.alts.Name))
		return err
	}

	d.apex = &dnsApex{Name: "DNS-Apex", plugin: d}
	if err := r.RegisterHandler(&et.Handler{
		Name:         d.apex.Name,
		Priority:     9,
		MaxInstances: support.NumTrustedResolvers() * 2,
		Transforms:   []string{"fqdn"},
		EventType:    oam.FQDN,
		Callback:     d.apex.handler,
	}); err != nil {
		r.Log().Error(fmt.Sprintf("Failed to register a handler: %v", err),
			slog.Group("plugin", "name", d.Name, "handler", d.apex.Name))
		return err
	}

	d.cname = &dnsCNAME{Name: "DNS-CNAME", plugin: d}
	if err := r.RegisterHandler(&et.Handler{
		Name:         d.cname.Name,
		Priority:     1,
		MaxInstances: support.MaxHandlerInstances,
		Transforms:   []string{"fqdn"},
		EventType:    oam.FQDN,
		Callback:     d.cname.handler,
	}); err != nil {
		r.Log().Error(fmt.Sprintf("Failed to register a handler: %v", err),
			slog.Group("plugin", "name", d.Name, "handler", d.cname.Name))
		return err
	}

	d.ip = &dnsIP{
		Name:    "DNS-IP",
		queries: []uint16{dns.TypeA, dns.TypeAAAA},
		plugin:  d,
	}
	if err := r.RegisterHandler(&et.Handler{
		Name:         d.ip.Name,
		Priority:     2,
		MaxInstances: support.MaxHandlerInstances,
		Transforms:   []string{"ipaddress"},
		EventType:    oam.FQDN,
		Callback:     d.ip.handler,
	}); err != nil {
		r.Log().Error(fmt.Sprintf("Failed to register a handler: %v", err),
			slog.Group("plugin", "name", d.Name, "handler", d.ip.Name))
		return err
	}

	d.reverse = NewReverse(d)
	if err := r.RegisterHandler(&et.Handler{
		Name:         d.reverse.Name,
		Priority:     9,
		MaxInstances: support.MaxHandlerInstances,
		Transforms:   []string{"fqdn"},
		EventType:    oam.IPAddress,
		Callback:     d.reverse.handler,
	}); err != nil {
		r.Log().Error(fmt.Sprintf("Failed to register a handler: %v", err),
			slog.Group("plugin", "name", d.Name, "handler", d.reverse.Name))
		return err
	}

	d.subs = NewSubs(d)
	if err := r.RegisterHandler(&et.Handler{
		Name:         d.subs.Name,
		Priority:     3,
		MaxInstances: support.MaxHandlerInstances,
		Transforms:   []string{"fqdn"},
		EventType:    oam.FQDN,
		Callback:     d.subs.check,
	}); err != nil {
		r.Log().Error(fmt.Sprintf("Failed to register a handler: %v", err),
			slog.Group("plugin", "name", d.Name, "handler", d.subs.Name))
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
