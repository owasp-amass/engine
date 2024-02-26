// Copyright © by Jeff Foley 2023-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/miekg/dns"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/engine/graph"
	"github.com/owasp-amass/engine/plugins/support"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/resolve"
)

type dnsIP struct {
	Name    string
	queries []uint16
	dblock  sync.Mutex
	log     *slog.Logger
}

func NewIP() et.Plugin {
	return &dnsIP{
		Name:    "DNS-IP",
		queries: []uint16{dns.TypeA, dns.TypeAAAA},
	}
}

func (d *dnsIP) Start(r et.Registry) error {
	d.log = r.Log().WithGroup("plugin").With("name", d.Name)

	name := "DNS-IP-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Name:         name,
		Priority:     2,
		MaxInstances: support.MaxHandlerInstances,
		Transforms:   []string{"ipaddress"},
		EventType:    oam.FQDN,
		Callback:     d.handler,
	}); err != nil {
		d.log.Error(fmt.Sprintf("Failed to register a handler: %v", err), "handler", name)
		return err
	}

	d.log.Info("Plugin started")
	return nil
}

func (d *dnsIP) Stop() {
	d.log.Info("Plugin stopped")
}

func (d *dnsIP) handler(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	matches, err := e.Session.Config().CheckTransformations("fqdn", "ipaddress", "dns")
	if err != nil {
		return err
	}
	if !matches.IsMatch("ipaddress") {
		return nil
	}

	if _, found := support.IsCNAME(e.Session, fqdn); found {
		return nil
	}

	for _, qtype := range d.queries {
		if rr, err := support.PerformQuery(fqdn.Name, qtype); err == nil && len(rr) > 0 {
			d.process(e, rr)
		}
	}
	return nil
}

func (d *dnsIP) process(e *et.Event, rr []*resolve.ExtractedAnswer) {
	d.dblock.Lock()
	defer d.dblock.Unlock()

	g := graph.Graph{DB: e.Session.DB()}
	for _, record := range rr {
		if record.Type == dns.TypeA {
			if ip, err := g.UpsertA(context.TODO(), record.Name, record.Data); err == nil && ip != nil {
				d.dispatchAndCache(e, record.Name, record.Data, ip, "a_record")
			}
		}
		if record.Type == dns.TypeAAAA {
			if ip, err := g.UpsertAAAA(context.TODO(), record.Name, record.Data); err == nil && ip != nil {
				d.dispatchAndCache(e, record.Name, record.Data, ip, "aaaa_record")
			}
		}
	}
}

func (d *dnsIP) dispatchAndCache(e *et.Event, name, data string, ip *dbt.Asset, rtype string) {
	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    data,
		Asset:   ip,
		Session: e.Session,
	})

	addr, hit := e.Session.Cache().GetAsset(ip.Asset)
	if !hit || addr == nil {
		return
	}

	fqdn, hit := e.Session.Cache().GetAsset(&domain.FQDN{Name: name})
	if !hit || fqdn == nil {
		return
	}

	now := time.Now()
	e.Session.Cache().SetRelation(&dbt.Relation{
		Type:      rtype,
		CreatedAt: now,
		LastSeen:  now,
		FromAsset: fqdn,
		ToAsset:   addr,
	})

	if a, ok := addr.Asset.(*oamnet.IPAddress); ok {
		e.Session.Log().Info("relationship discovered", "from",
			name, "relation", rtype, "to", a.Address.String(),
			slog.Group("plugin", "name", d.Name, "handler", "DNS-IP-Handler"))
	}
}
