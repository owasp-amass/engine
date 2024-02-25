// Copyright © by Jeff Foley 2023-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/engine/graph"
	"github.com/owasp-amass/engine/plugins/support"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/resolve"
)

type dnsIP struct {
	queries []uint16
	dblock  sync.Mutex
}

func NewIP() et.Plugin {
	return &dnsIP{queries: []uint16{dns.TypeA, dns.TypeAAAA}}
}

func (d *dnsIP) Start(r et.Registry) error {
	name := "DNS-IP-Handler"

	if err := r.RegisterHandler(&et.Handler{
		Name:         name,
		Priority:     2,
		MaxInstances: support.MaxHandlerInstances,
		Transforms:   []string{"ipaddress"},
		EventType:    oam.FQDN,
		Callback:     d.handler,
	}); err != nil {
		r.Log().Error(fmt.Sprintf("Failed to register a handler: %v", err), "handler", name)
		return err
	}
	return nil
}

func (d *dnsIP) Stop() {}

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
}
