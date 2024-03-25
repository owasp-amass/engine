// Copyright © by Jeff Foley 2023-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/miekg/dns"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/engine/graph"
	"github.com/owasp-amass/engine/plugins/support"
	et "github.com/owasp-amass/engine/types"
	"github.com/owasp-amass/open-asset-model/domain"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/resolve"
)

type dnsIP struct {
	name    string
	queries []uint16
	dblock  sync.Mutex
	plugin  *dnsPlugin
}

func (d *dnsIP) handler(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
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
			slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
	}
}
