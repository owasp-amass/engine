// Copyright © by Jeff Foley 2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"context"
	"errors"
	"time"

	"github.com/miekg/dns"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/engine/dispatcher"
	"github.com/owasp-amass/engine/graph"
	"github.com/owasp-amass/engine/registry"
	"github.com/owasp-amass/engine/sessions"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/resolve"
)

type dnsIP struct{}

var ipQueryTypes = []uint16{
	dns.TypeA,
	dns.TypeAAAA,
}

func newDNSIP() Plugin {
	return &dnsIP{}
}

func (d *dnsIP) Start(r *registry.Registry) error {
	name := "DNS-IP-Handler"

	if err := r.RegisterHandler(&registry.Handler{
		Name:       name,
		Transforms: []string{"ipaddress"},
		EventType:  oam.FQDN,
		Handler:    d.handler,
	}); err != nil {
		r.Log.Printf("Failed to register the %s: %v", name, err)
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

	session := e.Session.(*sessions.Session)
	matches, err := checkTransformations(session, "fqdn", "ipaddress", "dns")
	if err != nil {
		return err
	}
	if _, ok := matches["ipaddress"]; !ok {
		return nil
	}

	for _, qtype := range ipQueryTypes {
		if rr, err := performQuery(fqdn.Name, qtype); err == nil && len(rr) > 0 {
			d.processRecords(e, rr)
		}
	}
	return nil
}

func (d *dnsIP) processRecords(e *et.Event, rr []*resolve.ExtractedAnswer) {
	session := e.Session.(*sessions.Session)
	g := graph.Graph{DB: session.DB}
	dis := e.Dispatcher.(*dispatcher.Dispatcher)

	for _, record := range rr {
		var rel string
		var name *dbt.Asset
		var addr *dbt.Asset

		if record.Type == dns.TypeA {
			if ip, err := g.UpsertA(context.TODO(), record.Name, record.Data); err == nil && ip != nil {
				_ = dis.DispatchEvent(&et.Event{
					Name:       record.Data,
					Asset:      ip,
					Dispatcher: dis,
					Session:    session,
				})
				addr, _ = session.Cache.GetAsset(ip.Asset)
				if fqdn, hit := session.Cache.GetAsset(&domain.FQDN{Name: record.Name}); hit && fqdn != nil {
					rel = "a_record"
					name = fqdn
				}
			}
		}
		if record.Type == dns.TypeAAAA {
			if ip, err := g.UpsertAAAA(context.TODO(), record.Name, record.Data); err == nil && ip != nil {
				_ = dis.DispatchEvent(&et.Event{
					Name:       record.Data,
					Asset:      ip,
					Dispatcher: dis,
					Session:    session,
				})
				addr, _ = session.Cache.GetAsset(ip.Asset)
				if fqdn, hit := session.Cache.GetAsset(&domain.FQDN{Name: record.Name}); hit && fqdn != nil {
					rel = "aaaa_record"
					name = fqdn
				}
			}
		}

		if name != nil && addr != nil && rel != "" {
			now := time.Now()

			session.Cache.SetRelation(&dbt.Relation{
				Type:      rel,
				CreatedAt: now,
				LastSeen:  now,
				FromAsset: name,
				ToAsset:   addr,
			})
		}
	}
}
