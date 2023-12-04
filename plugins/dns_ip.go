// Copyright © by Jeff Foley 2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/miekg/dns"
	dbt "github.com/owasp-amass/asset-db/types"
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
	session := e.Session.(*sessions.Session)

	data, ok := e.Data.(*et.AssetData)
	if !ok {
		return errors.New("failed to extract the event data")
	}

	fqdn, ok := data.OAMAsset.(*domain.FQDN)
	if !ok {
		switch v := data.OAMAsset.(type) {
		default:
			fmt.Printf("Bad type: %T\n", v)
		}
		return errors.New("failed to extract the FQDN asset")
	}

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
	now := time.Now()
	session := e.Session.(*sessions.Session)
	g := graph.Graph{DB: session.DB}

	for _, record := range rr {
		if record.Type == dns.TypeA {
			if ip, err := g.UpsertA(context.TODO(), record.Name, record.Data); err == nil && ip != nil {
				scheduleAssetEvent(e, record.Data, ip)
				ip, _ = session.Cache.GetAsset(ip.Asset)
				if fqdn, hit := session.Cache.GetAsset(&domain.FQDN{Name: record.Name}); hit && fqdn != nil {
					session.Cache.SetRelation(&dbt.Relation{
						Type:      "a_record",
						CreatedAt: now,
						LastSeen:  now,
						FromAsset: fqdn,
						ToAsset:   ip,
					})
				}
			}
		}
		if record.Type == dns.TypeAAAA {
			if ip, err := g.UpsertAAAA(context.TODO(), record.Name, record.Data); err == nil && ip != nil {
				scheduleAssetEvent(e, record.Data, ip)
				ip, _ = session.Cache.GetAsset(ip.Asset)
				if fqdn, hit := session.Cache.GetAsset(&domain.FQDN{Name: record.Name}); hit && fqdn != nil {
					session.Cache.SetRelation(&dbt.Relation{
						Type:      "aaaa_record",
						CreatedAt: now,
						LastSeen:  now,
						FromAsset: fqdn,
						ToAsset:   ip,
					})
				}
			}
		}
	}
}
