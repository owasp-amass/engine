// Copyright © by Jeff Foley 2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"context"
	"errors"

	"github.com/miekg/dns"
	"github.com/owasp-amass/engine/graph"
	"github.com/owasp-amass/engine/registry"
	"github.com/owasp-amass/engine/sessions"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/resolve"
)

type dnsCNAME struct{}

func newDNSCNAME() Plugin {
	return &dnsCNAME{}
}

func (d *dnsCNAME) Start(r *registry.Registry) error {
	name := "DNS-CNAME-Handler"

	if err := r.RegisterHandler(&registry.Handler{
		Name:       name,
		Transforms: []string{"fqdn"},
		EventType:  oam.FQDN,
		Handler:    d.handler,
	}); err != nil {
		r.Log.Printf("Failed to register the %s: %v", name, err)
		return err
	}
	return nil
}

func (d *dnsCNAME) Stop() {}

func (d *dnsCNAME) handler(e *et.Event) error {
	session := e.Session.(*sessions.Session)

	data, ok := e.Data.(*et.AssetData)
	if !ok {
		return errors.New("failed to extract the event data")
	}

	fqdn, ok := data.OAMAsset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	matches, err := checkTransformations(session, "fqdn", "fqdn", "dns")
	if err != nil {
		return err
	}
	if _, ok := matches["fqdn"]; !ok {
		return nil
	}

	if rr, err := performQuery(fqdn.Name, dns.TypeCNAME); err == nil && len(rr) > 0 {
		d.processRecords(e, rr)
	}
	return nil
}

func (d *dnsCNAME) processRecords(e *et.Event, rr []*resolve.ExtractedAnswer) {
	session := e.Session.(*sessions.Session)
	g := graph.Graph{DB: session.DB}

	for _, record := range rr {
		if a, err := g.UpsertCNAME(context.TODO(), record.Name, record.Data); err == nil && a != nil {
			scheduleAssetEvent(e, record.Data, a)
		}
	}
}
