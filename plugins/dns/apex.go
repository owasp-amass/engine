// Copyright © by Jeff Foley 2023-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"errors"
	"fmt"
	"strings"

	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/engine/plugins/support"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
)

type dnsApex struct{}

func NewApex() et.Plugin {
	return &dnsApex{}
}

func (d *dnsApex) Start(r et.Registry) error {
	name := "DNS-NsMx-Handler"

	if err := r.RegisterHandler(&et.Handler{
		Name:         name,
		Priority:     9,
		MaxInstances: support.NumTrustedResolvers() * 2,
		Transforms:   []string{"fqdn"},
		EventType:    oam.FQDN,
		Callback:     d.handler,
	}); err != nil {
		r.Log().Error(fmt.Sprintf("Failed to register a handler: %v", err), "handler", name)
		return err
	}
	return nil
}

func (d *dnsApex) Stop() {}

func (d *dnsApex) handler(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !support.NameResolved(e.Session, fqdn) {
		return nil
	}

	rels, hit := e.Session.Cache().GetRelationsByType("ns_record")
	if !hit || len(rels) == 0 {
		return nil
	}

	var apexes []*dbt.Asset
	for _, r := range rels {
		apexes = append(apexes, r.FromAsset)
	}

	// determine which domain apex this name is a node in
	var apex *dbt.Asset
	best := len(fqdn.Name)
	for _, a := range apexes {
		n, ok := a.Asset.(*domain.FQDN)
		if !ok {
			continue
		}
		if idx := strings.Index(fqdn.Name, n.Name); idx != -1 && idx != 0 && idx < best {
			best = idx
			apex = a
		}
	}

	if apex != nil {
		d.callbackClosure(e, apex, fqdn)
	}
	return nil
}

func (d *dnsApex) callbackClosure(e *et.Event, apex *dbt.Asset, fqdn *domain.FQDN) {
	support.AppendToDBQueue(func() {
		_, _ = e.Session.DB().Create(apex, "node", fqdn)
	})
}
