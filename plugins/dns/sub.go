// Copyright © by Jeff Foley 2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"errors"
	"strings"
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

type qtypes struct {
	Qtype uint16
	Rtype string
}

type dnsSub struct {
	types []qtypes
}

func NewSub() et.Plugin {
	return &dnsSub{
		types: []qtypes{
			{Qtype: dns.TypeNS, Rtype: "ns_record"},
			{Qtype: dns.TypeMX, Rtype: "mx_record"},
			{Qtype: dns.TypeSOA, Rtype: "soa_record"},
			{Qtype: dns.TypeSPF, Rtype: "spf_record"},
		},
	}
}

func (d *dnsSub) Start(r et.Registry) error {
	name := "DNS-Subdomain-Handler"

	if err := r.RegisterHandler(&et.Handler{
		Name:       name,
		Priority:   3,
		Transforms: []string{"fqdn"},
		EventType:  oam.FQDN,
		Callback:   d.check,
	}); err != nil {
		r.Log().Printf("Failed to register the %s: %v", name, err)
		return err
	}
	return nil
}

func (d *dnsSub) Stop() {}

func (d *dnsSub) check(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	matches, err := e.Session.Config().CheckTransformations("fqdn", "fqdn", "dns")
	if err != nil {
		return err
	}
	if !matches.IsMatch("fqdn") || !support.NameResolved(e.Session, fqdn) {
		return nil
	}

	d.traverse(e, fqdn)
	return nil
}

func (d *dnsSub) traverse(e *et.Event, n *domain.FQDN) {
	sub := n.Name

	dom := e.Session.Config().WhichDomain(sub)
	if dom == "" {
		return
	}
	if sub == dom {
		d.queries(e, sub)
		return
	}
	dlabels := strings.Split(dom, ".")

	for {
		labels := strings.Split(sub, ".")
		// Is this large enough to consider further?
		if len(labels) < 2 {
			break
		}
		sub = strings.TrimSpace(strings.Join(labels[1:], "."))

		// no need to check subdomains already evaluated
		if _, hit := e.Session.Cache().GetAsset(&domain.FQDN{Name: sub}); hit {
			break
		}

		if len(dlabels) > len(labels) {
			break
		}
		d.queries(e, sub)
	}
}

func (d *dnsSub) queries(e *et.Event, subdomain string) {
	for i, t := range d.types {
		if rr, err := support.PerformQuery(subdomain, t.Qtype); err == nil && len(rr) > 0 {
			d.process(e, t.Rtype, rr)
		} else if i == 0 {
			// do not continue if we failed to obtain the NS record
			break
		}
	}
}

func (d *dnsSub) process(e *et.Event, rtype string, rr []*resolve.ExtractedAnswer) {
	g := graph.Graph{DB: e.Session.DB()}

	for _, record := range rr {
		fqdn, err := g.UpsertFQDN(context.TODO(), record.Name)
		if err != nil || fqdn == nil {
			continue
		}

		a, err := e.Session.DB().Create(fqdn, rtype, &domain.FQDN{Name: record.Data})
		if err != nil || a == nil {
			continue
		}

		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    record.Data,
			Asset:   a,
			Session: e.Session,
		})

		if to, hit := e.Session.Cache().GetAsset(a.Asset); hit && to != nil {
			now := time.Now()

			e.Session.Cache().SetRelation(&dbt.Relation{
				Type:      rtype,
				CreatedAt: now,
				LastSeen:  now,
				FromAsset: fqdn,
				ToAsset:   to,
			})
		}
	}
}
