// Copyright © by Jeff Foley 2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/miekg/dns"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/engine/graph"
	amassnet "github.com/owasp-amass/engine/net"
	"github.com/owasp-amass/engine/plugins/support"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/resolve"
)

type dnsReverse struct {
	defaultSweepSize int
	activeSweepSize  int
	maxSweepSize     int
}

func NewReverse() et.Plugin {
	return &dnsReverse{
		defaultSweepSize: 50,
		activeSweepSize:  100,
		maxSweepSize:     250,
	}
}

func (d *dnsReverse) Start(r et.Registry) error {
	name := "DNS-Reverse-Handler"

	if err := r.RegisterHandler(&et.Handler{
		Name:       name,
		Priority:   9,
		Transforms: []string{"fqdn"},
		EventType:  oam.IPAddress,
		Callback:   d.handler,
	}); err != nil {
		r.Log().Printf("Failed to register the %s: %v", name, err)
		return err
	}
	return nil
}

func (d *dnsReverse) Stop() {}

func (d *dnsReverse) handler(e *et.Event) error {
	ip, ok := e.Asset.Asset.(*oamnet.IPAddress)
	if !ok {
		return errors.New("failed to extract the IPAddress asset")
	}

	addrstr := ip.Address.String()
	if reserved, _ := amassnet.IsReservedAddress(addrstr); reserved {
		return nil
	}

	matches, err := e.Session.Config().CheckTransformations("ipaddress", "fqdn", "dns")
	if err != nil {
		return err
	}
	if !matches.IsMatch("fqdn") {
		return nil
	}

	var inscope bool
	if rr, err := support.PerformQuery(addrstr, dns.TypePTR); err == nil && len(rr) > 0 {
		inscope = d.process(e, rr)
	}
	// check that the IP address is related to a FQDN in scope
	if inscope || support.IsAddressInScope(e.Session, ip) {
		d.sweep(e, ip)
	}
	return nil
}

func (d *dnsReverse) sweep(e *et.Event, address *oamnet.IPAddress) {
	n, err := support.IPToNetblockWithAttempts(e.Session, address, 10, 500*time.Millisecond)
	if err != nil {
		return
	}

	addrstr := address.Address.String()
	_, cidr, err := net.ParseCIDR(n.Cidr.String())
	if err != nil || cidr == nil {
		addr := net.ParseIP(addrstr)
		mask := net.CIDRMask(18, 32)
		if amassnet.IsIPv6(addr) {
			mask = net.CIDRMask(64, 128)
		}

		cidr = &net.IPNet{
			IP:   addr.Mask(mask),
			Mask: mask,
		}
	}

	size := d.defaultSweepSize
	if e.Session.Config().Active {
		size = d.activeSweepSize
	}

	g := graph.Graph{DB: e.Session.DB()}
	for _, ip := range amassnet.CIDRSubset(cidr, addrstr, size) {
		ipstr := ip.String()

		if ipstr == addrstr {
			continue
		}
		if addr, err := g.UpsertAddress(context.TODO(), ipstr); err == nil && addr != nil {
			_ = e.Dispatcher.DispatchEvent(&et.Event{
				Name:    ipstr,
				Asset:   addr,
				Session: e.Session,
			})
		}
	}
}

func (d *dnsReverse) process(e *et.Event, rr []*resolve.ExtractedAnswer) bool {
	g := graph.Graph{DB: e.Session.DB()}

	var inscope bool
	for _, record := range rr {
		if a, err := g.UpsertPTR(context.TODO(), record.Name, record.Data); err == nil && a != nil {
			if e.Session.Config().IsDomainInScope(record.Data) {
				inscope = true
				_ = e.Dispatcher.DispatchEvent(&et.Event{
					Name:    record.Data,
					Asset:   a,
					Session: e.Session,
				})

				now := time.Now()
				if ptr, hit := e.Session.Cache().GetAsset(&domain.FQDN{Name: record.Name}); hit && ptr != nil {
					e.Session.Cache().SetRelation(&dbt.Relation{
						Type:      "ptr_record",
						CreatedAt: now,
						LastSeen:  now,
						FromAsset: ptr,
						ToAsset:   a,
					})
				}
			}
		}
	}
	return inscope
}
