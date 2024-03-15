// Copyright © by Jeff Foley 2023-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/engine/graph"
	amassnet "github.com/owasp-amass/engine/net"
	"github.com/owasp-amass/engine/plugins/support"
	et "github.com/owasp-amass/engine/types"
	"github.com/owasp-amass/open-asset-model/domain"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/resolve"
	bf "github.com/tylertreat/BoomFilters"
)

type dnsReverse struct {
	Name             string
	defaultSweepSize int
	activeSweepSize  int
	maxSweepSize     int
	release          chan struct{}
	fm               sync.Mutex
	count            int
	attempts         int
	filter           *bf.StableBloomFilter
	log              *slog.Logger
}

func NewReverse(l *slog.Logger) *dnsReverse {
	var r chan struct{}
	if max := support.MaxHandlerInstances; max > 0 {
		r = make(chan struct{}, max)
		for i := 0; i < max; i++ {
			r <- struct{}{}
		}
	}

	attempts := 10000
	return &dnsReverse{
		Name:             "DNS-Reverse",
		defaultSweepSize: 50,
		activeSweepSize:  100,
		maxSweepSize:     250,
		release:          r,
		attempts:         attempts,
		filter:           bf.NewDefaultStableBloomFilter(uint(attempts), 0.01),
		log:              l,
	}
}

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

	if rr, err := support.PerformQuery(addrstr, dns.TypePTR); err == nil && len(rr) > 0 {
		d.process(e, rr)
	}
	// check that the IP address is related to a FQDN in scope
	if d.release != nil && support.IsAddressInScope(e.Session, ip) {
		d.sweep(e, ip)
	}
	return nil
}

func (d *dnsReverse) process(e *et.Event, rr []*resolve.ExtractedAnswer) {
	g := graph.Graph{DB: e.Session.DB()}

	support.AppendToDBQueue(func() {
		for _, record := range rr {
			if a, err := g.UpsertPTR(context.TODO(), record.Name, record.Data); err == nil && a != nil {
				if e.Session.Config().IsDomainInScope(record.Data) {
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

						e.Session.Log().Info("relationship discovered", "from",
							record.Name, "relation", "ptr_record", "to", record.Data,
							slog.Group("plugin", "name", d.Name, "handler", "DNS-Reverse-Handler"))
					}
				}
			}
		}
	})
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

	for _, ip := range amassnet.CIDRSubset(cidr, addrstr, size) {
		if ipstr := ip.String(); ipstr != addrstr && d.passFilter(ipstr) {
			<-d.release
			go d.sweepAddressRoutine(e, ipstr)
		}
	}
}

func (d *dnsReverse) sweepAddressRoutine(e *et.Event, addr string) {
	defer func() { d.release <- struct{}{} }()

	if rr, err := support.PerformUntrustedQuery(addr, dns.TypePTR); err == nil &&
		len(rr) > 0 && e.Session.Config().IsDomainInScope(rr[0].Data) {
		queueSweepCallback(e, addr)
	}
}

func (d *dnsReverse) passFilter(addr string) bool {
	d.fm.Lock()
	defer d.fm.Unlock()

	d.count++
	if d.count > d.attempts {
		d.count = 1
		d.filter.Reset()
	}

	return !d.filter.TestAndAdd([]byte(addr))
}

func queueSweepCallback(e *et.Event, ip string) {
	g := graph.Graph{DB: e.Session.DB()}

	support.AppendToDBQueue(func() {
		if addr, err := g.UpsertAddress(context.TODO(), ip); err == nil && addr != nil {
			_ = e.Dispatcher.DispatchEvent(&et.Event{
				Name:    ip,
				Asset:   addr,
				Session: e.Session,
			})
		}
	})
}
