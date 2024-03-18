// Copyright © by Jeff Foley 2023-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"errors"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/caffix/queue"
	"github.com/caffix/stringset"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/engine/net/dns"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

const MaxHandlerInstances int = 500

var done chan struct{}

var dbQueue queue.Queue

var subre *regexp.Regexp

func init() {
	done = make(chan struct{})

	dbQueue = queue.NewQueue()
	go processDBCallbacks()

	subre = regexp.MustCompile(dns.AnySubdomainRegexString())
}

func ScrapeSubdomainNames(s string) []string {
	set := stringset.New()

	for _, sub := range subre.FindAllString(s, -1) {
		if sub != "" {
			set.Insert(sub)
		}
	}

	return set.Slice()
}

func Shutdown() {
	close(done)
}

func IPToNetblockWithAttempts(session et.Session, ip *oamnet.IPAddress, num int, d time.Duration) (*oamnet.Netblock, error) {
	var err error
	var nb *oamnet.Netblock

	for i := 0; i < num; i++ {
		nb, err = IPToNetblock(session, ip)
		if err == nil {
			break
		}
		time.Sleep(d)
	}

	return nb, err
}

func IPToNetblock(session et.Session, ip *oamnet.IPAddress) (*oamnet.Netblock, error) {
	if assets, hit := session.Cache().GetAssetsByType(oam.Netblock); hit && len(assets) > 0 {
		for _, a := range assets {
			if nb, ok := a.Asset.(*oamnet.Netblock); ok && nb.Cidr.Contains(ip.Address) {
				return nb, nil
			}
		}
	}
	return nil, errors.New("no netblock match in the cache")
}

func IsAddressInScope(session et.Session, ip *oamnet.IPAddress) bool {
	addr, hit := session.Cache().GetAsset(ip)
	if !hit || addr == nil {
		return false
	}

	rtype := "a_record"
	if ip.Type == "IPv6" {
		rtype = "aaaa_record"
	}

	if relations, hit := session.Cache().GetRelations(&dbt.Relation{
		Type:    rtype,
		ToAsset: addr,
	}); hit && len(relations) > 0 {
		for _, relation := range relations {
			a := relation.FromAsset.Asset

			if fqdn, ok := a.(*domain.FQDN); ok && session.Config().IsDomainInScope(fqdn.Name) {
				return true
			}
		}
	}
	return false
}

func IsCNAME(session et.Session, name *domain.FQDN) (*domain.FQDN, bool) {
	fqdn, hit := session.Cache().GetAsset(name)
	if !hit || fqdn == nil {
		return nil, false
	}

	if relations, hit := session.Cache().GetRelations(&dbt.Relation{
		Type:      "cname_record",
		FromAsset: fqdn,
	}); hit && len(relations) > 0 {
		if cname, ok := relations[0].ToAsset.Asset.(*domain.FQDN); ok {
			return cname, true
		}
	}
	return nil, false
}

func NameIPAddresses(session et.Session, name *domain.FQDN) []*oamnet.IPAddress {
	fqdn, hit := session.Cache().GetAsset(name)
	if !hit || fqdn == nil {
		return nil
	}

	var results []*oamnet.IPAddress
	if relations, hit := session.Cache().GetRelations(&dbt.Relation{
		Type:      "a_record",
		FromAsset: fqdn,
	}); hit && len(relations) > 0 {
		for _, r := range relations {
			if ip, ok := r.ToAsset.Asset.(*oamnet.IPAddress); ok {
				results = append(results, ip)
			}
		}
	}

	if relations, hit := session.Cache().GetRelations(&dbt.Relation{
		Type:      "aaaa_record",
		FromAsset: fqdn,
	}); hit && len(relations) > 0 {
		for _, r := range relations {
			if ip, ok := r.ToAsset.Asset.(*oamnet.IPAddress); ok {
				results = append(results, ip)
			}
		}
	}

	if len(results) > 0 {
		return results
	}
	return nil
}

func NameResolved(session et.Session, name *domain.FQDN) bool {
	if _, found := IsCNAME(session, name); found {
		return true
	}
	if ips := NameIPAddresses(session, name); len(ips) > 0 {
		return true
	}
	return false
}

func AppendToDBQueue(callback func()) {
	dbQueue.Append(callback)
}

func processDBCallbacks() {
loop:
	for {
		select {
		case <-done:
			break loop
		case <-dbQueue.Signal():
			dbQueue.Process(func(data interface{}) {
				if callback, ok := data.(func()); ok {
					callback()
				}
			})
		}
	}

	dbQueue.Process(func(data interface{}) {
		if callback, ok := data.(func()); ok {
			callback()
		}
	})
}

type PassiveDNSFilter map[string]interface{}

func NewPassiveDNSFilter() PassiveDNSFilter {
	return make(PassiveDNSFilter)
}

func (r PassiveDNSFilter) Insert(fqdn string) {
	parts := strings.Split(fqdn, ".")

	var labels []string
	for i := len(parts) - 1; i >= 0; i-- {
		labels = append(labels, parts[i])
	}

	cur := r
	llen := len(labels)
	for i, label := range labels {
		if e, found := cur[label]; !found && i < llen-1 {
			cur[label] = make(PassiveDNSFilter)
			cur = cur[label].(PassiveDNSFilter)
		} else if found && i < llen-1 {
			if reflect.TypeOf(e).Kind() == reflect.Struct {
				cur[label] = make(PassiveDNSFilter)
			}
			cur = cur[label].(PassiveDNSFilter)
		} else if !found && i == llen-1 {
			cur[label] = struct{}{}
		}
	}
}

func (r PassiveDNSFilter) Prune() {
	for k, v := range r {
		switch t := v.(type) {
		case PassiveDNSFilter:
			if len(t) >= 100 {
				delete(r, k)
				r[k] = struct{}{}
			} else {
				t.Prune()
			}
		}
	}
}

func (r PassiveDNSFilter) Slice() []string {
	return r.processMap("")
}

func (r PassiveDNSFilter) processMap(prefix string) []string {
	var fqdns []string

	for k, v := range r {
		name := k
		if prefix != "" {
			name += "." + prefix
		}

		switch t := v.(type) {
		case PassiveDNSFilter:
			fqdns = append(fqdns, t.processMap(name)...)
		default:
			fqdns = append(fqdns, name)
		}
	}

	return fqdns
}

func (r PassiveDNSFilter) Close() {
	for k := range r {
		delete(r, k)
	}
}
